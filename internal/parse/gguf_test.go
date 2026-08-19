package parse

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// ggufBuilder assembles a minimal but valid GGUF file for tests.
type ggufBuilder struct {
	kv      bytes.Buffer
	kvCount uint64
	tensors bytes.Buffer
	tCount  uint64
}

func (b *ggufBuilder) putStr(buf *bytes.Buffer, s string) {
	binary.Write(buf, binary.LittleEndian, uint64(len(s)))
	buf.WriteString(s)
}

func (b *ggufBuilder) str(key, val string) {
	b.putStr(&b.kv, key)
	binary.Write(&b.kv, binary.LittleEndian, uint32(ggString))
	b.putStr(&b.kv, val)
	b.kvCount++
}

func (b *ggufBuilder) u32(key string, val uint32) {
	b.putStr(&b.kv, key)
	binary.Write(&b.kv, binary.LittleEndian, uint32(ggUint32))
	binary.Write(&b.kv, binary.LittleEndian, val)
	b.kvCount++
}

func (b *ggufBuilder) strArray(key string, vals []string) {
	b.putStr(&b.kv, key)
	binary.Write(&b.kv, binary.LittleEndian, uint32(ggArray))
	binary.Write(&b.kv, binary.LittleEndian, uint32(ggString))
	binary.Write(&b.kv, binary.LittleEndian, uint64(len(vals)))
	for _, v := range vals {
		b.putStr(&b.kv, v)
	}
	b.kvCount++
}

func (b *ggufBuilder) tensor(name string, dims []int64, ggmlType uint32) {
	b.putStr(&b.tensors, name)
	binary.Write(&b.tensors, binary.LittleEndian, uint32(len(dims)))
	for _, d := range dims {
		binary.Write(&b.tensors, binary.LittleEndian, uint64(d))
	}
	binary.Write(&b.tensors, binary.LittleEndian, ggmlType)
	binary.Write(&b.tensors, binary.LittleEndian, uint64(0)) // offset
	b.tCount++
}

func (b *ggufBuilder) bytes() []byte {
	var out bytes.Buffer
	out.WriteString("GGUF")
	binary.Write(&out, binary.LittleEndian, uint32(3)) // version
	binary.Write(&out, binary.LittleEndian, b.tCount)
	binary.Write(&out, binary.LittleEndian, b.kvCount)
	out.Write(b.kv.Bytes())
	out.Write(b.tensors.Bytes())
	// a little tensor data so the file is non-trivial
	out.Write(make([]byte, 64))
	return out.Bytes()
}

func writeGGUF(t *testing.T) string {
	t.Helper()
	b := &ggufBuilder{}
	b.str("general.architecture", "llama")
	b.str("general.name", "TinyTest")
	b.str("general.author", "Davano")
	b.str("general.organization", "Davano Innovation Lab")
	b.str("general.license", "apache-2.0")
	b.str("general.license.link", "https://example.com/license")
	b.u32("general.file_type", 15) // Q4_K_M
	b.u32("general.alignment", 32)
	b.u32("llama.context_length", 8192)
	b.u32("llama.block_count", 32)
	b.str("general.base_model.0.name", "Meta-Llama-3-8B")
	b.str("general.base_model.0.repo_url", "https://hf.co/meta-llama/Meta-Llama-3-8B")
	b.strArray("general.datasets", []string{"the-stack", "wikipedia"})
	b.strArray("general.tags", []string{"text-generation"})
	// A chat template with Jinja control logic → should trip TESS-GGUF-010.
	b.str("tokenizer.chat_template", "{% for m in messages %}{{ m.content }}{% endfor %}")
	b.tensor("token_embd.weight", []int64{4096, 128256}, 12)

	dir := t.TempDir()
	path := filepath.Join(dir, "tiny.gguf")
	if err := os.WriteFile(path, b.bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseGGUF(t *testing.T) {
	path := writeGGUF(t)
	a, err := ParseGGUF(path)
	if err != nil {
		t.Fatalf("ParseGGUF: %v", err)
	}

	if a.Identity.Name != "TinyTest" {
		t.Errorf("name = %q, want TinyTest", a.Identity.Name)
	}
	if a.Identity.Organization != "Davano Innovation Lab" {
		t.Errorf("org = %q", a.Identity.Organization)
	}
	if len(a.Licenses) != 1 || a.Licenses[0].Raw != "apache-2.0" {
		t.Fatalf("licenses = %+v", a.Licenses)
	}
	if a.Licenses[0].URL != "https://example.com/license" {
		t.Errorf("license url = %q", a.Licenses[0].URL)
	}
	if a.Params.Architecture != "llama" {
		t.Errorf("arch = %q", a.Params.Architecture)
	}
	if a.Params.Quantization != "Q4_K_M" {
		t.Errorf("quantization = %q, want Q4_K_M", a.Params.Quantization)
	}
	if got := a.Params.Hyperparameters["context_length"]; got != "8192" {
		t.Errorf("context_length hyperparameter = %q", got)
	}
	if len(a.Lineage.BaseModels) != 1 || a.Lineage.BaseModels[0].Name != "Meta-Llama-3-8B" {
		t.Fatalf("base models = %+v", a.Lineage.BaseModels)
	}
	if a.Lineage.BaseModels[0].URL == "" {
		t.Errorf("base model url not captured")
	}
	if len(a.Lineage.Datasets) != 2 {
		t.Errorf("datasets = %+v", a.Lineage.Datasets)
	}
	if a.TensorCount != 1 {
		t.Errorf("tensor count = %d", a.TensorCount)
	}
	if len(a.Tensors) != 1 || a.Tensors[0].DType != "Q4_K" {
		t.Errorf("tensors = %+v", a.Tensors)
	}
	if a.Raw["tokenizer.chat_template"] == "" {
		t.Errorf("chat_template not preserved in raw")
	}
}

func TestParseGGUFBadMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.gguf")
	os.WriteFile(path, []byte("NOPExxxxxxxxxxxx"), 0o644)
	a, err := ParseGGUF(path)
	if err != nil {
		t.Fatalf("ParseGGUF: %v", err)
	}
	if !hasFinding(a, "TESS-GGUF-001") {
		t.Errorf("expected bad-magic finding, got %+v", a.Findings)
	}
}

func hasFinding(a *model.Artifact, id string) bool {
	for _, f := range a.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}
