package parse

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeSafetensors(t *testing.T, meta map[string]string) string {
	t.Helper()
	header := map[string]any{
		"__metadata__": meta,
		"model.embed.weight": map[string]any{
			"dtype":        "F16",
			"shape":        []int{4096, 128256},
			"data_offsets": []int{0, 1048576},
		},
	}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	lenbuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenbuf, uint64(len(hb)))
	out = append(out, lenbuf...)
	out = append(out, hb...)
	out = append(out, make([]byte, 16)...) // token of tensor data

	dir := t.TempDir()
	path := filepath.Join(dir, "model.safetensors")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseSafetensors(t *testing.T) {
	path := writeSafetensors(t, map[string]string{
		"format":     "pt",
		"license":    "mit",
		"base_model": "bert-base-uncased",
	})
	a, err := ParseSafetensors(path)
	if err != nil {
		t.Fatalf("ParseSafetensors: %v", err)
	}
	if a.Runtime.Framework != "safetensors (pt)" {
		t.Errorf("framework = %q", a.Runtime.Framework)
	}
	if len(a.Licenses) != 1 || a.Licenses[0].Raw != "mit" {
		t.Errorf("licenses = %+v", a.Licenses)
	}
	if len(a.Lineage.BaseModels) != 1 {
		t.Errorf("base models = %+v", a.Lineage.BaseModels)
	}
	if a.TensorCount != 1 {
		t.Errorf("tensor count = %d", a.TensorCount)
	}
	if len(a.Tensors) != 1 || a.Tensors[0].DType != "F16" {
		t.Errorf("tensors = %+v", a.Tensors)
	}
	if a.Raw["__metadata__.format"] != "pt" {
		t.Errorf("metadata not preserved: %+v", a.Raw)
	}
}

func TestParseSafetensorsBadHeaderLen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.safetensors")
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, 1<<40) // absurd header length
	os.WriteFile(path, buf, 0o644)
	a, err := ParseSafetensors(path)
	if err != nil {
		t.Fatalf("ParseSafetensors: %v", err)
	}
	if !hasFinding(a, "TESS-ST-002") {
		t.Errorf("expected invalid-header finding, got %+v", a.Findings)
	}
}
