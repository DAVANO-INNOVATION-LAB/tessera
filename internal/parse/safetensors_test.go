package parse

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// TestMaxHeaderBoundIsHonoured pins that a caller's memory ceiling actually
// reaches this parser. It previously did not: the option documented a cap on
// bytes held in memory, but safetensors used a hard-coded limit and ignored it,
// so an embedder that set a 16 MB ceiling could still be handed a 100 MB header.
func TestMaxHeaderBoundIsHonoured(t *testing.T) {
	// A header comfortably under the reference cap but over the caller's.
	body := map[string]any{}
	for i := 0; i < 400; i++ {
		body[strings.Repeat("t", 40)+strconv.Itoa(i)] = map[string]any{
			"dtype": "F16", "shape": []int{1}, "data_offsets": []int{0, 2},
		}
	}
	hb, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(len(hb)))
	data := append(append(buf, hb...), make([]byte, 2)...)

	path := filepath.Join(t.TempDir(), "big.safetensors")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// Under the default ceiling the header parses.
	a, err := parseSafetensorsBounded(path, stMaxHeader)
	if err != nil {
		t.Fatalf("default ceiling: %v", err)
	}
	if a.TensorCount != 400 {
		t.Errorf("default ceiling parsed %d tensors, want 400", a.TensorCount)
	}

	// With a ceiling below the header size it is refused rather than allocated.
	a, err = parseSafetensorsBounded(path, 1024)
	if err != nil {
		t.Fatalf("low ceiling: %v", err)
	}
	if a.TensorCount != 0 {
		t.Errorf("a header above the caller's ceiling was parsed anyway (%d tensors)", a.TensorCount)
	}
	var refused bool
	for _, f := range a.Findings {
		if f.ID == "TESS-ST-002" {
			refused = true
		}
	}
	if !refused {
		t.Errorf("expected TESS-ST-002 when the header exceeds the ceiling, got %+v", a.Findings)
	}
}
