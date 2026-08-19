package parse

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end reachability for the drift findings.
//
// internal/scan already unit-tests these against hand-built artifacts, and that
// is not enough: TESS-DRIFT-006 once had a unit test that passed for months
// while the finding could not fire through the real pipeline at all, because
// the test constructed the artifact the way the broken code expected rather
// than the way the parser produces one.
//
// So these drive the whole path — real files on disk, through Parse — and
// assert that each finding actually appears. A finding that cannot be reached
// from bytes is not a finding.

// buildGGUF writes a minimal well-formed GGUF with the given metadata.
func buildGGUF(t *testing.T, path string, strs map[string]string, u32s map[string]uint32, tensorDims []uint64) {
	t.Helper()
	var b []byte
	p32 := func(v uint32) { var x [4]byte; binary.LittleEndian.PutUint32(x[:], v); b = append(b, x[:]...) }
	p64 := func(v uint64) { var x [8]byte; binary.LittleEndian.PutUint64(x[:], v); b = append(b, x[:]...) }
	str := func(s string) { p64(uint64(len(s))); b = append(b, s...) }

	b = append(b, "GGUF"...)
	p32(3)
	nTensors := uint64(0)
	if len(tensorDims) > 0 {
		nTensors = 1
	}
	p64(nTensors)
	p64(uint64(len(strs) + len(u32s)))

	for k, v := range strs {
		str(k)
		p32(uint32(ggString))
		str(v)
	}
	for k, v := range u32s {
		str(k)
		p32(uint32(ggUint32))
		p32(v)
	}
	if nTensors == 1 {
		str("blk.0.weight")
		p32(uint32(len(tensorDims)))
		for _, d := range tensorDims {
			p64(d)
		}
		p32(1) // F16
		p64(0) // offset
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// buildSafetensors writes a minimal safetensors file with one tensor.
func buildSafetensors(t *testing.T, path, dtype string, shape []int) {
	t.Helper()
	n := 1
	for _, d := range shape {
		n *= d
	}
	hdr := map[string]any{
		"__metadata__": map[string]string{"format": "pt"},
		"w":            map[string]any{"dtype": dtype, "shape": shape, "data_offsets": []int{0, n * 2}},
	}
	hb, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(len(hb)))
	if err := os.WriteFile(path, append(append(buf, hb...), make([]byte, n*2)...), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEveryDriftFindingIsReachable(t *testing.T) {
	cases := []struct {
		id    string
		build func(t *testing.T, dir string)
	}{
		{"TESS-DRIFT-001", func(t *testing.T, dir string) {
			// The binary records llama; the config claims Mistral.
			buildGGUF(t, filepath.Join(dir, "m.gguf"),
				map[string]string{"general.architecture": "llama", "general.name": "m"},
				nil, []uint64{64, 64})
			writeJSON(t, filepath.Join(dir, "config.json"),
				map[string]any{"architectures": []string{"MistralForCausalLM"}})
		}},
		{"TESS-DRIFT-002", func(t *testing.T, dir string) {
			// Declared full precision over eight-bit weights.
			buildSafetensors(t, filepath.Join(dir, "model.safetensors"), "F8_E4M3", []int{512, 512})
			writeJSON(t, filepath.Join(dir, "config.json"),
				map[string]any{"architectures": []string{"X"}, "torch_dtype": "bfloat16"})
		}},
		{"TESS-DRIFT-003", func(t *testing.T, dir string) {
			// The file reports Q4_K_M; the config declares awq.
			buildGGUF(t, filepath.Join(dir, "m.gguf"),
				map[string]string{"general.architecture": "llama", "general.name": "m"},
				map[string]uint32{"general.file_type": 15}, []uint64{64, 64})
			writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
				"architectures":       []string{"LlamaForCausalLM"},
				"quantization_config": map[string]any{"quant_method": "awq", "bits": 4},
			})
		}},
		{"TESS-DRIFT-004", func(t *testing.T, dir string) {
			// The index names three shards; one is present.
			buildSafetensors(t, filepath.Join(dir, "model.safetensors"), "F16", []int{4, 4})
			writeJSON(t, filepath.Join(dir, "model.safetensors.index.json"), map[string]any{
				"weight_map": map[string]string{
					"a": "model.safetensors", "b": "shard-b.safetensors", "c": "shard-c.safetensors",
				},
			})
		}},
		{"TESS-DRIFT-005", func(t *testing.T, dir string) {
			// An architecture is declared; safetensors records none to check it against.
			buildSafetensors(t, filepath.Join(dir, "model.safetensors"), "F16", []int{4, 4})
			writeJSON(t, filepath.Join(dir, "config.json"),
				map[string]any{"architectures": []string{"LlamaForCausalLM"}})
		}},
		{"TESS-DRIFT-006", func(t *testing.T, dir string) {
			// A pickle sitting beside a safe format.
			buildSafetensors(t, filepath.Join(dir, "model.safetensors"), "F16", []int{4, 4})
			os.WriteFile(filepath.Join(dir, "pytorch_model.bin"), []byte("\x80\x05stub"), 0o644)
		}},
		{"TESS-DRIFT-007", func(t *testing.T, dir string) {
			// Declared eight billion parameters; sixty-four present.
			buildSafetensors(t, filepath.Join(dir, "model.safetensors"), "F16", []int{8, 8})
			writeJSON(t, filepath.Join(dir, "config.json"),
				map[string]any{"architectures": []string{"X"}, "num_parameters": 8_000_000_000})
		}},
	}

	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			dir := t.TempDir()
			c.build(t, dir)

			a, err := Parse(context.Background(), dir, Options{})
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			var got []string
			for _, f := range a.Findings {
				got = append(got, f.ID)
				if f.ID == c.id {
					return
				}
			}
			t.Errorf("%s is emitted by the code and documented, but no artifact on disk reached it. got %v",
				c.id, strings.Join(got, " "))
		})
	}
}
