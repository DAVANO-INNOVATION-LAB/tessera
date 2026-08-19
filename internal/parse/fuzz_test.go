package parse

import (
	"os"
	"path/filepath"
	"testing"
)

// Fuzzing is the load-bearing test for this package. Every parser here consumes
// a file an attacker controls completely, and the library is meant to be
// embedded in a long-running service, so a panic is not a crash of a scanning
// tool — it takes down the host process. The bar these targets enforce is
// therefore absolute: no input, however malformed, may panic.
//
// Run a longer campaign with:
//
//	go test ./internal/parse -fuzz FuzzGGUF -fuzztime 2m

// writeTemp puts fuzz input on disk, since the parsers take paths.
func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func FuzzGGUF(f *testing.F) {
	// Seeds: a valid file, and the shapes most likely to break a reader.
	f.Add([]byte("GGUF"))
	f.Add([]byte("GGUF\x03\x00\x00\x00"))
	// version 3, tensor_count and kv_count both absurd
	f.Add([]byte("GGUF\x03\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"))
	// one KV whose key length is enormous
	f.Add([]byte("GGUF\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"))
	if b, err := os.ReadFile("../../testdata/llama3-8b-instruct.Q4_K_M.gguf"); err == nil {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// The only contract: it may fail, it may find nothing, it must not panic.
		_, _ = ParseGGUF(writeTemp(t, "f.gguf", data))
	})
}

func FuzzSafetensors(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("\x00\x00\x00\x00\x00\x00\x00\x00"))
	// header length larger than the file
	f.Add([]byte("\xff\xff\xff\xff\xff\xff\xff\xff{}"))
	// valid length, invalid JSON
	f.Add([]byte("\x02\x00\x00\x00\x00\x00\x00\x00{{"))
	// well-formed header with hostile offsets
	f.Add([]byte(`\x36\x00\x00\x00\x00\x00\x00\x00{"a":{"dtype":"F16","shape":[-1],"data_offsets":[0,999]}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseSafetensors(writeTemp(t, "f.safetensors", data))
	})
}

func FuzzONNX(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x08, 0x09})             // ir_version = 9
	f.Add([]byte{0x3a, 0xff, 0xff, 0xff}) // length-delimited field claiming a huge length
	f.Add([]byte{0x12, 0x03, 'a', 'b', 'c'})
	// deeply nested submessages — the protobuf-bomb shape
	nested := []byte{}
	for i := 0; i < 200; i++ {
		nested = append([]byte{0x3a, byte(len(nested))}, nested...)
	}
	f.Add(nested)
	if b, err := os.ReadFile("../../testdata/detector.onnx"); err == nil {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseONNX(writeTemp(t, "f.onnx", data))
	})
}

// FuzzProtowire targets the wire reader directly, which is the layer that has
// to survive hostile framing before any ONNX semantics are involved.
func FuzzProtowire(f *testing.F) {
	f.Add([]byte{0x08, 0x01})
	f.Add([]byte{0x0a, 0x02, 'h', 'i'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		g := defaultGuards()
		// A handler that recurses into every length-delimited field is the
		// worst case for depth, which is exactly what should stay bounded.
		var descend func([]byte, int) error
		descend = func(b []byte, depth int) error {
			return walk(b, g, depth, func(fld pbField) error {
				if fld.wire == wireLen && len(fld.data) > 0 {
					_ = descend(fld.data, depth+1)
				}
				return nil
			})
		}
		_ = descend(data, 0)
	})
}
