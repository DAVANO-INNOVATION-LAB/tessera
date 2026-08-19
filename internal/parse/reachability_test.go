package parse

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Reachability tests: every finding this package can emit must be provably
// producible by some input.
//
// This exists because a finding was once documented, listed in the README, and
// unreachable — DOCKET/TESS-DRIFT-006 read the component list looking for a
// stray pickle, and a stray pickle is deliberately never added to the component
// list, so the exact case it described could not fire. Nothing failed. The
// finding simply never appeared, which is indistinguishable from "the artifact
// was clean" to anyone reading the output.
//
// A security tool that ships an assertion it cannot make is worse than one that
// never claimed it. So each guard below is driven with an input that should
// trip it, and the test fails if it does not.

// ggufHeader builds a GGUF v3 header with the given counts.
func ggufHeader(version uint32, tensors, kv uint64) []byte {
	var b []byte
	p32 := func(v uint32) { var t [4]byte; binary.LittleEndian.PutUint32(t[:], v); b = append(b, t[:]...) }
	p64 := func(v uint64) { var t [8]byte; binary.LittleEndian.PutUint64(t[:], v); b = append(b, t[:]...) }
	b = append(b, "GGUF"...)
	p32(version)
	p64(tensors)
	p64(kv)
	return b
}

func p64(b []byte, v uint64) []byte {
	var t [8]byte
	binary.LittleEndian.PutUint64(t[:], v)
	return append(b, t[:]...)
}

func p32(b []byte, v uint32) []byte {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], v)
	return append(b, t[:]...)
}

func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func idsFor(t *testing.T, path string) []string {
	t.Helper()
	a, err := Parse(context.Background(), path, Options{})
	if err != nil {
		return nil
	}
	var out []string
	for _, f := range a.Findings {
		out = append(out, f.ID)
	}
	return out
}

func TestEveryParseFindingIsReachable(t *testing.T) {
	// A GGUF string value: uint64 length then bytes.
	gstr := func(b []byte, s string) []byte { return append(p64(b, uint64(len(s))), s...) }

	cases := []struct {
		id    string
		name  string
		build func() []byte
	}{
		{"TESS-GGUF-001", "bad.gguf", func() []byte {
			return []byte("NOTGGUF-and-then-some-padding-bytes")
		}},
		{"TESS-GGUF-002", "kvcount.gguf", func() []byte {
			return ggufHeader(3, 0, ^uint64(0)) // implausible metadata count
		}},
		{"TESS-GGUF-005", "tensors.gguf", func() []byte {
			return ggufHeader(3, ^uint64(0), 0) // implausible tensor count
		}},
		{"TESS-GGUF-003", "longstr.gguf", func() []byte {
			return p64(ggufHeader(3, 0, 1), ^uint64(0)-8) // key length past the cap
		}},
		{"TESS-GGUF-007", "longarr.gguf", func() []byte {
			b := gstr(ggufHeader(3, 0, 1), "evil")
			b = p32(b, uint32(ggArray))
			b = p32(b, uint32(ggString))
			return p64(b, ^uint64(0)) // element count past the cap
		}},
		{"TESS-GGUF-006", "nested.gguf", func() []byte {
			b := gstr(ggufHeader(3, 0, 1), "evil")
			b = p32(b, uint32(ggArray))
			b = p32(b, uint32(ggArray)) // an array of arrays
			return p64(b, 1)
		}},
		{"TESS-GGUF-004", "dims.gguf", func() []byte {
			b := gstr(ggufHeader(3, 1, 0), "t")
			return p32(b, 99) // impossible dimension count
		}},
		{"TESS-GGUF-008", "v1.gguf", func() []byte {
			return ggufHeader(1, 2, 1) // unsupported version
		}},
		{"TESS-ST-001", "short.safetensors", func() []byte {
			return []byte{1, 2, 3} // too short for the length prefix
		}},
		{"TESS-ST-002", "badlen.safetensors", func() []byte {
			return p64(nil, ^uint64(0)) // header longer than the file
		}},
		{"TESS-ST-003", "badjson.safetensors", func() []byte {
			return append(p64(nil, 2), '{', '{') // valid length, invalid JSON
		}},
	}

	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			got := idsFor(t, writeFixture(t, c.name, c.build()))
			for _, id := range got {
				if id == c.id {
					return
				}
			}
			t.Errorf("%s is emitted by the code and documented, but no input reached it. got %v", c.id, got)
		})
	}
}

// TestPeerPickleIsReportedButNotAComponent is the specific regression for the
// unreachable finding: the peer file must be reported, and must NOT be hashed
// into the model's component set, because it is not part of this model.
func TestPeerPickleIsReportedButNotAComponent(t *testing.T) {
	dir := t.TempDir()
	writeMinimalSafetensors(t, filepath.Join(dir, "model.safetensors"))
	if err := os.WriteFile(filepath.Join(dir, "pytorch_model.bin"), []byte("\x80\x05stub"), 0o644); err != nil {
		t.Fatal(err)
	}

	a, err := Parse(context.Background(), dir, Options{})
	if err != nil {
		t.Fatal(err)
	}

	var reported bool
	for _, f := range a.Findings {
		if f.ID == "TESS-DRIFT-006" {
			reported = true
		}
	}
	if !reported {
		t.Error("a pickle beside safetensors must be reported as TESS-DRIFT-006")
	}
	for _, f := range a.Files {
		if strings.HasSuffix(f.Path, ".bin") {
			t.Errorf("the peer pickle was added to the component set: %+v — it is not part of "+
				"this model, and hashing it in describes an artifact nobody shipped", f)
		}
	}
}
