package inspect

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// A GGUF the scanner cannot read must not report as a GGUF it read and liked.
//
// The checks for these have existed in the parser from the start. The scanner
// simply never dispatched the extension, so every one of them was unreachable
// from a scan and a malformed GGUF came back clean.
func TestAMalformedGGUFDoesNotScanClean(t *testing.T) {
	hdr := func(version uint32, tensors, kv uint64) []byte {
		b := []byte("GGUF")
		b = binary.LittleEndian.AppendUint32(b, version)
		b = binary.LittleEndian.AppendUint64(b, tensors)
		b = binary.LittleEndian.AppendUint64(b, kv)
		return b
	}

	cases := []struct {
		name string
		data []byte
	}{
		{"truncated after the magic", []byte("GGUF")},
		{"implausible tensor count", hdr(3, math.MaxUint64, 4)},
		{"implausible metadata count", hdr(3, 4, math.MaxUint64)},
		{"not GGUF at all", []byte("NOPE\x00\x00\x00\x00")},
		{"version 1, whose layout differs", hdr(1, 4, 4)},
		{"empty file", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "model.gguf")
			if err := os.WriteFile(path, tc.data, 0o644); err != nil {
				t.Fatal(err)
			}
			findings, err := inspectGGUF(path, "model.gguf")
			if err != nil {
				t.Fatalf("inspect returned an error instead of a finding: %v", err)
			}
			if len(findings) == 0 {
				t.Fatal("scanned clean: this reads to an approver exactly like a file that " +
					"was examined and found sound")
			}
			for _, f := range findings {
				if f.Location != "model.gguf" {
					t.Errorf("finding points at %q rather than the path within the artifact", f.Location)
				}
			}
			t.Logf("%s -> %s (%s)", tc.name, findings[0].ID, findings[0].Severity)
		})
	}
}

// The counter-check. Adding a dispatch that flags every real model would be a
// worse defect than the gap it closed, so a well-formed GGUF must still scan
// clean — including a chat model, whose template is the usual source of noise.
func TestAWellFormedGGUFStillScansClean(t *testing.T) {
	cases := []struct {
		name string
		kv   map[string]string
	}{
		{"a plain model", map[string]string{
			"general.architecture": "llama",
			"general.name":         "test-model",
		}},
		{"a chat model with an ordinary template", map[string]string{
			"general.architecture":    "llama",
			"general.name":            "test-chat",
			"tokenizer.chat_template": "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}\n{% endfor %}{% if add_generation_prompt %}assistant: {% endif %}",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "model.gguf")
			writeValidGGUF(t, path, tc.kv)

			findings, err := inspectGGUF(path, "model.gguf")
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 0 {
				for _, f := range findings {
					t.Errorf("false positive on a valid model: %s %s — %s",
						f.ID, f.Severity, f.Description)
				}
			}
		})
	}
}

func writeValidGGUF(t *testing.T, path string, kv map[string]string) {
	t.Helper()
	var b []byte
	p32 := func(v uint32) { var x [4]byte; binary.LittleEndian.PutUint32(x[:], v); b = append(b, x[:]...) }
	p64 := func(v uint64) { var x [8]byte; binary.LittleEndian.PutUint64(x[:], v); b = append(b, x[:]...) }
	str := func(s string) { p64(uint64(len(s))); b = append(b, s...) }

	b = append(b, "GGUF"...)
	p32(3)
	p64(1) // one tensor
	p64(uint64(len(kv)))
	for k, v := range kv {
		str(k)
		p32(8) // string
		str(v)
	}
	str("blk.0.weight")
	p32(2)
	p64(4096)
	p64(4096)
	p32(1) // F16
	p64(0)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
