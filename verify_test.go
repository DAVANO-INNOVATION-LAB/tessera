package tessera_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	tessera "github.com/DAVANO-INNOVATION-LAB/tessera"
)

// Verification is the operation that matters at the point of use, so these
// tests are written the way it is actually exercised: generate a document,
// then check it against bytes that have or have not changed since.

func writeModelAt(t *testing.T, dir, name string, tensor string) string {
	t.Helper()
	header := map[string]any{
		"__metadata__": map[string]string{"format": "pt"},
		tensor:         map[string]any{"dtype": "F16", "shape": []int{2, 2}, "data_offsets": []int{0, 8}},
	}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(len(hb)))
	body := append(append(buf, hb...), make([]byte, 8)...)

	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// bomFor generates a document for an artifact and returns its path.
func bomFor(t *testing.T, artifact, format string) string {
	t.Helper()
	art, err := tessera.Analyze(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)

	var data []byte
	if format == "spdx" {
		data, err = tessera.SPDX(art, at)
	} else {
		data, err = tessera.CycloneDX(art, at)
	}
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "bom."+format+".json")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerifyRoundTripBothFormats(t *testing.T) {
	for _, format := range []string{"cyclonedx", "spdx"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			artifact := writeModelAt(t, dir, "model.safetensors", "w")
			bom := bomFor(t, artifact, format)

			res, err := tessera.Verify(context.Background(), bom, artifact)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !res.Verified {
				t.Errorf("a freshly generated document should verify against its own artifact; got %+v", res.Summary)
				for _, c := range res.Checks {
					t.Logf("  %s %s: %s", c.Outcome, c.Subject, c.Detail)
				}
			}
			if res.Summary.Passed == 0 {
				t.Error("verification passed without checking anything, which is not verification")
			}
		})
	}
}

// TestVerifyDetectsTampering is the whole point: a document written before the
// bytes changed must not still vouch for them.
func TestVerifyDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	artifact := writeModelAt(t, dir, "model.safetensors", "w")
	bom := bomFor(t, artifact, "cyclonedx")

	// Change one byte of the tensor payload, leaving the header intact so the
	// file still parses and only the digest moves.
	raw, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xFF
	if err := os.WriteFile(artifact, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := tessera.Verify(context.Background(), bom, artifact)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Verified {
		t.Fatal("a single flipped byte was not detected")
	}
	if res.Summary.Failed == 0 {
		t.Errorf("expected a failed check, got %+v", res.Summary)
	}
}

// TestVerifyDetectsUndocumentedFile covers the subtler failure: every documented
// claim holds, and something else rode along. That is the shape a smuggled
// payload takes, so passing it would defeat the purpose.
func TestVerifyDetectsUndocumentedFile(t *testing.T) {
	dir := t.TempDir()
	writeModelAt(t, dir, "model.safetensors", "w")
	index := filepath.Join(dir, "model.safetensors.index.json")
	os.WriteFile(index, []byte(`{"weight_map":{"w":"model.safetensors"}}`), 0o644)

	bom := bomFor(t, dir, "cyclonedx")

	// A shard appears after the document was written.
	writeModelAt(t, dir, "model-00002-of-00002.safetensors", "x")
	os.WriteFile(index, []byte(
		`{"weight_map":{"w":"model.safetensors","x":"model-00002-of-00002.safetensors"}}`), 0o644)

	res, err := tessera.Verify(context.Background(), bom, dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Verified {
		t.Fatal("a file present in the artifact and absent from the document must not verify")
	}
	if res.Summary.NotInDocument == 0 {
		t.Errorf("expected an undocumented component, got %+v", res.Summary)
	}
}

func TestVerifyRejectsNonDocuments(t *testing.T) {
	dir := t.TempDir()
	artifact := writeModelAt(t, dir, "model.safetensors", "w")

	notADoc := filepath.Join(dir, "notes.txt")
	os.WriteFile(notADoc, []byte("hello"), 0o644)

	if _, err := tessera.Verify(context.Background(), notADoc, artifact); err == nil {
		t.Error("a file that is not a bill of materials should be refused, not verified against")
	}
}
