package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The attestation record is the durable artifact — somebody may read it years
// after everyone who produced it has moved on. Its shape is a contract, and
// each field below exists because dropping it would break a specific check.
func TestAttestationRecordBindsDocumentToArtifact(t *testing.T) {
	raw := []byte(`{
      "kind":"tessera-aibom-attestation/v1",
      "document":"m.cdx.json","documentSha256":"aa",
      "artifact":"model.gguf","artifactSha256":"bb","artifactFormat":"gguf",
      "tool":"tessera","toolVersion":"v1.0.0","attestedAt":"2026-08-20T00:00:00Z",
      "signature":{"version":1,"suite":"x","signedAt":"2026-08-20T00:00:00Z"}}`)
	var rec attestation
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("the record shape changed incompatibly: %v", err)
	}
	if rec.DocumentSHA256 == "" {
		t.Error("no document digest: the attestation could be moved onto a different document")
	}
	if rec.ArtifactSHA256 == "" {
		t.Error("no artifact digest: nothing ties the document to the model it describes, " +
			"which is the whole difference between an attestation and a signature")
	}
	if rec.Kind == "" {
		t.Error("no kind: a reader cannot tell what this file is without guessing")
	}
	if rec.Signature == nil {
		t.Error("no signature")
	}
}

// An attestation with no signature must not verify. It reads as a complete
// record otherwise, which is exactly why it has to be rejected explicitly.
func TestUnsignedAttestationIsRejected(t *testing.T) {
	dir := t.TempDir()
	doc := filepath.Join(dir, "m.cdx.json")
	if err := os.WriteFile(doc, []byte(`{"bomFormat":"CycloneDX"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	att := doc + ".att.json"
	if err := os.WriteFile(att, []byte(`{"kind":"tessera-aibom-attestation/v1",
      "document":"m.cdx.json","documentSha256":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(dir, "k.pub")
	if err := os.WriteFile(pub, []byte("not a key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := runVerifyAttestation([]string{att, "--public", pub}); code == exitOK {
		t.Error("an attestation carrying no signature verified")
	}
}

func TestSlugOfProducesFilesystemSafeStems(t *testing.T) {
	for in, want := range map[string]string{
		"Meta-Llama-3-8B-Instruct": "meta-llama-3-8b-instruct",
		"org/model:v1":             "org-model-v1",
		"":                         "model",
		"///":                      "model",
		"a b c":                    "a-b-c",
	} {
		if got := slugOf(in); got != want {
			t.Errorf("slugOf(%q) = %q, want %q", in, got, want)
		}
	}
}
