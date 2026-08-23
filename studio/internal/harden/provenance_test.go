package harden

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestProvenanceRoundTrips(t *testing.T) {
	dir := t.TempDir()
	in := Provenance{
		Source: ProvenanceSource{
			Path: "models/llama", Digest: "abc123", ModelName: "llama", Verdict: "Quarantined",
		},
		Applied:        []Action{{Kind: KindRemoveFile, Path: "tokenizer.pkl"}},
		FindingsBefore: 6, FindingsAfter: 3,
	}
	if err := WriteProvenance(dir, in); err != nil {
		t.Fatal(err)
	}
	out, ok := ReadProvenance(dir)
	if !ok {
		t.Fatal("record did not read back")
	}
	if out.Source.Digest != "abc123" || out.FindingsAfter != 3 {
		t.Errorf("round trip lost data: %+v", out)
	}
	if out.HardenedAt == "" {
		t.Error("no timestamp was stamped")
	}
	if out.Schema != ProvenanceSchema {
		t.Errorf("schema = %q", out.Schema)
	}
}

// A directory with no record, a corrupt record, or a record from a future
// schema all read as "no record" rather than as a partial one. A half-parsed
// lineage is worse than none: the fields that did survive look authoritative.
func TestProvenanceRejectsUnusableRecords(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"absent", ""},
		{"corrupt", "{not json"},
		{"future schema", `{"schema":"tessera.hardening/v99","source":{"digest":"x"}}`},
		{"no schema", `{"source":{"digest":"x"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.body != "" {
				os.WriteFile(filepath.Join(dir, ProvenanceFile), []byte(tc.body), 0o644)
			}
			if _, ok := ReadProvenance(dir); ok {
				t.Error("an unusable record was accepted")
			}
		})
	}
}

// Apply writes the record, and it describes what actually happened rather than
// what was proposed: a deselected action must not appear in the applied list.
func TestApplyRecordsOnlyWhatItDid(t *testing.T) {
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "a.pkl"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(src, "b.pkl"), []byte("x"), 0o644)
	dest := filepath.Join(t.TempDir(), "out")

	plan := Plan{Actions: []Action{
		{Kind: KindRemoveFile, Path: "a.pkl", Selected: true},
		{Kind: KindRemoveFile, Path: "b.pkl", Selected: false},
	}}
	res, err := Apply(src, dest, plan, &Provenance{
		Source: ProvenanceSource{Digest: "src-digest", Path: "orig"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := ReadProvenance(dest)
	if !ok {
		t.Fatal("Apply wrote no record")
	}
	if len(rec.Applied) != 1 || rec.Applied[0].Path != "a.pkl" {
		t.Errorf("record claims %d actions, want only the selected one: %+v",
			len(rec.Applied), rec.Applied)
	}
	if res.Provenance == nil {
		t.Error("Apply did not return the record it wrote")
	}
	if _, err := os.Stat(filepath.Join(dest, "b.pkl")); err != nil {
		t.Error("a deselected action was applied anyway")
	}
}

// Hardening a hardened copy must not inherit the parent's record. A copy
// carrying its source's provenance would claim to be derived from its own
// grandparent, quietly skipping a link in the chain.
func TestHardeningAHardenedCopyDoesNotInheritItsRecord(t *testing.T) {
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "a.pkl"), []byte("x"), 0o644)
	if err := WriteProvenance(src, Provenance{
		Source: ProvenanceSource{Digest: "grandparent", Path: "original"},
	}); err != nil {
		t.Fatal(err)
	}
	parent, _ := ReadProvenance(src)

	dest := filepath.Join(t.TempDir(), "out")
	_, err := Apply(src, dest, Plan{Actions: []Action{
		{Kind: KindRemoveFile, Path: "a.pkl", Selected: true},
	}}, &Provenance{
		Source: SourceOf("mid", "parent-digest", "", "", "ReviewRequired", parent),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := ReadProvenance(dest)
	if !ok {
		t.Fatal("no record written")
	}
	if rec.Source.Digest != "parent-digest" {
		t.Errorf("source digest = %q, want the immediate parent", rec.Source.Digest)
	}
	if rec.Source.HardenedFrom != "grandparent" {
		t.Errorf("hardenedFrom = %q, want the grandparent so the chain stays walkable",
			rec.Source.HardenedFrom)
	}

	// And the file on disk must be the new one, not the copied-over old one.
	raw, _ := os.ReadFile(filepath.Join(dest, ProvenanceFile))
	var onDisk Provenance
	json.Unmarshal(raw, &onDisk)
	if onDisk.Source.Digest == "grandparent" {
		t.Error("the source's own record was copied into the derivative")
	}
}
