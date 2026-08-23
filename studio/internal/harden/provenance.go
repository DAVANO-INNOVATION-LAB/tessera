package harden

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Provenance: what a hardened copy says about where it came from.
//
// A hardened model is a derivative work, and a derivative nobody can trace is a
// liability. Six months on, somebody finds a directory called
// "llama-3-8b-hardened" and has to answer three questions before they can use
// it: hardened from what, by removing what, and is the thing it came from still
// the thing they think it is. All three are unanswerable from the bytes alone,
// so they get written down at the moment they are known.
//
// The record is keyed on the **source digest**, not the source path. Paths move,
// get renamed and get copied between machines; the digest is what still
// identifies the original after all of that. A lineage built on paths would
// break the first time somebody reorganised a directory.
//
// What this file is NOT is proof. It is a claim, written by this tool, sitting
// in a directory anybody can write to — and a "hardened" badge that can be
// forged by dropping a JSON file next to a model would be worse than no badge
// at all, because it would launder an untouched model into a trusted one. The
// server's scan history is the authoritative side of this; see Verify.

// ProvenanceFile is where the record lives inside a hardened copy.
//
// Named rather than hidden. A dotfile would be invisible in the interfaces
// people actually use to look at model directories, and something this load
// bearing should not be discoverable only by those who already know it exists.
const ProvenanceFile = "tessera-hardening.json"

// ProvenanceSchema versions the record, so a reader that meets a future one can
// say so instead of silently misreading fields.
const ProvenanceSchema = "tessera.hardening/v1"

// Provenance is the record written into a hardened copy.
type Provenance struct {
	Schema string `json:"schema"`
	// HardenedAt is when the copy was written, in UTC.
	HardenedAt string `json:"hardenedAt"`
	Tool       string `json:"tool,omitempty"`

	// Source identifies the artifact this was derived from.
	Source ProvenanceSource `json:"source"`

	// Applied is the exact set of changes, kept in full. A summary ("2 actions")
	// would not let anybody reconstruct what the copy is missing, which is the
	// question asked when it fails to load.
	Applied []Action `json:"applied"`
	// Refused is carried too, because the findings hardening would not touch are
	// the ones still needing a human, and this file may outlive the scan that
	// reported them.
	Refused []Action `json:"refused,omitempty"`

	// FindingsBefore and FindingsAfter bracket what this achieved.
	FindingsBefore int `json:"findingsBefore"`
	FindingsAfter  int `json:"findingsAfter"`
}

// ProvenanceSource is the artifact a hardened copy came from.
type ProvenanceSource struct {
	// Path is what the operator called it, which is what they will recognise.
	Path string `json:"path,omitempty"`
	// Digest is the durable link: the SHA-256 of the source's primary file.
	Digest    string `json:"digest,omitempty"`
	ModelName string `json:"modelName,omitempty"`
	Format    string `json:"format,omitempty"`
	// Verdict records what the source scanned as, so the improvement is legible
	// from the copy alone.
	Verdict string `json:"verdict,omitempty"`
	// HardenedFrom is set when the source was itself a hardened copy, making the
	// chain walkable one link at a time from any point in it.
	HardenedFrom string `json:"hardenedFrom,omitempty"`
}

// WriteProvenance records the derivation inside the hardened copy.
func WriteProvenance(dir string, p Provenance) error {
	if p.Schema == "" {
		p.Schema = ProvenanceSchema
	}
	if p.HardenedAt == "" {
		p.HardenedAt = time.Now().UTC().Format(time.RFC3339)
	}
	data, err := json.MarshalIndent(&p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ProvenanceFile), append(data, '\n'), 0o644)
}

// ReadProvenance returns the record in a directory, if it has one.
//
// A missing file is not an error: most directories are not hardened copies, and
// asking is the normal case rather than the exceptional one.
func ReadProvenance(dir string) (*Provenance, bool) {
	data, err := os.ReadFile(filepath.Join(dir, ProvenanceFile))
	if err != nil {
		return nil, false
	}
	var p Provenance
	if err := json.Unmarshal(data, &p); err != nil {
		// A corrupt record reads as no record. Reporting a partially-parsed
		// lineage would be worse than reporting none: the fields that did parse
		// would look authoritative.
		return nil, false
	}
	if p.Schema != ProvenanceSchema {
		return nil, false
	}
	return &p, true
}

// SourceOf builds the source half of a record from an analysed original.
func SourceOf(path, digest, modelName, format, verdict string, parent *Provenance) ProvenanceSource {
	s := ProvenanceSource{
		Path: path, Digest: digest, ModelName: modelName,
		Format: format, Verdict: verdict,
	}
	if parent != nil {
		s.HardenedFrom = parent.Source.Digest
	}
	return s
}

// String renders a record for a terminal, where most of the questions it
// answers get asked.
func (p *Provenance) String() string {
	if p == nil {
		return ""
	}
	src := p.Source.Path
	if src == "" {
		src = p.Source.Digest
	}
	return fmt.Sprintf("hardened from %s at %s: %d action(s), findings %d -> %d",
		src, p.HardenedAt, len(p.Applied), p.FindingsBefore, p.FindingsAfter)
}
