package ingest

import "github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"

// The scanner vocabulary this package needs, kept here rather than imported.
//
// Assay owns a catalogue of scanner container images — which image runs, what
// arguments it takes, whether it is enabled by default. None of that means
// anything inside a single static binary with no cluster to schedule pods on.
// What does travel is the naming: the categories a finding falls into and the
// output formats these tools write. Copying that vocabulary is a few lines;
// importing the catalogue would drag orchestration into a library whose whole
// value is having none.
type Category string

const (
	CategoryMalware    Category = "malware"
	CategoryCVE        Category = "cve"
	CategorySBOM       Category = "sbom"
	CategorySecret     Category = "secret"
	CategoryLicense    Category = "license"
	CategoryModel      Category = "model"
	CategoryProvenance Category = "provenance"
	CategoryAIBOM      Category = "aibom"
)

// Output formats this package can read.
const (
	FormatTessera    = "tessera"
	FormatClamAV     = "clamav"
	FormatTrivyJSON  = "trivy-json"
	FormatGrypeJSON  = "grype-json"
	FormatSyftSPDX   = "syft-spdx"
	FormatTrufflehog = "trufflehog-json"
)

// SeverityCounts is the shared tally type, defined beside Finding.
type SeverityCounts = model.SeverityCounts
