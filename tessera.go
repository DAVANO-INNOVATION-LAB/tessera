// Package tessera reads a local AI model file — GGUF, safetensors, or ONNX —
// and produces a normalized description of it: identity, licence, lineage,
// parameters, per-file hashes, and the security findings its own metadata
// discloses. That description renders to CycloneDX 1.6 and SPDX 3.0.1.
//
// This is the embedding surface. It is designed to be imported directly by
// another Go program rather than shelled out to or run as a sidecar:
//
//	art, err := tessera.Analyze(ctx, "/models/llama3.gguf")
//	if err != nil { return err }
//	for _, f := range art.Findings { ... }
//	bom, err := tessera.CycloneDX(art, time.Now())
//
// Three properties make that embedding safe, and they are load-bearing enough
// that there are tests pinning them:
//
//   - Zero third-party dependencies. Only the Go standard library. An importer
//     inherits no transitive dependency tree, so there is no version conflict
//     to resolve and nothing new in its vendor directory or its image.
//   - No hidden state and no logging. Nothing is written to stdout or stderr,
//     ever — the caller owns all output. The one package-level variable is
//     Version, which main sets once at startup and everything else only reads.
//   - Safe for concurrent use. Analyze, Detect and the emitters may be called
//     from any number of goroutines; a single *Artifact must not be mutated
//     while another goroutine is reading it.
//   - No network. The net package is not in the dependency tree, so an
//     analysis cannot reach out even if a malicious artifact asks it to.
//
// Analysis reads headers and metadata only. It does not load a machine-learning
// framework, does not resolve an ONNX custom operator, and does not follow an
// ONNX external-data reference that escapes the model directory. Those are the
// behaviours it exists to report, so triggering them would defeat the purpose.
package tessera

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/coverage"
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/emit"
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/inspect"
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/parse"
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/verify"
)

// Version identifies the build, and is stamped into the tools section of every
// bill of materials so a consumer can tell which scanner made the claims.
//
// It is written once, from main, before any analysis starts, and only read
// afterwards. Do not assign it from concurrent code: an earlier version of the
// shared-library entry point assigned it on every call, which is a data race
// between concurrent callers.
var Version = "dev"

// toolIdentity is what the emitters stamp into the document metadata.
func toolIdentity() emit.Tool {
	return emit.Tool{Name: "tessera", Version: Version, Vendor: "Davano Innovation Lab"}
}

// Analyze reads the model at path and returns its normalized description.
//
// path may be a single model file or a directory containing one. For a
// directory, Analyze resolves the primary model file and gathers the physical
// files belonging to it — gguf-split shards, a safetensors index's shard set,
// ONNX external-data sidecars — hashing each independently so a multi-file
// model is a set of pinned components rather than one opaque blob.
//
// A parse problem inside a recognized file is reported as a Finding, not as an
// error: a malformed header is a fact about the artifact that the caller needs,
// and returning it as an error would discard everything else that was read. An
// error is returned only when there is nothing to describe at all — the path is
// unreadable, or it holds no recognized model format.
func Analyze(ctx context.Context, path string, opts ...Option) (*Artifact, error) {
	cfg := newConfig(opts)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return parse.Parse(ctx, path, cfg.parseOptions())
}

// Detect reports which model format the file at path is, without parsing it.
// ok is false when the file is not a format this package understands. Detection
// prefers content over extension, because an attacker renames files.
func Detect(path string) (format Format, ok bool) {
	return parse.Detect(path)
}

// Inspect walks a staged artifact directory and reports risks that live in the
// files around the model as much as in the model itself.
//
// This is a different question from Analyze. Analyze opens one model and
// describes it; Inspect walks everything present and asks what a loader would
// execute. That distinction matters because the formats Tessera parses natively
// — GGUF, safetensors, ONNX — are precisely the ones that cannot carry code. The
// attack lands in the pickle, the Keras Lambda layer, or the TensorFlow graph op
// sitting in the same directory, and a scan that only opened the safetensors
// would report a clean artifact.
//
// It examines pickle and PyTorch containers by opcode, Keras archives and HDF5
// configs, TensorFlow SavedModel graphs, NumPy arrays, ZIP and tar archives,
// and loose Python. Bounded by default so a hostile artifact cannot exhaust the
// host; a walk that hits a cap reports Truncated rather than a clean result,
// because a clean report over a partial walk is not a clean artifact.
func Inspect(ctx context.Context, root string, opts ...Option) (*InspectReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cfg := newConfig(opts)
	limits := inspect.DefaultLimits()
	if cfg.maxFiles > 0 {
		limits.MaxFiles = cfg.maxFiles
	}
	return inspect.Inspect(root, limits)
}

// InspectLimits bound the inspector's work.
func InspectLimits() InspectLimitSet { return inspect.DefaultLimits() }

// CycloneDX renders the artifact as a CycloneDX ML-BOM at the default spec
// version (1.6). Use CycloneDXVersion to choose one.
//
// generatedAt is supplied by the caller rather than read from the clock so that
// output is reproducible: the same artifact and the same timestamp produce
// byte-identical bytes. Findings are included as a vulnerability-disclosure
// report affecting the model component, so the bill of materials and the risk
// assessment cannot be separated in transit.
func CycloneDX(a *Artifact, generatedAt time.Time) ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("tessera: nil artifact")
	}
	return emit.CycloneDX(a, generatedAt, toolIdentity())
}

// Supported CycloneDX specification versions. 1.6 is the default; 1.7 is
// available for readers that require the current spec.
const (
	CycloneDX16 = emit.CycloneDX16
	CycloneDX17 = emit.CycloneDX17
)

// CycloneDXVersion renders the artifact as a CycloneDX ML-BOM at a named spec
// version. An unrecognized version is an error rather than a silent fallback.
func CycloneDXVersion(a *Artifact, generatedAt time.Time, specVersion string) ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("tessera: nil artifact")
	}
	return emit.CycloneDXVersion(a, generatedAt, toolIdentity(), specVersion)
}

// SPDX renders the artifact as an SPDX 3.0.1 JSON-LD document using the AI and
// Dataset profiles. As with CycloneDX, generatedAt is the caller's to supply.
func SPDX(a *Artifact, generatedAt time.Time) ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("tessera: nil artifact")
	}
	return emit.SPDX(a, generatedAt, toolIdentity())
}

// SARIF renders the artifact's findings as a SARIF 2.1.0 log, the format code
// scanning pipelines ingest. A model with no findings produces a valid log with
// no results, which reports a clean scan rather than a broken step.
func SARIF(a *Artifact, generatedAt time.Time) ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("tessera: nil artifact")
	}
	return emit.SARIF(a, generatedAt, toolIdentity())
}

// Severity ranks a finding's severity for ordering, lowest number most severe.
// Callers mapping findings into their own model use this to sort or to derive a
// gate decision without hard-coding the severity vocabulary.
func Severity(s string) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	}
	return 4
}

// Worst returns the most severe severity among findings, or "" when there are
// none. It is the one-line answer to "should this artifact be allowed through".
func Worst(findings []Finding) string {
	worst := ""
	rank := 5
	for _, f := range findings {
		if r := Severity(f.Severity); r < rank {
			rank, worst = r, f.Severity
		}
	}
	return worst
}

// Verify checks a bill of materials against the artifact it claims to describe.
//
// This is the inverse of generating one, and the operation that matters at the
// point of use: a document produced at build time says nothing about the bytes
// in front of you now unless somebody checks. Korea's Framework Act requires
// inspecting the "currency and accuracy" of such documents, Canada's ITSP.80.101
// says to verify integrity before a model is loaded, and the G7 minimum elements
// name a hash algorithm from the IANA registry precisely so a third party can
// recompute it. Verify is that recomputation.
//
// documentPath is a CycloneDX or SPDX document, detected by content rather than
// by filename. artifactPath is the model, analysed fresh. Where the two
// disagree, the bytes are treated as true and the report names the failed claim.
//
// A document whose claims all pass but which omits a file that is present is
// reported as unverified: an undocumented component is the shape a smuggled
// payload takes.
func Verify(ctx context.Context, documentPath, artifactPath string, opts ...Option) (*VerifyResult, error) {
	doc, err := verify.ReadDocument(documentPath)
	if err != nil {
		return nil, err
	}
	art, err := Analyze(ctx, artifactPath, opts...)
	if err != nil {
		return nil, err
	}
	return verify.Verify(ctx, doc, art), nil
}

// Coverage reports which elements of a published minimum-elements standard a
// given artifact actually supplies.
//
// The G7 minimum elements and CERT-In's AIBOM table are the checklists a
// regulated buyer holds this output against, and neither publisher ships
// anything that measures conformance against them. Reporting coverage — with
// the gaps named and the unfillable ones distinguished from the merely missing
// — is more useful than claiming a percentage, because the gaps are the part a
// buyer will otherwise discover on their own.
func Coverage(ctx context.Context, standard string, artifactPath string, opts ...Option) (*CoverageReport, error) {
	art, err := Analyze(ctx, artifactPath, opts...)
	if err != nil {
		return nil, err
	}
	return coverage.Assess(coverage.Standard(standard), art)
}

// CoverageStandards lists the standards Coverage can report against.
func CoverageStandards() []string {
	out := make([]string, 0, len(coverage.Standards()))
	for _, s := range coverage.Standards() {
		out = append(out, string(s))
	}
	return out
}
