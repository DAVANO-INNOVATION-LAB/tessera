package gate

import (
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// The policy vocabulary, as plain Go.
//
// These began as Kubernetes custom-resource types, and the Kubernetes part was
// never load-bearing: the rules are a struct of thresholds and booleans, and an
// exception is a waiver with an expiry. Only the wrappers carried ObjectMeta.
// Flattening them means the same gate that decides whether a model may be
// admitted to a cluster also runs in a CI job, on a laptop, or inside an
// air-gapped enclave with no API server to ask.
//
// Cupel maps its custom resources onto these at the boundary, so there is one
// implementation of the decision rather than two that drift.

// Verdicts a gate can reach.
const (
	VerdictApproved       = "Approved"
	VerdictQuarantined    = "Quarantined"
	VerdictReviewRequired = "ReviewRequired"
)

// Rules are the thresholds and requirements a scan is judged against. Pointer
// fields distinguish "not set, use the default" from "deliberately set to
// zero", which for a threshold are opposite instructions.
type Rules struct {
	// MaxCriticalCVEs above which the artifact is quarantined. Nil = no limit.
	MaxCriticalCVEs *int32 `json:"maxCriticalCVEs,omitempty"`
	// MaxHighCVEs above which the artifact is quarantined. Nil = no limit.
	MaxHighCVEs *int32 `json:"maxHighCVEs,omitempty"`
	// BlockMalware quarantines on any malware finding. Defaults to true.
	BlockMalware *bool `json:"blockMalware,omitempty"`
	// BlockSecrets quarantines on any leaked-secret finding. Defaults to true.
	BlockSecrets *bool `json:"blockSecrets,omitempty"`
	// BlockUnsafeModel quarantines on a critical model finding — a pickle that
	// imports os.system, an archive that escapes its directory,
	// trust_remote_code. These execute on load, so they are as serious as
	// malware. Defaults to true.
	BlockUnsafeModel *bool `json:"blockUnsafeModel,omitempty"`
	// BlockModelDrift gates on the artifact's declarations disagreeing with
	// its bytes. Off by default: drift is frequently benign, and a quantized
	// re-upload carrying its original config is the common case.
	BlockModelDrift *bool `json:"blockModelDrift,omitempty"`
	// MaxHighModelFindings is how many High model-inspection findings an
	// artifact may carry before it is quarantined. Nil means no limit.
	//
	// BlockUnsafeModel covers Critical only, so until this existed a High
	// finding could be raised, scored and reported with no rule able to act on
	// it. A chat template that reaches the interpreter and a native library
	// inside the weights are both High, and both execute at load.
	//
	// CVEs have had two thresholds from the start; this is the matching one for
	// findings about the model itself.
	MaxHighModelFindings *int32 `json:"maxHighModelFindings,omitempty"`
	// BlockUnexamined quarantines an artifact part of which could not be read.
	//
	// Off by default, because it refuses artifacts that are admitted today and
	// that is the operator's call. Turning it on is the difference between "no
	// findings" meaning "nothing wrong was found" and meaning "nothing was
	// found, and we looked".
	BlockUnexamined *bool `json:"blockUnexamined,omitempty"`
	// RequireSignature demands a verified signature from a trusted publisher.
	RequireSignature bool `json:"requireSignature,omitempty"`
	// RequireProvenance demands a provenance attestation, not merely a
	// signature: who built the artifact and from what, rather than only that
	// somebody signed it.
	RequireProvenance bool `json:"requireProvenance,omitempty"`
	// RequireSBOM demands a generated software bill of materials.
	RequireSBOM bool `json:"requireSBOM,omitempty"`
	// RequireAIBOM demands a description of the model itself. This is what the
	// EU AI Act Annex XII, the CISA/G7 minimum elements and Korea's Framework
	// Act each ask a provider to be able to produce, and it is satisfied by a
	// different scanner from RequireSBOM.
	RequireAIBOM bool `json:"requireAIBOM,omitempty"`
	// AllowedFormats, when set, is the only set of model formats permitted.
	AllowedFormats []string `json:"allowedFormats,omitempty"`
	// BlockedFormats are refused outright.
	BlockedFormats []string `json:"blockedFormats,omitempty"`
}

// Artifact identifies what was scanned.
type Artifact struct {
	URI       string `json:"uri"`
	Digest    string `json:"digest,omitempty"`
	MediaType string `json:"mediaType,omitempty"`
	Format    string `json:"format,omitempty"`
	SizeBytes *int64 `json:"sizeBytes,omitempty"`
}

// ScannerResult is one scanner's outcome.
type ScannerResult struct {
	Scanner    string         `json:"scanner"`
	Status     string         `json:"status"`
	Findings   int32          `json:"findings,omitempty"`
	Severities SeverityCounts `json:"severities,omitempty"`
	// Drift counts the findings reporting that the artifact's own declarations
	// disagree with its bytes, by severity. Kept separate from the severity
	// buckets above because it is gated separately.
	Drift SeverityCounts `json:"drift,omitempty"`
	// Unexamined counts the findings reporting that part of the artifact was
	// not read — a container that would not open, a walk that stopped at its
	// limit, a header that would not parse.
	//
	// Separate for the same reason Drift is: these say nothing about what is in
	// the artifact, only about how much of it was looked at, and a policy that
	// wants to refuse an unread artifact has nothing else to match on. Folded
	// into the severity buckets they are indistinguishable from findings about
	// the bytes.
	Unexamined SeverityCounts `json:"unexamined,omitempty"`
	// Produced records whether the scanner actually generated its artifact.
	// A scanner that ran cleanly but described nothing must not satisfy a
	// requirement to produce a bill of materials, and only this field can tell
	// those two outcomes apart.
	Produced *bool  `json:"produced,omitempty"`
	Message  string `json:"message,omitempty"`
}

// KnownCategory reports the category a scanner name belongs to.
//
// In the operator this came from a catalogue of container images. Here it is a
// plain lookup: the gate has to know that a result named "trivy" is CVE
// evidence, and it must refuse to reach a clean verdict on a scanner it does
// not recognize — an unknown scanner reporting nothing is not the same as a
// known scanner finding nothing.
func KnownCategory(scanner string) (Category, bool) {
	c, ok := scannerCategories[scanner]
	return c, ok
}

var scannerCategories = map[string]Category{
	"clamav":          CategoryMalware,
	"trivy":           CategoryCVE,
	"grype":           CategoryCVE,
	"syft":            CategorySBOM,
	"trufflehog":      CategorySecret,
	"model-inspector": CategoryModel,
	"provenance":      CategoryProvenance,
	"tessera":         CategoryAIBOM,
}

// SeverityCounts is the shared tally type, defined beside Finding so the gate
// and the ingestion parsers count in the same currency.
type SeverityCounts = model.SeverityCounts

// Exception waives a violation that a person has reviewed and accepted.
type Exception struct {
	// FindingIDs waives specific findings; Rules waives whole rule names.
	FindingIDs []string `json:"findingIDs,omitempty"`
	Rules      []string `json:"rules,omitempty"`
	// Reason is why the risk was accepted. An unexplained waiver is
	// indistinguishable from a mistake when someone reads it a year later.
	Reason string `json:"reason"`
	// ScannedDigest binds the acceptance to the exact bytes that were
	// reviewed. Without it, an approval carries over to whatever is published
	// under that name next — the same replay the gate refuses elsewhere.
	ScannedDigest string `json:"scannedDigest,omitempty"`
	// ExpiresAt bounds the waiver. Nil never expires, which is worth avoiding.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// Scanner categories a result can fall into.
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

// Scanner statuses the gate recognizes.
//
// These are exported because the set is not guessable and getting it wrong is
// silent: a status outside this vocabulary is treated as "did not complete",
// which is the safe reading but produces a confusing violation on a scan that
// actually ran. A caller writing "Succeeded" gets told its scanners never
// finished.
const (
	// StatusPassed means the scanner ran and found nothing.
	StatusPassed = "Passed"
	// StatusFailed means the scanner ran and reported findings. It is not an
	// error: a scanner that finds something has done its job.
	StatusFailed = "Failed"
	// StatusSkipped means the scanner was deliberately not run.
	StatusSkipped = "Skipped"
)

// StatusFor returns the status a scanner should report for a finding count.
func StatusFor(findings int) string {
	if findings > 0 {
		return StatusFailed
	}
	return StatusPassed
}
