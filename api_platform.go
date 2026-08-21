package tessera

import (
	"context"
	"fmt"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/compliance"
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/gate"
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/ingest"
)

// The platform surface: judging an artifact, not merely describing it.
//
// Analyze and Inspect answer what a model is and what is dangerous about it.
// These three answer the questions that follow — does it pass, what does it
// mean for a framework, and how do other scanners' findings join the same
// picture. They were all built inside a Kubernetes operator, where each needed
// an API server to reach. None of them actually did: a threshold comparison, a
// control catalogue and an output parser are computation, not orchestration.
// Moving them here means the same decision runs in a cluster, in CI, on a
// laptop, or inside an air-gapped enclave, and gives exactly one implementation
// of it rather than two that drift.

type (
	// GateRules are the thresholds and requirements a scan is judged against.
	GateRules = gate.Rules
	// GateResult is the verdict, its violations, and what was waived.
	GateResult = gate.Evaluation
	// GateViolation is one rule that failed.
	GateViolation = gate.Violation
	// GateException waives a violation a person reviewed and accepted.
	GateException = gate.Exception
	// GateArtifact identifies what was scanned.
	GateArtifact = gate.Artifact
	// ScannerResult is one scanner's outcome, as the gate reads it.
	ScannerResult = gate.ScannerResult
	// SeverityCounts is a tally of findings by severity.
	SeverityCounts = gate.SeverityCounts

	// ComplianceCatalog is a control framework.
	ComplianceCatalog = compliance.Catalog
	// ComplianceAssessment is a model version assessed against one.
	ComplianceAssessment = compliance.Assessment
	// ComplianceEvidence is what a scan established.
	ComplianceEvidence = compliance.Evidence
	// ComplianceAttestation is a human claim closing a control no scan can.
	ComplianceAttestation = compliance.Attestation
	// ComplianceScope bounds an assessment.
	ComplianceScope = compliance.Scope
	// ATLASTechnique is one MITRE ATLAS technique and this tool's coverage of it.
	ATLASTechnique = compliance.Technique

	// IngestedResults are findings read from another scanner's output.
	IngestedResults = ingest.Parsed
)

// Gate verdicts.
const (
	VerdictApproved       = gate.VerdictApproved
	VerdictQuarantined    = gate.VerdictQuarantined
	VerdictReviewRequired = gate.VerdictReviewRequired
)

// Gate judges a set of scanner results against policy rules and returns a
// verdict with the reasons behind it.
//
// An unrecognized scanner cannot produce a clean verdict. A result whose name
// the gate does not know is reported as unresolved rather than ignored, because
// a scanner that reported nothing and a scanner nobody could interpret look
// identical from the outside and mean opposite things.
func Gate(results []ScannerResult, artifact GateArtifact, rules *GateRules, exceptions []GateException, now time.Time) GateResult {
	return gate.Evaluate(results, artifact, rules, exceptions, now)
}

// Compliance assesses evidence against a control framework.
//
// A control the scan cannot observe never comes back satisfied on scan evidence
// alone; it needs an attestation naming a person, with an expiry. That is the
// difference between producing evidence and claiming compliance, and this
// function is deliberately unable to do the second.
func Compliance(catalog *ComplianceCatalog, ev ComplianceEvidence, attestations []ComplianceAttestation, scope ComplianceScope, now time.Time) ComplianceAssessment {
	return compliance.Evaluate(catalog, ev, attestations, scope, now)
}

// NISTAIRMF is the NIST AI Risk Management Framework control catalogue.
func NISTAIRMF() *ComplianceCatalog { return compliance.NISTAIRMF() }

// NIST80053 is the NIST SP 800-53 Rev. 5 control catalogue.
func NIST80053() *ComplianceCatalog { return compliance.NIST80053() }

// ATLASTechniques lists the MITRE ATLAS techniques this tool maps, including
// the ones it explicitly does not detect. A coverage table that listed only
// successes would misrepresent what a clean result means.
func ATLASTechniques() []ATLASTechnique { return compliance.ATLASTechniques() }

// Ingest reads another scanner's output file and normalizes it into findings.
// Recognized formats: clamav, trivy-json, grype-json, syft-spdx,
// trufflehog-json, tessera.
func Ingest(ctx context.Context, format, path string) (*IngestedResults, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if format == "" || path == "" {
		return nil, fmt.Errorf("tessera: ingest needs both a format and a path")
	}
	return ingest.Parse(format, path)
}

// Scanner statuses the gate recognizes. A status outside this set is read as
// "did not complete", which is the safe default but is not what a caller
// inventing its own vocabulary intends.
const (
	ScannerPassed  = gate.StatusPassed
	ScannerFailed  = gate.StatusFailed
	ScannerSkipped = gate.StatusSkipped
)

// ScannerStatusFor returns the status to report for a finding count.
func ScannerStatusFor(findings int) string { return gate.StatusFor(findings) }

// Rule names a gate violation can carry. They are exported because a caller
// writing an exception has to name the rule it waives, and a waiver naming a
// rule that does not exist waives nothing while looking like it does.
const (
	RuleMaxCriticalCVEs   = gate.RuleMaxCriticalCVEs
	RuleMaxHighCVEs       = gate.RuleMaxHighCVEs
	RuleBlockMalware      = gate.RuleBlockMalware
	RuleBlockSecrets      = gate.RuleBlockSecrets
	RuleBlockUnsafeModel  = gate.RuleBlockUnsafeModel
	RuleRequireSignature  = gate.RuleRequireSignature
	RuleRequireSBOM       = gate.RuleRequireSBOM
	RuleRequireAIBOM      = gate.RuleRequireAIBOM
	RuleBlockModelDrift   = gate.RuleBlockModelDrift
	RuleRequireProvenance = gate.RuleRequireProvenance
	RuleAllowedFormats    = gate.RuleAllowedFormats
	RuleBlockedFormats    = gate.RuleBlockedFormats
	RuleScanIncomplete    = gate.RuleScanIncomplete
)

// Category outcomes reported alongside a verdict. Unknown is distinct from
// Clean on purpose: a category nothing examined and a category examined and
// found clean are opposite facts that would otherwise look identical.
const (
	StatusClean    = gate.StatusClean
	StatusDetected = gate.StatusDetected
	StatusUnknown  = gate.StatusUnknown
)

// Scanner output formats Ingest can read. Exported because a caller has to name
// one, and an unrecognized format is an error rather than a guess — reading
// Trivy's JSON as Grype's would produce a confidently wrong finding list.
const (
	FormatTessera    = ingest.FormatTessera
	FormatClamAV     = ingest.FormatClamAV
	FormatTrivyJSON  = ingest.FormatTrivyJSON
	FormatGrypeJSON  = ingest.FormatGrypeJSON
	FormatSyftSPDX   = ingest.FormatSyftSPDX
	FormatTrufflehog = ingest.FormatTrufflehog
)

// SeverityCountsAreOneType is a compile-time assertion that the gate and the
// ingestion parsers count in the same currency. They were two structurally
// identical types once, which forced every consumer to write a conversion that
// could only be the identity function; if they ever diverge again this stops
// building rather than reappearing as a confusing type error downstream.
var _ = func() struct{} {
	var g GateResult
	var p IngestedResults
	g.CVEs = p.Severities
	return struct{}{}
}()
