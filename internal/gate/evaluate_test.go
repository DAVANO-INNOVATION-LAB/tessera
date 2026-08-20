package gate

import (
	"strings"
	"testing"
	"time"
)

func result(scanner, status string, counts SeverityCounts) ScannerResult {
	return ScannerResult{
		Scanner:    scanner,
		Status:     status,
		Findings:   counts.Total(),
		Severities: counts,
	}
}

func TestCleanScanIsApproved(t *testing.T) {
	results := []ScannerResult{
		result("clamav", "Passed", SeverityCounts{}),
		result("trivy", "Passed", SeverityCounts{}),
		result("trufflehog", "Passed", SeverityCounts{}),
		result("syft", "Passed", SeverityCounts{}),
	}

	eval := Evaluate(results, Artifact{}, nil, nil, time.Now())

	if eval.Verdict != VerdictApproved {
		t.Fatalf("verdict = %q, want Approved (violations: %v)", eval.Verdict, eval.Violations)
	}
	if eval.RiskScore != 0 {
		t.Errorf("risk score = %d, want 0", eval.RiskScore)
	}
	if eval.MalwareStatus != StatusClean {
		t.Errorf("malware = %q, want Clean", eval.MalwareStatus)
	}
}

func TestMalwareQuarantinesAndSaturatesRisk(t *testing.T) {
	results := []ScannerResult{
		result("clamav", "Failed", SeverityCounts{Critical: 1}),
		result("trivy", "Passed", SeverityCounts{}),
	}

	eval := Evaluate(results, Artifact{}, nil, nil, time.Now())

	if eval.Verdict != VerdictQuarantined {
		t.Errorf("verdict = %q, want Quarantined", eval.Verdict)
	}
	if eval.RiskScore != 100 {
		t.Errorf("risk score = %d, want 100 for confirmed malware", eval.RiskScore)
	}
}

// An incomplete scan must never read as a pass: absence of findings from a
// scanner that never ran is not evidence of safety.
func TestPendingScannerBlocksApproval(t *testing.T) {
	results := []ScannerResult{
		result("clamav", "Passed", SeverityCounts{}),
		result("trivy", "Running", SeverityCounts{}),
	}

	eval := Evaluate(results, Artifact{}, nil, nil, time.Now())

	if eval.Verdict == VerdictApproved {
		t.Fatal("approved an artifact with an incomplete scan")
	}
	if !hasRule(eval.Violations, RuleScanIncomplete) {
		t.Errorf("violations = %v, want a %s violation", eval.Violations, RuleScanIncomplete)
	}
}

func TestCVEThresholds(t *testing.T) {
	limit := int32(0)
	pol := &Rules{MaxCriticalCVEs: &limit}
	results := []ScannerResult{
		result("trivy", "Failed", SeverityCounts{Critical: 3, High: 5}),
	}

	eval := Evaluate(results, Artifact{}, pol, nil, time.Now())

	if !hasRule(eval.Violations, RuleMaxCriticalCVEs) {
		t.Errorf("violations = %v, want %s", eval.Violations, RuleMaxCriticalCVEs)
	}
	if eval.Verdict != VerdictQuarantined {
		t.Errorf("verdict = %q, want Quarantined for a critical violation", eval.Verdict)
	}
}

// Trivy and Grype find overlapping CVE sets. Summing them would double-count
// the same vulnerability and inflate the risk score, so the evaluator takes
// the per-severity maximum instead.
func TestOverlappingCVEScannersAreNotDoubleCounted(t *testing.T) {
	results := []ScannerResult{
		result("trivy", "Failed", SeverityCounts{Critical: 2, High: 4}),
		result("grype", "Failed", SeverityCounts{Critical: 2, High: 6}),
	}

	eval := Evaluate(results, Artifact{}, nil, nil, time.Now())

	if eval.CVEs.Critical != 2 {
		t.Errorf("critical CVEs = %d, want 2 (max, not sum)", eval.CVEs.Critical)
	}
	if eval.CVEs.High != 6 {
		t.Errorf("high CVEs = %d, want 6 (max, not sum)", eval.CVEs.High)
	}
}

func TestBlockedFormatQuarantines(t *testing.T) {
	pol := &Rules{BlockedFormats: []string{"pickle"}}
	results := []ScannerResult{
		result("clamav", "Passed", SeverityCounts{}),
	}

	eval := Evaluate(results, Artifact{Format: "Pickle"}, pol, nil, time.Now())

	if !hasRule(eval.Violations, RuleBlockedFormats) {
		t.Errorf("violations = %v, want %s (format match must be case-insensitive)",
			eval.Violations, RuleBlockedFormats)
	}
}

func TestAllowedFormatsRejectsUnlisted(t *testing.T) {
	pol := &Rules{AllowedFormats: []string{"safetensors", "onnx"}}
	results := []ScannerResult{
		result("clamav", "Passed", SeverityCounts{}),
	}

	eval := Evaluate(results, Artifact{Format: "pytorch"}, pol, nil, time.Now())

	if !hasRule(eval.Violations, RuleAllowedFormats) {
		t.Errorf("violations = %v, want %s", eval.Violations, RuleAllowedFormats)
	}
}

func TestUnexpiredExceptionWaivesViolation(t *testing.T) {
	limit := int32(0)
	pol := &Rules{MaxCriticalCVEs: &limit}
	results := []ScannerResult{
		result("trivy", "Failed", SeverityCounts{Critical: 1}),
	}
	future := time.Now().Add(24 * time.Hour)
	exceptions := []Exception{{
		Rules:     []string{RuleMaxCriticalCVEs},
		Reason:    "accepted risk pending upstream fix",
		ExpiresAt: &future,
	}}

	eval := Evaluate(results, Artifact{}, pol, exceptions, time.Now())

	if hasRule(eval.Violations, RuleMaxCriticalCVEs) {
		t.Errorf("violation was not waived: %v", eval.Violations)
	}
	if !hasRule(eval.Waived, RuleMaxCriticalCVEs) {
		t.Errorf("waived = %v, want the CVE violation recorded as waived", eval.Waived)
	}
	if eval.Verdict != VerdictApproved {
		t.Errorf("verdict = %q, want Approved once the only violation is waived", eval.Verdict)
	}
}

// An expired exception must stop waiving, or exceptions become permanent.
func TestExpiredExceptionDoesNotWaive(t *testing.T) {
	limit := int32(0)
	pol := &Rules{MaxCriticalCVEs: &limit}
	results := []ScannerResult{
		result("trivy", "Failed", SeverityCounts{Critical: 1}),
	}
	past := time.Now().Add(-24 * time.Hour)
	exceptions := []Exception{{
		Rules:     []string{RuleMaxCriticalCVEs},
		Reason:    "expired waiver",
		ExpiresAt: &past,
	}}

	eval := Evaluate(results, Artifact{}, pol, exceptions, time.Now())

	if !hasRule(eval.Violations, RuleMaxCriticalCVEs) {
		t.Errorf("expired exception still waived the violation: %v", eval.Violations)
	}
}

func TestRequireSignatureFailsWithoutProvenance(t *testing.T) {
	pol := &Rules{RequireSignature: true}
	results := []ScannerResult{
		result("clamav", "Passed", SeverityCounts{}),
	}

	eval := Evaluate(results, Artifact{}, pol, nil, time.Now())

	if !hasRule(eval.Violations, RuleRequireSignature) {
		t.Errorf("violations = %v, want %s", eval.Violations, RuleRequireSignature)
	}
	if eval.SignatureVerified {
		t.Error("signature reported verified with no provenance scanner result")
	}
}

func TestVerifiedSecretsBlock(t *testing.T) {
	results := []ScannerResult{
		result("trufflehog", "Failed", SeverityCounts{Critical: 1}),
		result("clamav", "Passed", SeverityCounts{}),
	}

	eval := Evaluate(results, Artifact{}, nil, nil, time.Now())

	if eval.SecretsStatus != StatusDetected {
		t.Errorf("secrets = %q, want Detected", eval.SecretsStatus)
	}
	if !hasRule(eval.Violations, RuleBlockSecrets) {
		t.Errorf("violations = %v, want %s blocked by default", eval.Violations, RuleBlockSecrets)
	}
}

func TestRiskScoreIsBounded(t *testing.T) {
	results := []ScannerResult{
		result("trivy", "Failed", SeverityCounts{Critical: 50, High: 200}),
		result("trufflehog", "Failed", SeverityCounts{Critical: 10}),
	}

	eval := Evaluate(results, Artifact{}, nil, nil, time.Now())

	if eval.RiskScore > 100 {
		t.Errorf("risk score = %d, want it clamped to 100", eval.RiskScore)
	}
}

func hasRule(violations []Violation, rule string) bool {
	for _, v := range violations {
		if v.Rule == rule {
			return true
		}
	}
	return false
}

func TestCriticalModelFindingQuarantinesByDefault(t *testing.T) {
	results := []ScannerResult{
		result("model-inspector", "Failed", SeverityCounts{Critical: 1}),
		result("clamav", "Passed", SeverityCounts{}),
	}

	eval := Evaluate(results, Artifact{}, nil, nil, time.Now())

	if !hasRule(eval.Violations, RuleBlockUnsafeModel) {
		t.Errorf("violations = %v, want %s enforced by default", eval.Violations, RuleBlockUnsafeModel)
	}
	if eval.Verdict != VerdictQuarantined {
		t.Errorf("verdict = %q, want Quarantined", eval.Verdict)
	}
}

// Model findings outweigh a CVE of the same severity: unsafe deserialization
// is already-working code execution, not a bug something else has to reach.
func TestModelFindingsOutweighEquivalentCVEs(t *testing.T) {
	modelRisk := Evaluate(
		[]ScannerResult{
			result("model-inspector", "Failed", SeverityCounts{Critical: 1}),
		},
		Artifact{}, nil, nil, time.Now()).RiskScore

	cveRisk := Evaluate(
		[]ScannerResult{
			result("trivy", "Failed", SeverityCounts{Critical: 1}),
		},
		Artifact{}, nil, nil, time.Now()).RiskScore

	if modelRisk <= cveRisk {
		t.Errorf("model risk %d does not exceed CVE risk %d for the same severity", modelRisk, cveRisk)
	}
}

func TestBlockUnsafeModelCanBeDisabled(t *testing.T) {
	disabled := false
	pol := &Rules{BlockUnsafeModel: &disabled}
	results := []ScannerResult{
		result("model-inspector", "Failed", SeverityCounts{Critical: 1}),
	}

	eval := Evaluate(results, Artifact{}, pol, nil, time.Now())

	if hasRule(eval.Violations, RuleBlockUnsafeModel) {
		t.Errorf("rule still enforced after being disabled: %v", eval.Violations)
	}
}

// A result whose scanner name is not in the catalog used to be dropped on the
// floor: it disappeared from every category, so no rule saw it, no violation
// fired, and twelve critical findings came back Approved at risk 0. A renamed
// scanner between operator versions was enough to turn findings into a clean
// bill of health.
func TestUnrecognisedScannerCannotProduceACleanVerdict(t *testing.T) {
	eval := Evaluate([]ScannerResult{{
		Scanner:    "clamav-v2", // not in the catalog
		Status:     "Failed",
		Findings:   12,
		Severities: SeverityCounts{Critical: 12},
	}}, Artifact{URI: "s3://models/x"}, nil, nil, time.Now())

	if eval.Verdict == VerdictApproved {
		t.Error("twelve critical findings from an unrecognised scanner produced an Approved verdict")
	}
	if len(eval.Violations) == 0 {
		t.Fatal("no violation was raised for results that were never interpreted")
	}
	var named bool
	for _, v := range eval.Violations {
		if v.Rule == RuleScanIncomplete && strings.Contains(v.Message, "clamav-v2") {
			named = true
		}
	}
	if !named {
		t.Errorf("the violation does not name the scanner that could not be interpreted: %+v", eval.Violations)
	}

	// A known scanner must still behave exactly as before.
	clean := Evaluate([]ScannerResult{{
		Scanner: "clamav", Status: "Passed",
	}}, Artifact{URI: "s3://models/x"}, nil, nil, time.Now())
	if clean.Verdict != VerdictApproved {
		t.Errorf("a clean result from a known scanner no longer passes: %s — %+v", clean.Verdict, clean.Violations)
	}
}

func boolPtr(b bool) *bool { return &b }

func aibomResult(produced bool, drift SeverityCounts) ScannerResult {
	return ScannerResult{
		Scanner:    "tessera",
		Status:     "Passed",
		Findings:   drift.Total(),
		Severities: drift,
		Drift:      drift,
		Produced:   boolPtr(produced),
	}
}

// The failure this rule exists to prevent: a scanner that ran, described
// nothing, and reported no findings looks exactly like one that described a
// clean model. If requireAIBOM is satisfied by the scanner merely having run,
// the gate reads as enforced and enforces nothing.
func TestRequireAIBOMIsNotSatisfiedByAScannerThatDescribedNothing(t *testing.T) {
	pol := &Rules{RequireAIBOM: true}
	results := []ScannerResult{aibomResult(false, SeverityCounts{})}

	eval := Evaluate(results, Artifact{}, pol, nil, time.Now())
	if !hasRule(eval.Violations, RuleRequireAIBOM) {
		t.Fatalf("a scanner that produced no bill of materials must fail requireAIBOM; got %v",
			eval.Violations)
	}
}

func TestRequireAIBOMPassesWhenOneWasProduced(t *testing.T) {
	pol := &Rules{RequireAIBOM: true}
	results := []ScannerResult{aibomResult(true, SeverityCounts{})}

	eval := Evaluate(results, Artifact{}, pol, nil, time.Now())
	if hasRule(eval.Violations, RuleRequireAIBOM) {
		t.Fatalf("a produced bill of materials must satisfy the rule; got %v", eval.Violations)
	}
	if !eval.AIBOMGenerated {
		t.Error("the evaluation should record that one was generated")
	}
}

// A package SBOM is a different document produced by a different scanner.
// Accepting it for requireAIBOM would let a policy claim the model was
// described when only its surroundings were.
func TestPackageSBOMDoesNotSatisfyRequireAIBOM(t *testing.T) {
	pol := &Rules{RequireAIBOM: true}
	results := []ScannerResult{{Scanner: "syft", Status: "Passed"}}

	eval := Evaluate(results, Artifact{}, pol, nil, time.Now())
	if !hasRule(eval.Violations, RuleRequireAIBOM) {
		t.Fatal("syft's package SBOM must not satisfy a rule asking for a model description")
	}
}

// Drift is off by default: a quantized re-upload carrying its original config
// is the common case, and a scanner that quarantines the common case gets
// switched off. It must still be visible in the evaluation.
func TestDriftIsSurfacedButNotGatedByDefault(t *testing.T) {
	drift := SeverityCounts{High: 2}
	results := []ScannerResult{aibomResult(true, drift)}

	eval := Evaluate(results, Artifact{}, nil, nil, time.Now())
	if hasRule(eval.Violations, RuleBlockModelDrift) {
		t.Fatal("drift must not quarantine unless a policy asks for it")
	}
	if eval.Drift.High != 2 {
		t.Fatalf("drift must still be counted, got %+v", eval.Drift)
	}
}

func TestDriftGateFiresWhenEnabled(t *testing.T) {
	pol := &Rules{BlockModelDrift: boolPtr(true)}
	results := []ScannerResult{
		aibomResult(true, SeverityCounts{High: 1}),
	}

	eval := Evaluate(results, Artifact{}, pol, nil, time.Now())
	if !hasRule(eval.Violations, RuleBlockModelDrift) {
		t.Fatalf("an enabled drift gate must fire on a high-severity disagreement; got %v",
			eval.Violations)
	}
}

// Low and medium drift is the noise floor — a licence string that does not
// resolve, a tokenizer version that moved. Quarantining on it would train
// operators to waive the rule, which is worse than not having it.
func TestLowSeverityDriftDoesNotQuarantine(t *testing.T) {
	pol := &Rules{BlockModelDrift: boolPtr(true)}
	results := []ScannerResult{
		aibomResult(true, SeverityCounts{Medium: 3, Low: 5}),
	}

	eval := Evaluate(results, Artifact{}, pol, nil, time.Now())
	if hasRule(eval.Violations, RuleBlockModelDrift) {
		t.Fatal("only high and critical drift should quarantine")
	}
}
