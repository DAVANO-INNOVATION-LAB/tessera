// Package policy evaluates scan results against an ArtifactScanPolicy to
// produce a verdict and a risk score. It is pure: no cluster access, no I/O,
// so both the scan controller and the admission webhook can call it.
package gate

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Evaluation is the outcome of applying a policy to a set of scan results.
type Evaluation struct {
	// Verdict is Approved, Quarantined, or ReviewRequired.
	Verdict string
	// RiskScore is 0 (clean) to 100 (critical risk).
	RiskScore int32
	// Violations are the policy rules the artifact failed.
	Violations []Violation
	// Waived are violations suppressed by an ArtifactException.
	Waived []Violation
	// CVEs aggregated across all vulnerability
	CVEs SeverityCounts
	// ModelFindings are the model-inspection results: unsafe serialization,
	// archive escapes, code-executing configs. These are what distinguish a
	// model scan from a container scan, so they carry their own weight.
	ModelFindings SeverityCounts
	// AIBOMFindings are what the bill-of-materials pass observed about the
	// model itself, including drift.
	AIBOMFindings SeverityCounts
	// Drift counts findings where the artifact's declarations disagree with
	// its bytes, summed across every scanner that reported any.
	Drift SeverityCounts
	// AIBOMGenerated reports whether a bill of materials describing the model
	// was actually produced. A scanner that ran and described nothing is not
	// the same as one that described a clean model.
	AIBOMGenerated bool
	// MalwareStatus is Clean, Detected, or Unknown.
	MalwareStatus string
	// SecretsStatus is Clean, Detected, or Unknown.
	SecretsStatus string
	// SignatureVerified reports whether provenance verification passed.
	SignatureVerified bool
	// ProvenanceChecked reports whether a provenance scanner actually ran.
	// Unverified and unmeasured are different states: only the former is
	// evidence of risk.
	ProvenanceChecked bool
}

// Violation is a single failed policy rule.
type Violation struct {
	// Rule is the policy field that failed (e.g. maxCriticalCVEs).
	Rule string
	// Message explains the failure in user-facing terms.
	Message string
	// Severity of the violation.
	Severity string
}

func (v Violation) String() string { return fmt.Sprintf("%s: %s", v.Rule, v.Message) }

// Rule names, also used as ArtifactException.spec.rules values.
const (
	RuleMaxCriticalCVEs   = "maxCriticalCVEs"
	RuleMaxHighCVEs       = "maxHighCVEs"
	RuleBlockMalware      = "blockMalware"
	RuleBlockSecrets      = "blockSecrets"
	RuleBlockUnsafeModel  = "blockUnsafeModel"
	RuleRequireSignature  = "requireSignature"
	RuleRequireSBOM       = "requireSBOM"
	RuleRequireAIBOM      = "requireAIBOM"
	RuleBlockModelDrift   = "blockModelDrift"
	RuleRequireProvenance = "requireProvenance"
	RuleAllowedFormats    = "allowedFormats"
	RuleBlockedFormats    = "blockedFormats"
	RuleScanIncomplete    = "scanIncomplete"
)

// Status values for the malware and secrets summaries.
const (
	StatusClean    = "Clean"
	StatusDetected = "Detected"
	StatusUnknown  = "Unknown"
)

// Evaluate applies the policy to scan results for an artifact. A nil policy
// uses conservative built-in defaults: block malware and secrets, allow CVEs.
func Evaluate(
	results []ScannerResult,
	artifact Artifact,
	pol *Rules,
	exceptions []Exception,
	now time.Time,
) Evaluation {
	rules := effectiveRules(pol)
	byCategory, unresolved := groupByCategory(results)

	eval := Evaluation{
		MalwareStatus: statusFor(byCategory[CategoryMalware]),
		SecretsStatus: statusFor(byCategory[CategorySecret]),
		CVEs:          sumSeverities(byCategory[CategoryCVE]),
		ModelFindings: sumSeverities(byCategory[CategoryModel]),
		AIBOMFindings: sumSeverities(byCategory[CategoryAIBOM]),
		Drift:         sumDrift(results),
	}
	eval.AIBOMGenerated = produced(byCategory[CategoryAIBOM])
	eval.ProvenanceChecked = hasCategory(byCategory, CategoryProvenance)
	eval.SignatureVerified = allPassed(byCategory[CategoryProvenance])

	var violations []Violation

	// A result whose scanner cannot be resolved has not been interpreted, so
	// whatever it found has not been weighed. That is an incomplete scan, not
	// a clean one.
	if len(unresolved) > 0 {
		violations = append(violations, Violation{
			Rule:     RuleScanIncomplete,
			Severity: "High",
			Message: fmt.Sprintf(
				"results from unrecognised scanner(s) could not be interpreted and were not counted: %s",
				strings.Join(dedupeStrings(unresolved), ", ")),
		})
	}

	// An incomplete scan is itself a policy failure: absence of findings is
	// not evidence of safety.
	if incomplete := incompleteScanners(results); len(incomplete) > 0 {
		violations = append(violations, Violation{
			Rule:     RuleScanIncomplete,
			Severity: "High",
			Message:  fmt.Sprintf("scanners did not complete: %s", strings.Join(incomplete, ", ")),
		})
	}

	if boolValue(rules.BlockMalware, true) && eval.MalwareStatus == StatusDetected {
		violations = append(violations, Violation{
			Rule:     RuleBlockMalware,
			Severity: "Critical",
			Message:  fmt.Sprintf("malware detected (%d findings)", countFindings(byCategory[CategoryMalware])),
		})
	}

	if boolValue(rules.BlockSecrets, true) && eval.SecretsStatus == StatusDetected {
		violations = append(violations, Violation{
			Rule:     RuleBlockSecrets,
			Severity: "High",
			Message:  fmt.Sprintf("embedded secrets detected (%d findings)", countFindings(byCategory[CategorySecret])),
		})
	}

	// A critical model-inspection finding means the artifact executes code
	// when it is loaded. That is disqualifying on its own, independent of any
	// format allow-list a policy happens to configure.
	if boolValue(rules.BlockUnsafeModel, true) && eval.ModelFindings.Critical > 0 {
		violations = append(violations, Violation{
			Rule:     RuleBlockUnsafeModel,
			Severity: "Critical",
			Message: fmt.Sprintf("%d critical model-inspection finding(s): the artifact executes code on load",
				eval.ModelFindings.Critical),
		})
	}

	if rules.MaxCriticalCVEs != nil && eval.CVEs.Critical > *rules.MaxCriticalCVEs {
		violations = append(violations, Violation{
			Rule:     RuleMaxCriticalCVEs,
			Severity: "Critical",
			Message:  fmt.Sprintf("%d critical CVEs exceeds limit of %d", eval.CVEs.Critical, *rules.MaxCriticalCVEs),
		})
	}

	if rules.MaxHighCVEs != nil && eval.CVEs.High > *rules.MaxHighCVEs {
		violations = append(violations, Violation{
			Rule:     RuleMaxHighCVEs,
			Severity: "High",
			Message:  fmt.Sprintf("%d high CVEs exceeds limit of %d", eval.CVEs.High, *rules.MaxHighCVEs),
		})
	}

	if rules.RequireSignature && !eval.SignatureVerified {
		violations = append(violations, Violation{
			Rule:     RuleRequireSignature,
			Severity: "High",
			Message:  "no verified signature from a trusted publisher",
		})
	}

	if rules.RequireProvenance && !hasCategory(byCategory, CategoryProvenance) {
		violations = append(violations, Violation{
			Rule:     RuleRequireProvenance,
			Severity: "Medium",
			Message:  "provenance attestation is required but was not verified",
		})
	}

	if rules.RequireSBOM && !hasCategory(byCategory, CategorySBOM) {
		violations = append(violations, Violation{
			Rule:     RuleRequireSBOM,
			Severity: "Medium",
			Message:  "SBOM is required but was not generated",
		})
	}

	// An AI bill of materials is a different document from an SBOM and is
	// satisfied by a different scanner, so it needs its own rule. Requiring
	// one and accepting the package SBOM in its place would let a policy
	// claim a model was described when only its surroundings were.
	if rules.RequireAIBOM && !eval.AIBOMGenerated {
		message := "AI bill of materials is required but no scanner produced one"
		if hasCategory(byCategory, CategoryAIBOM) {
			message = "AI bill of materials is required; the scanner ran but described " +
				"nothing, which is not the same as describing a clean model"
		}
		violations = append(violations, Violation{
			Rule:     RuleRequireAIBOM,
			Severity: "Medium",
			Message:  message,
		})
	}

	// Drift at High or above means the artifact's own declarations do not
	// describe its weights. That is not a vulnerability and it is not malware;
	// it is the artifact being something other than what it says it is, which
	// is why it gets a rule of its own and is off by default.
	if boolValue(rules.BlockModelDrift, false) && eval.Drift.Critical+eval.Drift.High > 0 {
		violations = append(violations, Violation{
			Rule:     RuleBlockModelDrift,
			Severity: "High",
			Message: fmt.Sprintf(
				"%d finding(s) where the model's declarations disagree with its weights",
				eval.Drift.Critical+eval.Drift.High),
		})
	}

	if format := strings.ToLower(artifact.Format); format != "" {
		if len(rules.AllowedFormats) > 0 && !containsFold(rules.AllowedFormats, format) {
			violations = append(violations, Violation{
				Rule:     RuleAllowedFormats,
				Severity: "High",
				Message:  fmt.Sprintf("model format %q is not in the allowed list %v", artifact.Format, rules.AllowedFormats),
			})
		}
		if containsFold(rules.BlockedFormats, format) {
			violations = append(violations, Violation{
				Rule:     RuleBlockedFormats,
				Severity: "Critical",
				Message:  fmt.Sprintf("model format %q is blocked by policy", artifact.Format),
			})
		}
	}

	eval.Violations, eval.Waived = applyExceptions(violations, exceptions, now)
	eval.RiskScore = riskScore(eval)
	eval.Verdict = verdict(eval)
	return eval
}

// applyExceptions splits violations into enforced and waived.
func applyExceptions(violations []Violation, exceptions []Exception, now time.Time) (enforced, waived []Violation) {
	waivedRules := map[string]bool{}
	for _, ex := range exceptions {
		if ex.ExpiresAt != nil && now.After(*ex.ExpiresAt) {
			continue
		}
		for _, rule := range ex.Rules {
			waivedRules[rule] = true
		}
	}
	for _, v := range violations {
		if waivedRules[v.Rule] {
			waived = append(waived, v)
			continue
		}
		enforced = append(enforced, v)
	}
	return enforced, waived
}

// riskScore maps findings onto 0-100. Malware saturates the score because a
// single confirmed detection is disqualifying regardless of anything else.
func riskScore(eval Evaluation) int32 {
	if eval.MalwareStatus == StatusDetected {
		return 100
	}

	score := 0
	score += int(eval.CVEs.Critical) * 20
	score += int(eval.CVEs.High) * 8
	score += int(eval.CVEs.Medium) * 2
	score += int(eval.CVEs.Low)

	// Model-level findings are weighted above CVEs of the same severity: a
	// pickle that imports os.system is already-working code execution, not a
	// vulnerability that something else still has to reach.
	score += int(eval.ModelFindings.Critical) * 35
	score += int(eval.ModelFindings.High) * 12
	score += int(eval.ModelFindings.Medium) * 3

	if eval.SecretsStatus == StatusDetected {
		score += 40
	}
	// Only penalize provenance when it was actually checked and did not
	// verify. If no provenance scanner ran, that dimension is unmeasured, and
	// the requireSignature/requireProvenance rules are what force the issue.
	if eval.ProvenanceChecked && !eval.SignatureVerified {
		score += 10
	}
	for _, v := range eval.Violations {
		switch v.Severity {
		case "Critical":
			score += 25
		case "High":
			score += 10
		default:
			score += 3
		}
	}

	if score > 100 {
		score = 100
	}
	return int32(score)
}

func verdict(eval Evaluation) string {
	if len(eval.Violations) == 0 {
		return VerdictApproved
	}
	for _, v := range eval.Violations {
		if v.Severity == "Critical" {
			return VerdictQuarantined
		}
	}
	return VerdictReviewRequired
}

func effectiveRules(pol *Rules) Rules {
	if pol == nil {
		return Rules{}
	}
	return *pol
}

// groupByCategory buckets results by what they measure, and reports any
// scanner it could not resolve.
//
// Dropping an unresolvable result silently was the most dangerous line in this
// package: a result carrying twelve critical findings under a name not in the
// catalog — a renamed scanner, a newer operator, a typo in a policy — vanished
// from every category, so blockMalware and blockSecrets saw nothing, no
// violation fired, and the verdict came back Approved at risk 0. Findings
// became a clean bill of health by way of a name lookup.
func groupByCategory(results []ScannerResult) (map[Category][]ScannerResult, []string) {
	grouped := map[Category][]ScannerResult{}
	var unresolved []string
	for _, r := range results {
		cat, known := KnownCategory(r.Scanner)
		if !known {
			unresolved = append(unresolved, r.Scanner)
			continue
		}
		grouped[cat] = append(grouped[cat], r)
	}
	sort.Strings(unresolved)
	return grouped, unresolved
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func statusFor(results []ScannerResult) string {
	if len(results) == 0 {
		return StatusUnknown
	}
	sawCompleted := false
	for _, r := range results {
		if r.Findings > 0 {
			return StatusDetected
		}
		if r.Status == "Passed" || r.Status == "Failed" {
			sawCompleted = true
		}
	}
	if !sawCompleted {
		return StatusUnknown
	}
	return StatusClean
}

func sumSeverities(results []ScannerResult) SeverityCounts {
	// Multiple CVE scanners overlap heavily, so take the per-severity maximum
	// rather than the sum. Summing would double-count the same CVE found by
	// both Trivy and Grype and inflate the risk score.
	var total SeverityCounts
	for _, r := range results {
		total.Critical = max32(total.Critical, r.Severities.Critical)
		total.High = max32(total.High, r.Severities.High)
		total.Medium = max32(total.Medium, r.Severities.Medium)
		total.Low = max32(total.Low, r.Severities.Low)
		total.Unknown = max32(total.Unknown, r.Severities.Unknown)
	}
	return total
}

func incompleteScanners(results []ScannerResult) []string {
	var incomplete []string
	for _, r := range results {
		switch r.Status {
		case "Passed", "Failed", "Skipped":
			continue
		default:
			incomplete = append(incomplete, r.Scanner)
		}
	}
	sort.Strings(incomplete)
	return incomplete
}

func allPassed(results []ScannerResult) bool {
	if len(results) == 0 {
		return false
	}
	for _, r := range results {
		if r.Status != "Passed" || r.Findings > 0 {
			return false
		}
	}
	return true
}

// sumDrift totals drift across every scanner rather than only the bill-of-
// materials one. Drift is a property of the artifact, and if another scanner
// ever learns to spot it the gate should count that too.
func sumDrift(results []ScannerResult) SeverityCounts {
	var total SeverityCounts
	for _, r := range results {
		total.Critical += r.Drift.Critical
		total.High += r.Drift.High
		total.Medium += r.Drift.Medium
		total.Low += r.Drift.Low
		total.Unknown += r.Drift.Unknown
	}
	return total
}

// produced reports whether at least one scanner in the group emitted the
// document it exists to emit. A scanner that does not answer the question at
// all (Produced nil) cannot satisfy a rule that asks for a document.
func produced(results []ScannerResult) bool {
	for _, r := range results {
		if r.Produced != nil && *r.Produced {
			return true
		}
	}
	return false
}

func hasCategory(grouped map[Category][]ScannerResult, cat Category) bool {
	for _, r := range grouped[cat] {
		if r.Status == "Passed" || r.Status == "Failed" {
			return true
		}
	}
	return false
}

func countFindings(results []ScannerResult) int32 {
	var total int32
	for _, r := range results {
		total += r.Findings
	}
	return total
}

func containsFold(list []string, value string) bool {
	for _, item := range list {
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

func boolValue(p *bool, fallback bool) bool {
	if p == nil {
		return fallback
	}
	return *p
}

func max32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}
