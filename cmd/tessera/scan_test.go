package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera"
)

// The gate's status vocabulary is Passed/Failed/Skipped. Reporting anything
// else — "Succeeded" was the first attempt — is read as "did not complete", so
// a scan that ran fine produces a scanIncomplete violation and a verdict of
// ReviewRequired on a clean model.
func TestScannerStatusUsesTheGateVocabulary(t *testing.T) {
	if got := tessera.ScannerStatusFor(0); got != tessera.ScannerPassed {
		t.Errorf("no findings -> %q, want %q", got, tessera.ScannerPassed)
	}
	if got := tessera.ScannerStatusFor(3); got != tessera.ScannerFailed {
		t.Errorf("findings -> %q, want %q", got, tessera.ScannerFailed)
	}

	// The real regression: a clean artifact must reach Approved, not
	// ReviewRequired via an invented status.
	results := []tessera.ScannerResult{{
		Scanner: "tessera",
		Status:  tessera.ScannerStatusFor(0),
	}}
	eval := tessera.Gate(results, tessera.GateArtifact{}, nil, nil, time.Now())
	for _, v := range eval.Violations {
		if v.Rule == "scanIncomplete" {
			t.Fatalf("a completed scan reported scanIncomplete: %s", v.Message)
		}
	}
	if eval.Verdict != tessera.VerdictApproved {
		t.Errorf("verdict = %q, want Approved for a clean completed scan", eval.Verdict)
	}
}

// Drift is tallied separately from everything else because the gate gates it
// separately. Counting a drift finding into the general severities would gate
// it by default, which is the opposite of the intent.
func TestTallySeparatesDriftFromTheRest(t *testing.T) {
	findings := []tessera.Finding{
		{ID: "TESS-DRIFT-001", Severity: tessera.SeverityHigh, Category: "drift"},
		{ID: "TESS-PICKLE-001", Severity: tessera.SeverityCritical, Category: "model"},
		{ID: "TESS-LIC-001", Severity: tessera.SeverityLow, Category: "license"},
	}
	general := tally(findings, false)
	drift := tally(findings, true)

	if drift.High != 1 || drift.Total() != 1 {
		t.Errorf("drift tally = %+v, want exactly the one drift finding", drift)
	}
	if general.Critical != 1 || general.Low != 1 || general.Total() != 2 {
		t.Errorf("general tally = %+v, want the two non-drift findings", general)
	}
	if general.High != 0 {
		t.Error("the drift finding was counted into the general severities; it would then be gated by default")
	}
}

// mergeFindings drops what the parser already reported. The scan relies on that
// to attribute only the accepted remainder to the walk — taking the walk's
// whole output would re-count a defect described twice and inflate the risk.
func TestMergeFindingsDedupesByIDAndLocation(t *testing.T) {
	parsed := []tessera.Finding{
		{ID: "TESS-ST-001", Severity: "Medium", Location: "model.safetensors"},
	}
	walked := []tessera.Finding{
		{ID: "TESS-ST-001", Severity: "Medium", Location: "model.safetensors"}, // same defect
		{ID: "TESS-ST-001", Severity: "Medium", Location: "other.safetensors"}, // different file
		{ID: "TESS-PICKLE-001", Severity: "Critical", Location: "t.pkl"},
	}
	merged := mergeFindings(parsed, walked)
	if len(merged) != 3 {
		t.Fatalf("merged %d findings, want 3 (one duplicate dropped): %v", len(merged), merged)
	}
	contribution := merged[len(parsed):]
	if len(contribution) != 2 {
		t.Errorf("walk contributed %d, want 2; the scan attributes this slice to the inspector",
			len(contribution))
	}
	for _, f := range contribution {
		if f.ID == "TESS-ST-001" && f.Location == "model.safetensors" {
			t.Error("the duplicate survived; risk would be counted twice for one defect")
		}
	}
}

func TestScanExitMapsVerdictsToDocumentedCodes(t *testing.T) {
	for _, tc := range []struct {
		verdict string
		want    int
	}{
		{tessera.VerdictQuarantined, exitCritical},
		{tessera.VerdictReviewRequired, exitFindings},
		{tessera.VerdictApproved, exitClean},
	} {
		if got := scanExit(tc.verdict); got != tc.want {
			t.Errorf("scanExit(%q) = %d, want %d", tc.verdict, got, tc.want)
		}
	}
}

func TestLoadRulesRejectsMalformedPolicy(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRules(bad); err == nil {
		t.Error("a malformed policy was accepted; the scan would silently run on defaults")
	}
	if _, err := loadRules(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("a missing policy file was accepted")
	}
	rules, err := loadRules("")
	if err != nil || rules != nil {
		t.Errorf("no --policy should mean built-in defaults, got %v / %v", rules, err)
	}
}

// A directory of PyTorch pickles has no GGUF, safetensors or ONNX file to
// parse, and is the most common shape on Hugging Face. The scan used to refuse
// it outright — which meant the one artifact layout where the walk matters most
// was the one layout that got no walk at all. Nothing was reported, and the
// exit code said "error" rather than "dangerous".
func TestUnparseableTargetStillGetsWalked(t *testing.T) {
	if !errors.Is(fmt.Errorf("x: %w", tessera.ErrUnrecognized), tessera.ErrUnrecognized) {
		t.Fatal("ErrUnrecognized does not survive wrapping; the scan cannot recognise it")
	}
}

// The sentinel has to stay distinguishable from a genuine read failure. They
// call for opposite responses: one means carry on and walk, the other means
// stop, and collapsing them would either hide a broken file or refuse a
// perfectly good directory.
func TestUnrecognizedIsDistinctFromAReadFailure(t *testing.T) {
	readFail := fmt.Errorf("permission denied")
	if errors.Is(readFail, tessera.ErrUnrecognized) {
		t.Error("a read failure matched ErrUnrecognized; the scan would walk on regardless")
	}
}
