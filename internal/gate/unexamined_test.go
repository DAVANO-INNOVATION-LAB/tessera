package gate

import (
	"testing"
	"time"
)

func unread(n int32) []ScannerResult {
	return []ScannerResult{{
		Scanner: "model-inspector", Status: "Passed",
		Findings:   n,
		Unexamined: SeverityCounts{Medium: n},
	}}
}

// The gap this closes: an artifact the scanner could not read produced a
// verdict identical to one it read and liked, under every rule the policy
// language had.
func TestAnUnexaminedArtifactCanBeRefused(t *testing.T) {
	on, off := true, false
	art := Artifact{URI: "pvc://claim/m"}

	// Off by default, so an existing cluster admits exactly what it did before.
	loose := Evaluate(unread(1), art, &Rules{}, nil, time.Now())
	if loose.Verdict != VerdictApproved {
		t.Fatalf("with the rule unset the verdict changed to %q", loose.Verdict)
	}

	// Explicitly off is the same.
	explicit := Evaluate(unread(1), art, &Rules{BlockUnexamined: &off}, nil, time.Now())
	if explicit.Verdict != VerdictApproved {
		t.Errorf("explicitly off still refused: %q", explicit.Verdict)
	}

	// On, and it refuses.
	strict := Evaluate(unread(1), art, &Rules{BlockUnexamined: &on}, nil, time.Now())
	if strict.Verdict == VerdictApproved {
		t.Fatal("an artifact that could not be read was approved under blockUnexamined")
	}
	if len(strict.Violations) == 0 || strict.Violations[0].Rule != RuleBlockUnexamined {
		t.Fatalf("refused for the wrong reason: %+v", strict.Violations)
	}
}

// A fully read artifact must not trip it, or the rule is unusable.
func TestAFullyExaminedArtifactIsUnaffected(t *testing.T) {
	on := true
	clean := []ScannerResult{{Scanner: "model-inspector", Status: "Passed"}}
	eval := Evaluate(clean, Artifact{URI: "pvc://claim/m"}, &Rules{BlockUnexamined: &on}, nil, time.Now())
	if eval.Verdict != VerdictApproved {
		t.Fatalf("a fully examined artifact was refused: %q — %+v", eval.Verdict, eval.Violations)
	}
}

// Any severity counts. The point is not how bad the unread part looked; it is
// that nobody looked at it.
func TestSeverityOfTheUnreadPartDoesNotMatter(t *testing.T) {
	on := true
	for name, c := range map[string]SeverityCounts{
		"low":     {Low: 1},
		"medium":  {Medium: 1},
		"high":    {High: 1},
		"unknown": {Unknown: 1},
	} {
		results := []ScannerResult{{Scanner: "s", Status: "Passed", Unexamined: c}}
		eval := Evaluate(results, Artifact{URI: "u"}, &Rules{BlockUnexamined: &on}, nil, time.Now())
		if eval.Verdict == VerdictApproved {
			t.Errorf("%s severity in the coverage bucket did not refuse", name)
		}
	}
}

// Coverage is summed across scanners, like drift: whichever one ran into the
// unreadable file, the artifact is the thing that was not fully read.
func TestCoverageIsSummedAcrossScanners(t *testing.T) {
	on := true
	results := []ScannerResult{
		{Scanner: "model-inspector", Status: "Passed"},
		{Scanner: "clamav", Status: "Passed", Unexamined: SeverityCounts{Low: 2}},
	}
	eval := Evaluate(results, Artifact{URI: "u"}, &Rules{BlockUnexamined: &on}, nil, time.Now())
	if eval.Unexamined.Total() != 2 {
		t.Errorf("coverage totalled %d, want 2", eval.Unexamined.Total())
	}
	if eval.Verdict == VerdictApproved {
		t.Error("a scanner other than the inspector hit an unreadable file and it was approved")
	}
}
