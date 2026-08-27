package gate

import (
	"testing"
	"time"
)

func highFindings(n int32) []ScannerResult {
	return []ScannerResult{{
		Scanner: "model-inspector", Status: "Passed",
		Findings: n, Severities: SeverityCounts{High: n},
	}}
}

// The gap a real cluster run exposed: 30 of 300 models carried High model
// findings — a chat template reaching the interpreter, a native library beside
// the weights — and came back Approved, because BlockUnsafeModel covers
// Critical and nothing covered High.
func TestHighModelFindingsCanBeRefused(t *testing.T) {
	art := Artifact{URI: "pvc://claim/m"}
	zero, five := int32(0), int32(5)

	// Unset, and it behaves exactly as before.
	if v := Evaluate(highFindings(2), art, &Rules{}, nil, time.Now()); v.Verdict != VerdictApproved {
		t.Fatalf("with no limit set the verdict changed to %q", v.Verdict)
	}

	// Zero tolerance refuses.
	strict := Evaluate(highFindings(2), art, &Rules{MaxHighModelFindings: &zero}, nil, time.Now())
	if strict.Verdict == VerdictApproved {
		t.Fatal("two high model findings were approved under a limit of zero")
	}
	if strict.Violations[0].Rule != RuleMaxHighModel {
		t.Errorf("refused for the wrong reason: %+v", strict.Violations)
	}

	// A budget admits what fits inside it.
	loose := Evaluate(highFindings(2), art, &Rules{MaxHighModelFindings: &five}, nil, time.Now())
	if loose.Verdict != VerdictApproved {
		t.Errorf("two findings under a limit of five was refused: %q", loose.Verdict)
	}
	over := Evaluate(highFindings(6), art, &Rules{MaxHighModelFindings: &five}, nil, time.Now())
	if over.Verdict == VerdictApproved {
		t.Error("six findings under a limit of five was approved")
	}
}

// The threshold must count model findings, not CVEs — they are separate
// buckets and conflating them would make either rule mean the wrong thing.
func TestTheLimitCountsModelFindingsNotCVEs(t *testing.T) {
	zero := int32(0)
	cvesOnly := []ScannerResult{{
		Scanner: "trivy", Status: "Passed", Findings: 3,
		Severities: SeverityCounts{High: 3},
	}}
	eval := Evaluate(cvesOnly, Artifact{URI: "u"},
		&Rules{MaxHighModelFindings: &zero}, nil, time.Now())
	for _, v := range eval.Violations {
		if v.Rule == RuleMaxHighModel {
			t.Error("a CVE scanner's high findings tripped the model-findings limit")
		}
	}
}

// A clean model must be unaffected, or the rule is unusable.
func TestACleanModelIsUnaffectedByTheLimit(t *testing.T) {
	zero := int32(0)
	clean := []ScannerResult{{Scanner: "model-inspector", Status: "Passed"}}
	if v := Evaluate(clean, Artifact{URI: "u"}, &Rules{MaxHighModelFindings: &zero}, nil, time.Now()); v.Verdict != VerdictApproved {
		t.Fatalf("a clean model was refused: %q — %+v", v.Verdict, v.Violations)
	}
}
