package main

import (
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/tessera"
)

func artifactWith(severities ...string) *tessera.Artifact {
	a := &tessera.Artifact{}
	for i, s := range severities {
		a.Findings = append(a.Findings, tessera.Finding{
			ID: "TESS-TEST-00" + string(rune('1'+i)), Severity: s,
		})
	}
	return a
}

// The reason --fail-on exists: High and Medium share exit code 2, so a caller
// gating on the number alone cannot separate them. These cases are the ones
// that were impossible before.
func TestGateExitSeparatesHighFromMedium(t *testing.T) {
	cases := []struct {
		name    string
		worst   string
		failOn  string
		want    int
		because string
	}{
		{"medium under a high gate passes", tessera.SeverityMedium, "high", exitClean,
			"gating on high must not fail a Medium-only result"},
		{"high under a high gate fails", tessera.SeverityHigh, "high", exitFindings, ""},
		{"high under a critical gate passes", tessera.SeverityHigh, "critical", exitClean, ""},
		{"critical under a critical gate fails", tessera.SeverityCritical, "critical", exitCritical, ""},
		{"medium under a medium gate fails", tessera.SeverityMedium, "medium", exitFindings, ""},
		{"low under a medium gate passes", tessera.SeverityLow, "medium", exitClean, ""},
		{"low under a low gate still exits clean", tessera.SeverityLow, "low", exitClean,
			"a Low finding is not an exit-worthy result even when gated on"},
		{"critical under never passes", tessera.SeverityCritical, "never", exitClean,
			"never must suppress even a Critical"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := gateExit(artifactWith(tc.worst), tc.failOn)
			if err != nil {
				t.Fatalf("gateExit: %v", err)
			}
			if got != tc.want {
				t.Errorf("gateExit(worst=%s, fail-on=%s) = %d, want %d. %s",
					tc.worst, tc.failOn, got, tc.want, tc.because)
			}
		})
	}
}

// An unset threshold must not change what already-published pipelines see.
func TestGateExitUnsetPreservesHistoricalCodes(t *testing.T) {
	for _, tc := range []struct {
		worst string
		want  int
	}{
		{tessera.SeverityCritical, exitCritical},
		{tessera.SeverityHigh, exitFindings},
		{tessera.SeverityMedium, exitFindings},
		{tessera.SeverityLow, exitClean},
	} {
		got, err := gateExit(artifactWith(tc.worst), "")
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("worst=%s with no --fail-on = %d, want %d", tc.worst, got, tc.want)
		}
	}
	got, err := gateExit(&tessera.Artifact{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != exitClean {
		t.Errorf("no findings = %d, want %d", got, exitClean)
	}
}

func TestGateExitRejectsUnknownThreshold(t *testing.T) {
	for _, v := range []string{"none", "warn", "CRITICAL!", "2", "info"} {
		if _, err := gateExit(artifactWith(tessera.SeverityHigh), v); err == nil {
			t.Errorf("--fail-on %q was accepted; an unknown threshold must be a usage error", v)
		}
	}
	// Case is not the user's problem.
	if _, err := gateExit(artifactWith(tessera.SeverityHigh), "Critical"); err != nil {
		t.Errorf("--fail-on Critical should be accepted case-insensitively: %v", err)
	}
}
