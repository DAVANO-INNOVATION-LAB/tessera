package tessera_test

import (
	"context"
	"testing"

	tessera "github.com/DAVANO-INNOVATION-LAB/tessera"
)

// Coverage exists to be honest about gaps, so the tests are mostly about the
// gaps being reported rather than the populated rows being counted.

func TestCoverageReportsBothStandards(t *testing.T) {
	dir := t.TempDir()
	artifact := writeSafetensors(t, dir, map[string]string{"format": "pt", "license": "mit"})

	for _, std := range tessera.CoverageStandards() {
		t.Run(std, func(t *testing.T) {
			rep, err := tessera.Coverage(context.Background(), std, artifact)
			if err != nil {
				t.Fatalf("Coverage(%s): %v", std, err)
			}
			if len(rep.Elements) == 0 {
				t.Fatal("a standard with no elements is not a standard")
			}
			if rep.Populated == 0 {
				t.Error("nothing was populated, which would mean the mapping is not wired up")
			}
			// The unfillable rows must be present and reasoned. A report that
			// silently omitted them would overstate coverage, which is the
			// failure this feature exists to avoid.
			if rep.OutOfScope == 0 {
				t.Error("no element was marked out of scope; training data and evaluation " +
					"results are never derivable from a model file and must be reported as such")
			}
			for _, e := range rep.Elements {
				if e.Status == tessera.CoverageOutOfScope && e.Note == "" {
					t.Errorf("%q is out of scope without saying why", e.Name)
				}
			}
			if got := rep.Populated + rep.Absent + rep.OutOfScope; got != len(rep.Elements) {
				t.Errorf("counts sum to %d but there are %d elements", got, len(rep.Elements))
			}
		})
	}
}

func TestCoverageRejectsUnknownStandard(t *testing.T) {
	dir := t.TempDir()
	artifact := writeSafetensors(t, dir, map[string]string{"format": "pt"})

	if _, err := tessera.Coverage(context.Background(), "not-a-standard", artifact); err == nil {
		t.Error("an unknown standard should be refused rather than silently reported against nothing")
	}
}

// TestCoverageDistinguishesAbsentFromUnfillable pins the distinction the report
// is built on: a licence the artifact happens not to state is absent and could
// be supplied, while training properties can never be.
func TestCoverageDistinguishesAbsentFromUnfillable(t *testing.T) {
	dir := t.TempDir()
	// No licence in the metadata, so the licence row should be absent.
	artifact := writeSafetensors(t, dir, map[string]string{"format": "pt"})

	rep, err := tessera.Coverage(context.Background(), "g7", artifact)
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]tessera.CoverageStatus{}
	for _, e := range rep.Elements {
		status[e.Name] = e.Status
	}
	if got := status["Model license"]; got != tessera.CoverageAbsent {
		t.Errorf("an undisclosed licence should be absent, got %q", got)
	}
	if got := status["Model training properties"]; got != tessera.CoverageOutOfScope {
		t.Errorf("training properties should be out of scope, got %q", got)
	}
}
