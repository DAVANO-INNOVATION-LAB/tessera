package model

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var idPattern = regexp.MustCompile(`TESS-[A-Z0-9]+-\d+`)

// Every id in the taxonomy must be one the tool can actually emit. A mapping
// for a finding that does not exist is dead weight that looks like coverage.
func TestTaxonomyOnlyNamesRealFindings(t *testing.T) {
	emitted := emittedIDs(t)
	for id := range taxonomy {
		if !emitted[id] {
			t.Errorf("taxonomy maps %s, which nothing emits", id)
		}
	}
}

// The inverse is deliberately not required: operational findings carry no CWE
// on purpose. What this test enforces is that the *unmapped* set stays the set
// somebody decided on, so a new finding cannot slip through unclassified
// without a person looking at it.
func TestUnmappedFindingsAreTheExpectedOnes(t *testing.T) {
	expected := map[string]bool{
		"TESS-DRIFT-005": true, "TESS-COVERAGE-001": true,
		"TESS-FILE-001": true, "TESS-FILE-002": true,
		"TESS-IO-001": true, "TESS-IO-002": true,
		"TESS-KERAS-004": true, "TESS-ONNX-005": true,
		"TESS-ONNX-006": true, "TESS-LIC-001": true,
	}
	for id := range emittedIDs(t) {
		if _, mapped := taxonomy[id]; mapped {
			continue
		}
		if !expected[id] {
			t.Errorf("%s has no CWE and is not on the deliberately-unmapped list. "+
				"Either classify it or add it there with a reason — an unclassified "+
				"finding is one nobody downstream can action.", id)
		}
	}
}

// A CWE identifier is a number. Getting this wrong produces a link that 404s in
// somebody's ticket a month later.
func TestCWEIdentifiersAreWellFormed(t *testing.T) {
	numeric := regexp.MustCompile(`^\d+$`)
	atlasPattern := regexp.MustCompile(`^AML\.T\d{4}(\.\d{3})?$`)
	for id, c := range taxonomy {
		if c.CWE != "" {
			if !numeric.MatchString(c.CWE) {
				t.Errorf("%s: CWE %q is not a bare number", id, c.CWE)
			}
			if c.CWEName == "" {
				t.Errorf("%s: CWE-%s has no name, so a reader has to look it up", id, c.CWE)
			}
		}
		if c.ATLAS != "" {
			if !atlasPattern.MatchString(c.ATLAS) {
				t.Errorf("%s: %q is not an ATLAS technique id", id, c.ATLAS)
			}
			if c.ATLASName == "" {
				t.Errorf("%s: %s has no name", id, c.ATLAS)
			}
		}
	}
}

// The two most dangerous findings must carry the classification a security
// engineer would search for. If these ever lose their mapping, the table has
// been edited carelessly.
func TestTheObviousOnesAreClassified(t *testing.T) {
	for id, wantCWE := range map[string]string{
		"TESS-PICKLE-001":  "502", // deserialization of untrusted data
		"TESS-PY-001":      "78",  // OS command injection
		"TESS-ARCHIVE-003": "22",  // path traversal
		"TESS-HF-001":      "829", // untrusted inclusion
	} {
		c, ok := Classify(id)
		if !ok || c.CWE != wantCWE {
			t.Errorf("Classify(%s) = %q, want CWE-%s", id, c.CWE, wantCWE)
		}
	}
}

func TestClassifyReportsAbsence(t *testing.T) {
	if _, ok := Classify("TESS-LIC-001"); ok {
		t.Error("an operational finding reported a classification")
	}
	if _, ok := Classify("TESS-NOT-REAL-001"); ok {
		t.Error("an unknown id reported a classification")
	}
}

func emittedIDs(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, dir := range []string{"..", "../../cmd", "../../internal"} {
		walk(t, dir, out)
	}
	if len(out) < 50 {
		t.Fatalf("only found %d finding ids; this test is not looking where it thinks it is", len(out))
	}
	return out
}

func walk(t *testing.T, dir string, out map[string]bool) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		p := dir + "/" + e.Name()
		if e.IsDir() {
			if e.Name() == "testdata" || e.Name() == ".git" {
				continue
			}
			walk(t, p, out)
			continue
		}
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, id := range idPattern.FindAllString(string(b), -1) {
			if !strings.HasPrefix(id, "TESS-TEST") {
				out[id] = true
			}
		}
	}
}
