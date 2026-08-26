package model

import "testing"

// The unexamined set and the deliberately-unmapped set answer the same
// question — "does this describe the artifact, or the scan?" — so a finding
// added to one and forgotten in the other is a finding the gate misreads.
func TestUnexaminedFindingsCarryNoCWE(t *testing.T) {
	for _, id := range UnexaminedIDs() {
		if !Unexamined(id) {
			t.Errorf("%s is listed but not recognised", id)
		}
		if _, mapped := taxonomy[id]; mapped {
			t.Errorf("%s is treated as unexamined but also carries a CWE; it cannot be both "+
				"a statement about coverage and a weakness class", id)
		}
	}
}

// Findings about the artifact must never land in the coverage bucket.
func TestFindingsAboutTheArtifactAreNotUnexamined(t *testing.T) {
	for _, id := range []string{
		"TESS-PICKLE-001", "TESS-HF-001", "TESS-HF-003", "TESS-GGUF-010",
		"TESS-ARCHIVE-003", "TESS-NATIVE-001", "TESS-DRIFT-002",
		// Present but unstated is not the same as unread.
		"TESS-LIC-001", "TESS-DRIFT-005",
	} {
		if Unexamined(id) {
			t.Errorf("%s says something about the artifact and must not count as unexamined", id)
		}
	}
}
