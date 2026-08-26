package model

// Unexamined reports whether a finding says a file was not read, rather than
// saying something about what was in it.
//
// The distinction matters because a verdict is built from findings, and these
// carry no information about the artifact at all — only about the scan. A
// report with none of them and a report full of them look equally clean to
// anything counting severities, which is how an artifact nobody could parse
// comes back approved.
//
// This is the same set the taxonomy declines to give a CWE, and for the same
// reason: they describe coverage, not a weakness. Keeping one list means the
// two answers cannot drift apart.
func Unexamined(id string) bool {
	switch id {
	case
		// The walk stopped early or a file could not be opened.
		"TESS-COVERAGE-001", "TESS-FILE-001", "TESS-FILE-002",
		"TESS-IO-001", "TESS-IO-002",
		// A container was recognised and could not be read into.
		"TESS-KERAS-004", "TESS-ONNX-005", "TESS-ONNX-006", "TESS-GGUF-009":
		return true
	}
	return false
}

// UnexaminedIDs lists every finding meaning "this was not examined".
func UnexaminedIDs() []string {
	return []string{
		"TESS-COVERAGE-001", "TESS-FILE-001", "TESS-FILE-002",
		"TESS-IO-001", "TESS-IO-002",
		"TESS-KERAS-004", "TESS-ONNX-005", "TESS-ONNX-006", "TESS-GGUF-009",
	}
}
