package inspect

import (
	"fmt"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/parse"
)

// FindingGGUFUnreadable is a GGUF file that could not be examined.
//
// Reported rather than passed over in silence. A scanner that recognises a
// format, fails to read it, and says nothing produces a report identical to one
// over a file it read and found clean — and the reader of that report has no
// way to tell which they are holding. That is the more dangerous of the two
// outcomes, because it is the one that looks like an assurance.
const FindingGGUFUnreadable = "TESS-GGUF-009"

// inspectGGUF examines a GGUF file's header, metadata and tensor table.
//
// The checks themselves live in the parser, which has always had them: bad
// magic, implausible counts, over-long strings, malformed dimensions. They were
// simply never reached from a scan, because this extension was not dispatched.
// A malformed GGUF scanned clean.
func inspectGGUF(path, rel string) ([]model.Finding, error) {
	a, err := parse.ParseGGUF(path)
	if err != nil {
		return []model.Finding{finding(
			FindingGGUFUnreadable, "GGUF file could not be examined", "Medium", rel,
			fmt.Sprintf("the file claims to be GGUF but its header could not be read (%v); "+
				"nothing inside it has been checked", err))}, nil
	}
	if a == nil {
		return []model.Finding{finding(
			FindingGGUFUnreadable, "GGUF file could not be examined", "Medium", rel,
			"the file claims to be GGUF but yielded nothing to examine")}, nil
	}

	// The parser records where it looked by absolute path; a report is read
	// against the artifact, so say where the file sits within it.
	out := make([]model.Finding, 0, len(a.Findings))
	for _, f := range a.Findings {
		f.Location = rel
		out = append(out, f)
	}
	return out, nil
}
