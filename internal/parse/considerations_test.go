package parse

import (
	"strings"
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

const fullCard = `
# Some-Model

## Uses

### Direct Use
Assistant-style chat in English.

### Out-of-Scope Use
Must not be used for medical or legal advice.

## Bias, Risks, and Limitations
Reflects biases in web-scale training data.

## Recommendations
Keep a human in the loop.

` + "```bash\n# not a heading\necho hi\n```" + `
`

func TestConsiderationsReadFromHeadings(t *testing.T) {
	a := &model.Artifact{}
	parseConsiderations(a, fullCard, "README.md")
	c := a.Considerations

	if len(c.UseCases) != 1 || !strings.Contains(c.UseCases[0], "Assistant-style") {
		t.Errorf("useCases = %v", c.UseCases)
	}
	if len(c.TechnicalLimitations) != 1 || !strings.Contains(c.TechnicalLimitations[0], "medical") {
		t.Errorf("technicalLimitations = %v", c.TechnicalLimitations)
	}
	if len(c.EthicalConsiderations) != 1 {
		t.Fatalf("ethicalConsiderations = %v", c.EthicalConsiderations)
	}
	// Recommendations are the mitigation for the risks the card raises, which
	// is how CycloneDX models them — a field on a risk, not a list of its own.
	if !strings.Contains(c.EthicalConsiderations[0].MitigationStrategy, "human in the loop") {
		t.Errorf("recommendations were not attached as a mitigation: %+v", c.EthicalConsiderations[0])
	}
	if c.Source != "README.md" {
		t.Errorf("source = %q; declared prose must name the file it came from", c.Source)
	}
}

// A "# heading" inside a fenced code block is a shell comment. Treating it as a
// heading would attach a code snippet to a governance field.
func TestHeadingsInsideCodeFencesAreIgnored(t *testing.T) {
	a := &model.Artifact{}
	parseConsiderations(a, fullCard, "README.md")
	for _, s := range append(a.Considerations.UseCases, a.Considerations.TechnicalLimitations...) {
		if strings.Contains(s, "echo hi") || strings.Contains(s, "not a heading") {
			t.Errorf("code-fence content leaked into considerations: %q", s)
		}
	}
}

// A card that does not use the template reports nothing. An absent
// consideration is better than an invented one — deciding that a paragraph *is*
// a limitation would be inference dressed up as extraction.
func TestUnstructuredCardYieldsNothing(t *testing.T) {
	a := &model.Artifact{}
	parseConsiderations(a, "Just some prose about a model, with no headings at all.\n", "README.md")
	if !a.Considerations.Empty() {
		t.Errorf("invented considerations from unstructured prose: %+v", a.Considerations)
	}
}

// Generated cards are full of unfilled placeholders. Carrying them into a bill
// of materials would fill a governance field with the word "needed".
func TestPlaceholdersAreNotCarried(t *testing.T) {
	a := &model.Artifact{}
	parseConsiderations(a, "## Limitations\n\n[More Information Needed]\n", "README.md")
	if !a.Considerations.Empty() {
		t.Errorf("a placeholder was carried through: %+v", a.Considerations)
	}
}

// Long sections are bounded. A bill of materials names the source; it does not
// reproduce a model card.
func TestLongSectionsAreBounded(t *testing.T) {
	a := &model.Artifact{}
	parseConsiderations(a, "## Limitations\n\n"+strings.Repeat("word ", 500), "README.md")
	if len(a.Considerations.TechnicalLimitations) != 1 {
		t.Fatal("expected one limitation")
	}
	got := a.Considerations.TechnicalLimitations[0]
	if len(got) > 520 {
		t.Errorf("section not bounded: %d characters", len(got))
	}
	if !strings.HasSuffix(got, "…") {
		t.Error("a truncated section should say it was truncated")
	}
}

// The longest heading wins, so "Out-of-Scope Use" is a limitation rather than a
// use case.
func TestOutOfScopeUseIsALimitationNotAUseCase(t *testing.T) {
	a := &model.Artifact{}
	parseConsiderations(a, "## Out-of-Scope Use\n\nNot for medical advice.\n", "README.md")
	if len(a.Considerations.UseCases) != 0 {
		t.Errorf("out-of-scope use was recorded as an intended use: %v", a.Considerations.UseCases)
	}
	if len(a.Considerations.TechnicalLimitations) != 1 {
		t.Errorf("technicalLimitations = %v", a.Considerations.TechnicalLimitations)
	}
}
