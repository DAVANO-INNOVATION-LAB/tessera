package parse

import (
	"strings"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// Reading the governance half of a model card.
//
// Hugging Face model cards follow a template closely enough to be worth
// parsing: the frontmatter carries structured fields, and the body carries the
// prose under predictable headings — "Uses", "Out-of-Scope Use", "Bias, Risks,
// and Limitations", "Limitations", "Recommendations". That prose is what a
// reviewer is actually looking for and what CycloneDX has a block for.
//
// Two rules keep this honest.
//
// It reads headings, never sentences. Deciding that a paragraph *is* a
// limitation would be inference dressed as extraction; matching a heading the
// author wrote is reading. Where a card does not use the template, nothing is
// reported — an absent consideration is better than an invented one.
//
// And everything it produces is marked declared, sourced to the file. Nothing in
// a weights file states an intended use. These are the author's claims, carried
// so a reviewer can read them, never so a tool can assert them.

// headingTopic maps a model-card heading to the consideration it belongs to.
// Matched case-insensitively against the heading text with punctuation removed,
// longest first, so "out of scope use" wins over "use".
var headingTopics = []struct {
	match string
	topic string
}{
	{"out of scope use", "limitation"},
	{"out-of-scope use", "limitation"},
	{"bias risks and limitations", "risk"},
	{"bias risks limitations", "risk"},
	{"risks and limitations", "risk"},
	{"ethical considerations", "risk"},
	{"technical limitations", "limitation"},
	{"known limitations", "limitation"},
	{"limitations and bias", "risk"},
	{"limitations", "limitation"},
	{"recommendations", "mitigation"},
	{"intended uses and limitations", "use"},
	{"intended use", "use"},
	{"direct use", "use"},
	{"downstream use", "use"},
	{"uses", "use"},
	{"intended users", "user"},
	{"performance and limitations", "tradeoff"},
	{"performance", "tradeoff"},
}

// parseConsiderations reads the body of a model card into the considerations
// block. body is the markdown after any YAML frontmatter.
func parseConsiderations(a *model.Artifact, body, source string) {
	sections := markdownSections(body)
	if len(sections) == 0 {
		return
	}
	c := &a.Considerations
	var mitigation string

	for _, sec := range sections {
		topic := topicFor(sec.heading)
		if topic == "" || sec.text == "" {
			continue
		}
		switch topic {
		case "use":
			c.UseCases = appendUnique(c.UseCases, sec.text)
		case "user":
			c.Users = appendUnique(c.Users, sec.text)
		case "limitation":
			c.TechnicalLimitations = appendUnique(c.TechnicalLimitations, sec.text)
		case "tradeoff":
			c.PerformanceTradeoffs = appendUnique(c.PerformanceTradeoffs, sec.text)
		case "mitigation":
			// Held rather than emitted: a recommendation is the mitigation for
			// the risks the card raises, and CycloneDX models it as a field on
			// a risk rather than a list of its own.
			mitigation = sec.text
		case "risk":
			c.EthicalConsiderations = append(c.EthicalConsiderations,
				model.Risk{Name: sec.text})
		}
	}

	if mitigation != "" {
		for i := range c.EthicalConsiderations {
			if c.EthicalConsiderations[i].MitigationStrategy == "" {
				c.EthicalConsiderations[i].MitigationStrategy = mitigation
			}
		}
	}
	if !c.Empty() {
		c.Source = source
	}
}

func topicFor(heading string) string {
	h := normalizeHeading(heading)
	for _, t := range headingTopics {
		if h == t.match || strings.HasPrefix(h, t.match) {
			return t.topic
		}
	}
	return ""
}

// normalizeHeading lowercases and strips punctuation and template scaffolding,
// so "### Bias, Risks, and Limitations [optional]" matches.
func normalizeHeading(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.Index(s, "["); i >= 0 {
		s = s[:i]
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ', r == '-', r == ',', r == '&', r == ':':
			b.WriteRune(' ')
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

type mdSection struct {
	heading string
	text    string
}

// markdownSections splits a document at ATX headings.
//
// Fenced code blocks are skipped: a "# comment" inside a shell example is not a
// heading, and treating it as one would attach a code snippet to a governance
// field.
func markdownSections(body string) []mdSection {
	var out []mdSection
	var cur *mdSection
	var buf []string
	inFence := false

	flush := func() {
		if cur != nil {
			cur.text = cleanBody(strings.Join(buf, "\n"))
			out = append(out, *cur)
		}
		buf = nil
	}

	for _, line := range strings.Split(body, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
			inFence = !inFence
		}
		if !inFence && strings.HasPrefix(t, "#") {
			flush()
			h := strings.TrimLeft(t, "#")
			cur = &mdSection{heading: strings.TrimSpace(h)}
			continue
		}
		if cur != nil {
			buf = append(buf, line)
		}
	}
	flush()
	return out
}

// cleanBody reduces a section to a single readable paragraph.
//
// Bounded deliberately. A model card section can run for pages, and a bill of
// materials is not the place to reproduce one — the document says what the card
// claims and names the file, so a reader who needs the full text knows where it
// is.
func cleanBody(s string) string {
	const limit = 500
	var lines []string
	inFence := false
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence || t == "" {
			continue
		}
		// Template placeholders carry no information and appear in a great many
		// cards that were generated and never filled in.
		if strings.Contains(t, "[More Information Needed]") || strings.HasPrefix(t, "<!--") {
			continue
		}
		t = strings.TrimLeft(t, "-*+ ")
		lines = append(lines, t)
	}
	out := strings.Join(lines, " ")
	out = strings.Join(strings.Fields(out), " ")
	if len(out) > limit {
		// Cut at a word boundary so the text does not end mid-token.
		cut := strings.LastIndex(out[:limit], " ")
		if cut < limit/2 {
			cut = limit
		}
		out = strings.TrimRight(out[:cut], " .,;:") + "…"
	}
	return out
}

func appendUnique(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}
