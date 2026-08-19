// Package strutil holds the small string helpers that more than one package
// genuinely needs, so there is one implementation rather than several that
// drift apart.
//
// It is deliberately tiny. A helper belongs here only when two callers want
// exactly the same behaviour; a function that merely looks similar to another
// stays where it is, because collapsing two rules that happen to coincide today
// is how a change made for one caller silently breaks the other.
package strutil

import "strings"

// Slug reduces s to characters that are safe in a filename, a URL fragment, and
// an identifier: letters, digits, dot, dash, underscore. Everything else
// becomes a dash, and runs of dashes at either end are trimmed.
//
// fallback is returned when nothing survives — an empty string would otherwise
// produce a nameless file or an unaddressable identifier.
//
// Note that this is not the rule for an SPDX LicenseRef, which forbids the
// underscore. That one lives in internal/spdxlicense and stays separate on
// purpose: it implements a specification, not a convenience.
func Slug(s, fallback string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return fallback
	}
	return out
}
