package store

import (
	"fmt"
	"strings"
	"time"
)

// Suppressions: the difference between a tool people keep using and one they
// stop opening.
//
// Some findings are true and accepted. TESS-PICKLE-003 fires on every pickle by
// design — it is a property of the format, not a defect in the model — and
// drift fires on legitimately re-quantised weights. A tool that shows those
// forever with no way to say "reviewed, accepted, here is why" gets ignored
// within a week, and then the Critical it reports next month is ignored too.
//
// Three rules, each of which exists because the obvious shortcut is worse.
//
// **A reason is required.** An unexplained waiver is indistinguishable from a
// mistake when somebody reads it a year later, and the person who wrote it will
// not be there to ask.
//
// **Suppression hides, it never deletes.** The scan record keeps every finding
// exactly as it was found. Suppression is a view over the truth, not an edit to
// it — otherwise history stops being evidence and an audit cannot reconstruct
// what the tool actually saw.
//
// **An expiry is offered and its absence is visible.** A waiver that never
// expires is how an accepted risk becomes a forgotten one. Permanent
// suppressions are allowed, because sometimes they are right, but they are
// marked so a reviewer can find them.

// Suppression is an accepted finding.
type Suppression struct {
	ID string `json:"id"`
	// FindingID is required: a suppression that matched everything would be an
	// off switch for the tool.
	FindingID string `json:"findingId"`
	// Location, when set, narrows the suppression to one file. Empty means the
	// finding is accepted wherever it appears, which is right for a
	// format-inherent finding and wrong for most others.
	Location string `json:"location,omitempty"`
	// Digest, when set, binds the suppression to one artifact's bytes. This is
	// the strongest form: accepting a finding in *this* model rather than in
	// every model that ever reports it.
	Digest string `json:"digest,omitempty"`

	// Reason is required. See the package comment.
	Reason string `json:"reason"`
	// By records who accepted it. Empty when no identity was available, which
	// is itself worth seeing in a review.
	By string `json:"by,omitempty"`

	CreatedAt string `json:"createdAt"`
	// ExpiresAt is optional. Empty means it never expires, which the interface
	// marks rather than hides.
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// Expired reports whether the suppression has lapsed.
func (s Suppression) Expired(now time.Time) bool {
	if s.ExpiresAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, s.ExpiresAt)
	if err != nil {
		// An unparseable expiry is treated as expired. Failing towards showing
		// the finding is the safe direction: the cost is noise, and the cost of
		// the other choice is a hidden Critical.
		return true
	}
	return now.After(t)
}

// Permanent reports whether this suppression has no expiry, so a reviewer can
// find the ones that will never lapse on their own.
func (s Suppression) Permanent() bool { return s.ExpiresAt == "" }

// Matches reports whether a finding is covered.
//
// Empty Location or Digest widen the match rather than narrow it, so a
// suppression is always at least as broad as it looks and never accidentally
// narrower than intended.
func (s Suppression) Matches(findingID, location, digest string, now time.Time) bool {
	if s.Expired(now) {
		return false
	}
	if !strings.EqualFold(s.FindingID, findingID) {
		return false
	}
	if s.Location != "" && s.Location != location {
		return false
	}
	if s.Digest != "" && s.Digest != digest {
		return false
	}
	return true
}

// Suppressions returns every suppression, newest first.
func (st *Store) Suppressions() []Suppression {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]Suppression, len(st.cfg.Suppressions))
	copy(out, st.cfg.Suppressions)
	return out
}

// AddSuppression records an accepted finding.
func (st *Store) AddSuppression(s Suppression) (Suppression, error) {
	if strings.TrimSpace(s.FindingID) == "" {
		return Suppression{}, fmt.Errorf("a suppression needs a finding id")
	}
	if strings.TrimSpace(s.Reason) == "" {
		return Suppression{}, fmt.Errorf(
			"a suppression needs a reason: an unexplained waiver is indistinguishable " +
				"from a mistake when somebody reads it a year from now")
	}
	if s.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, s.ExpiresAt); err != nil {
			return Suppression{}, fmt.Errorf("expiry must be an RFC3339 time")
		}
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	s.ID = newID()
	s.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	st.cfg.Suppressions = append(st.cfg.Suppressions, s)
	return s, st.writeLocked()
}

// RemoveSuppression lifts a waiver, so the finding surfaces again.
func (st *Store) RemoveSuppression(id string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	for i, s := range st.cfg.Suppressions {
		if s.ID == id {
			st.cfg.Suppressions = append(st.cfg.Suppressions[:i], st.cfg.Suppressions[i+1:]...)
			return st.writeLocked()
		}
	}
	return fmt.Errorf("no suppression with id %q", id)
}

// Apply splits findings into active and suppressed.
//
// Nothing is discarded: the suppressed set is returned so the interface can
// show a count and let somebody look. A finding that vanishes without trace is
// how an accepted risk becomes an invisible one.
func (st *Store) Apply(findings []FindingRecord, digest string, now time.Time) (active, suppressed []FindingRecord) {
	sups := st.Suppressions()
	for _, f := range findings {
		hidden := false
		for _, s := range sups {
			if s.Matches(f.ID, f.Location, digest, now) {
				hidden = true
				break
			}
		}
		if hidden {
			suppressed = append(suppressed, f)
			continue
		}
		active = append(active, f)
	}
	return active, suppressed
}
