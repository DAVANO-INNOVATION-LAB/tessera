package store

import (
	"testing"
	"time"
)

var now = time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

// An unexplained waiver is indistinguishable from a mistake a year later, and
// the person who wrote it will not be there to ask.
func TestSuppressionRequiresAReason(t *testing.T) {
	s := open(t)
	if _, err := s.AddSuppression(Suppression{FindingID: "TESS-PICKLE-003"}); err == nil {
		t.Error("a suppression with no reason was accepted")
	}
	if _, err := s.AddSuppression(Suppression{Reason: "fine"}); err == nil {
		t.Error("a suppression with no finding id was accepted; it would match everything")
	}
}

// Suppression is a view over the truth, not an edit to it. The scan record has
// to keep every finding or history stops being evidence.
func TestSuppressionHidesButNeverDeletes(t *testing.T) {
	s := open(t)
	s.AddSuppression(Suppression{
		FindingID: "TESS-PICKLE-003", Reason: "inherent to the format, accepted"})

	findings := []FindingRecord{
		{ID: "TESS-PICKLE-003", Severity: "Low"},
		{ID: "TESS-PICKLE-001", Severity: "Critical"},
	}
	active, hidden := s.Apply(findings, "digest", now)

	if len(active) != 1 || active[0].ID != "TESS-PICKLE-001" {
		t.Errorf("active = %v, want only the un-waived Critical", active)
	}
	if len(hidden) != 1 || hidden[0].ID != "TESS-PICKLE-003" {
		t.Errorf("suppressed = %v, want the waived finding returned, not discarded", hidden)
	}
}

// A lapsed waiver must stop hiding, or "time-boxed" means nothing.
func TestExpiredSuppressionStopsHiding(t *testing.T) {
	s := open(t)
	s.AddSuppression(Suppression{
		FindingID: "TESS-DRIFT-002", Reason: "re-quantised on purpose",
		ExpiresAt: now.Add(-time.Hour).Format(time.RFC3339)})

	active, hidden := s.Apply([]FindingRecord{{ID: "TESS-DRIFT-002"}}, "d", now)
	if len(active) != 1 {
		t.Error("an expired suppression is still hiding a finding")
	}
	if len(hidden) != 0 {
		t.Error("an expired suppression reported the finding as suppressed")
	}
}

// An unparseable expiry fails towards showing the finding. The cost of that is
// noise; the cost of the other direction is a hidden Critical.
func TestUnparseableExpiryFailsTowardsShowing(t *testing.T) {
	s := Suppression{FindingID: "X", ExpiresAt: "not-a-time"}
	if !s.Expired(now) {
		t.Error("a suppression with an unreadable expiry was treated as live")
	}
}

// Scoping narrows; an empty scope is deliberately broad. Getting this backwards
// would silently hide findings somebody meant to see.
func TestScopeNarrowsRatherThanWidens(t *testing.T) {
	byLocation := Suppression{FindingID: "F", Location: "a.pkl", Reason: "r"}
	if !byLocation.Matches("F", "a.pkl", "d1", now) {
		t.Error("a location-scoped suppression did not match its own location")
	}
	if byLocation.Matches("F", "b.pkl", "d1", now) {
		t.Error("a location-scoped suppression matched a different file")
	}

	byDigest := Suppression{FindingID: "F", Digest: "d1", Reason: "r"}
	if byDigest.Matches("F", "a.pkl", "d2", now) {
		t.Error("a digest-scoped suppression matched a different artifact")
	}

	broad := Suppression{FindingID: "F", Reason: "r"}
	if !broad.Matches("F", "anywhere.pkl", "any-digest", now) {
		t.Error("an unscoped suppression should match wherever the finding appears")
	}
	if broad.Matches("OTHER", "anywhere.pkl", "d", now) {
		t.Error("a suppression matched a different finding id")
	}
}

// A waiver that never expires is how an accepted risk becomes a forgotten one.
// They are allowed, and they are findable.
func TestPermanentSuppressionsAreIdentifiable(t *testing.T) {
	if !(Suppression{}).Permanent() {
		t.Error("a suppression with no expiry did not report itself permanent")
	}
	if (Suppression{ExpiresAt: "2030-01-01T00:00:00Z"}).Permanent() {
		t.Error("a time-boxed suppression reported itself permanent")
	}
}

func TestSuppressionsSurviveARestart(t *testing.T) {
	dir := t.TempDir() + "/config.json"
	first, _ := Open(dir)
	added, err := first.AddSuppression(Suppression{
		FindingID: "TESS-PICKLE-003", Reason: "accepted"})
	if err != nil {
		t.Fatal(err)
	}

	second, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := second.Suppressions()
	if len(got) != 1 || got[0].ID != added.ID {
		t.Errorf("suppressions did not survive a reopen: %v", got)
	}

	if err := second.RemoveSuppression(added.ID); err != nil {
		t.Fatal(err)
	}
	if len(second.Suppressions()) != 0 {
		t.Error("removing a suppression left it in place")
	}
}
