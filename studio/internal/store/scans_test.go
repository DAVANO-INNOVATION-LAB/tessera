package store

import (
	"path/filepath"
	"testing"
)

func hist(t *testing.T) *History {
	t.Helper()
	h, err := OpenHistory(filepath.Join(t.TempDir(), "scans"))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func rec(digest, at string, fs ...FindingRecord) ScanRecord {
	return ScanRecord{
		Target: "/models/x", ModelName: "m", Digest: digest,
		ScannedAt: at, Findings: fs, RiskScore: int32(len(fs) * 10),
	}
}

// The whole point of persistence: yesterday's answer is still there.
func TestScansSurviveAndSortNewestFirst(t *testing.T) {
	h := hist(t)
	h.Record(rec("aa", "2026-08-01T00:00:00Z"))
	h.Record(rec("aa", "2026-08-20T00:00:00Z"))

	got := h.Scans()
	if len(got) != 2 {
		t.Fatalf("kept %d scans, want 2", len(got))
	}
	if got[0].ScannedAt < got[1].ScannedAt {
		t.Error("scans are not newest first; the latest state is what a reader wants")
	}
}

// First-seen is the question every triage conversation opens with. It is
// tracked per deployment — the same digest at the same path over time — because
// that is the thing somebody is actually managing.
func TestAssetsTrackFirstSeenPerDeployment(t *testing.T) {
	h := hist(t)
	h.Record(ScanRecord{Target: "/models/a", Digest: "same", ScannedAt: "2026-08-01T00:00:00Z"})
	h.Record(ScanRecord{Target: "/models/a", Digest: "same", ScannedAt: "2026-08-20T00:00:00Z"})

	assets := h.Assets()
	if len(assets) != 1 {
		t.Fatalf("got %d assets, want 1: two scans of one deployment is one row", len(assets))
	}
	a := assets[0]
	if a.FirstSeen != "2026-08-01T00:00:00Z" {
		t.Errorf("firstSeen = %s, want the earliest scan", a.FirstSeen)
	}
	if a.LastSeen != "2026-08-20T00:00:00Z" {
		t.Errorf("lastSeen = %s, want the latest scan", a.LastSeen)
	}
	if a.ScanCount != 2 {
		t.Errorf("scanCount = %d, want 2", a.ScanCount)
	}
}

// The digest still correlates one artifact across locations, which is what
// makes "where else is this model" answerable even though the inventory lists
// deployments rather than files.
func TestDigestStillCorrelatesAcrossLocations(t *testing.T) {
	h := hist(t)
	h.Record(ScanRecord{Target: "/one", Digest: "shared", ScannedAt: "2026-08-01T00:00:00Z"})
	h.Record(ScanRecord{Target: "/two", Digest: "shared", ScannedAt: "2026-08-02T00:00:00Z"})

	if got := h.For("shared"); len(got) != 2 {
		t.Errorf("For(digest) returned %d scans, want both locations", len(got))
	}
}

// An inventory sorted alphabetically buries the thing that needs attention,
// which is the only reason anybody opened it.
func TestAssetsAreWorstFirst(t *testing.T) {
	h := hist(t)
	h.Record(ScanRecord{Digest: "clean", ScannedAt: "2026-08-20T00:00:00Z", RiskScore: 0})
	h.Record(ScanRecord{Digest: "bad", ScannedAt: "2026-08-20T00:00:00Z", RiskScore: 95})
	h.Record(ScanRecord{Digest: "mid", ScannedAt: "2026-08-20T00:00:00Z", RiskScore: 40})

	got := h.Assets()
	if len(got) != 3 || got[0].Digest != "bad" || got[2].Digest != "clean" {
		t.Errorf("order = %v, want worst risk first", []string{got[0].Digest, got[1].Digest, got[2].Digest})
	}
}

// The query the per-model filter cannot answer.
func TestSearchSpansEveryScan(t *testing.T) {
	h := hist(t)
	h.Record(rec("a", "2026-08-01T00:00:00Z",
		FindingRecord{ID: "TESS-PICKLE-001", Severity: "Critical", Title: "dangerous callable", CWE: "502"}))
	h.Record(rec("b", "2026-08-02T00:00:00Z",
		FindingRecord{ID: "TESS-LIC-001", Severity: "Low", Title: "no licence"}))

	if got := h.Search("pickle", ""); len(got) != 1 {
		t.Errorf("search for pickle across models returned %d, want 1", len(got))
	}
	if got := h.Search("", "Critical"); len(got) != 1 {
		t.Errorf("severity filter returned %d, want 1", len(got))
	}
	// The taxonomy is searchable, which is the point of adding it.
	if got := h.Search("502", ""); len(got) != 1 {
		t.Errorf("search by CWE returned %d, want 1", len(got))
	}
	if got := h.Search("nothing-matches", ""); len(got) != 0 {
		t.Errorf("a miss returned %d results", len(got))
	}
}

// "What changed in v2" — answerable only because both scans were kept.
func TestCompareShowsWhatChanged(t *testing.T) {
	h := hist(t)
	before, _ := h.Record(rec("v1", "2026-08-01T00:00:00Z",
		FindingRecord{ID: "TESS-DRIFT-002", Severity: "High", Location: "config.json"},
		FindingRecord{ID: "TESS-LIC-001", Severity: "Low"}))
	after, _ := h.Record(rec("v2", "2026-08-02T00:00:00Z",
		FindingRecord{ID: "TESS-LIC-001", Severity: "Low"},
		FindingRecord{ID: "TESS-PICKLE-001", Severity: "Critical", Location: "t.pkl"}))

	d, err := h.Compare(before.ID, after.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Added) != 1 || d.Added[0].ID != "TESS-PICKLE-001" {
		t.Errorf("added = %v, want the new pickle finding", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].ID != "TESS-DRIFT-002" {
		t.Errorf("removed = %v, want the resolved drift finding", d.Removed)
	}
	if d.Unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", d.Unchanged)
	}
}

// The same weakness in two files is two findings to fix, so location is part of
// identity. Without it a diff would report "unchanged" for a finding that moved.
func TestDiffTreatsLocationAsPartOfIdentity(t *testing.T) {
	h := hist(t)
	a, _ := h.Record(rec("x", "2026-08-01T00:00:00Z",
		FindingRecord{ID: "TESS-PICKLE-001", Severity: "Critical", Location: "one.pkl"}))
	b, _ := h.Record(rec("x", "2026-08-02T00:00:00Z",
		FindingRecord{ID: "TESS-PICKLE-001", Severity: "Critical", Location: "two.pkl"}))

	d, _ := h.Compare(a.ID, b.ID)
	if d.Unchanged != 0 || len(d.Added) != 1 || len(d.Removed) != 1 {
		t.Errorf("same id in a different file was treated as unchanged: %+v", d)
	}
}

// A nil History is valid and keeps nothing — the no --config case must not
// crash or require a branch at every call site.
func TestNilHistoryIsUsable(t *testing.T) {
	var h *History
	if _, err := h.Record(rec("a", "2026-08-01T00:00:00Z")); err != nil {
		t.Errorf("recording to a nil history errored: %v", err)
	}
	if got := h.Scans(); got != nil {
		t.Error("a nil history returned scans")
	}
	if got := h.Assets(); len(got) != 0 {
		t.Error("a nil history returned assets")
	}
}

func TestCompareRefusesUnknownScans(t *testing.T) {
	h := hist(t)
	if _, err := h.Compare("nope", "also-nope"); err == nil {
		t.Error("comparing scans that do not exist succeeded")
	}
}

// Same bytes in two places are two things to manage. Keying on digest alone
// merged them and produced an inventory row reading "Approved, risk 0" for a
// location that also held a Critical finding — the inventory lying about the
// estate. This is the regression test for that.
func TestSameArtifactInTwoPlacesIsTwoAssets(t *testing.T) {
	h := hist(t)
	h.Record(ScanRecord{
		Target: "/clean/model.gguf", Digest: "same", ScannedAt: "2026-08-20T00:00:00Z",
		RiskScore: 0, Verdict: "Approved"})
	h.Record(ScanRecord{
		Target: "/poisoned/model.gguf", Digest: "same", ScannedAt: "2026-08-20T00:00:01Z",
		RiskScore: 95, Verdict: "Quarantined",
		Findings: []FindingRecord{{ID: "TESS-PICKLE-001", Severity: "Critical"}}})

	assets := h.Assets()
	if len(assets) != 2 {
		t.Fatalf("got %d assets, want 2: the same file beside different neighbours "+
			"is a different risk", len(assets))
	}
	if assets[0].Verdict != "Quarantined" {
		t.Errorf("worst asset is %q; the dangerous location must lead", assets[0].Verdict)
	}
	var sawClean bool
	for _, a := range assets {
		if a.Target == "/clean/model.gguf" && a.RiskScore == 0 {
			sawClean = true
		}
	}
	if !sawClean {
		t.Error("the clean location was lost; both deployments must be visible")
	}
}
