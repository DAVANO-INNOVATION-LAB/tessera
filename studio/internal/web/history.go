package web

import (
	"fmt"
	"net/http"

	"github.com/DAVANO-INNOVATION-LAB/tessera"
	"github.com/DAVANO-INNOVATION-LAB/tessera/studio/internal/store"
)

// The inventory, history, cross-model search and diff — all of which exist only
// because scan results are kept.

func (s *Server) requireHistory(w http.ResponseWriter) bool {
	if s.History == nil {
		writeErr(w, http.StatusServiceUnavailable,
			fmt.Errorf("no scan history: start with --config to keep results"))
		return false
	}
	return true
}

// handleAssets is the view a security engineer opens the tool expecting: every
// artifact seen, worst first, with first-seen and last-seen.
func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if !s.requireHistory(w) {
		return
	}
	assets := s.History.Assets()
	totals := map[string]int{}
	for _, a := range assets {
		for sev, n := range a.Counts {
			totals[sev] += n
		}
	}
	writeJSON(w, map[string]any{
		"assets":     assets,
		"totals":     totals,
		"scans":      len(s.History.Scans()),
		"historyDir": s.History.Dir(),
	})
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	if !s.requireHistory(w) {
		return
	}
	if d := r.URL.Query().Get("digest"); d != "" {
		writeJSON(w, map[string]any{"scans": s.History.For(d)})
		return
	}
	writeJSON(w, map[string]any{"scans": s.History.Scans()})
}

// handleSearch answers the query the per-model filter cannot: which of my
// models has a critical pickle.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	if !s.requireHistory(w) {
		return
	}
	results := s.History.Search(r.URL.Query().Get("q"), r.URL.Query().Get("severity"))
	writeJSON(w, map[string]any{"results": results, "count": len(results)})
}

func (s *Server) handleCompare(w http.ResponseWriter, r *http.Request) {
	if !s.requireHistory(w) {
		return
	}
	d, err := s.History.Compare(r.URL.Query().Get("from"), r.URL.Query().Get("to"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, d)
}

// recordScan turns an analysed artifact into a history entry.
//
// The taxonomy is resolved here rather than at read time, so a record stays
// searchable by CWE even if the mapping table later changes — a historical
// record should say what was believed when it was written.
func recordScan(h *store.History, target string, art *tessera.Artifact,
	verdict tessera.GateResult, truncated bool) (store.ScanRecord, error) {
	if h == nil {
		return store.ScanRecord{}, nil
	}
	fs := make([]store.FindingRecord, 0, len(art.Findings))
	for _, f := range art.Findings {
		rec := store.FindingRecord{
			ID: f.ID, Severity: f.Severity, Title: f.Title,
			Category: f.Category, Location: f.Location,
		}
		if c, ok := tessera.Classify(f.ID); ok {
			rec.CWE, rec.ATLAS = c.CWE, c.ATLAS
		}
		fs = append(fs, rec)
	}
	return h.Record(store.ScanRecord{
		Target:    target,
		ModelName: art.Identity.Name,
		Format:    string(art.Format),
		Digest:    art.PrimaryFile().SHA256,
		Verdict:   verdict.Verdict,
		RiskScore: verdict.RiskScore,
		Worst:     tessera.Worst(art.Findings),
		Findings:  fs,
		Truncated: truncated,
	})
}
