package web

import (
	"net/http"

	"github.com/DAVANO-INNOVATION-LAB/tessera"
	"github.com/DAVANO-INNOVATION-LAB/tessera/studio/internal/store"
)

// The inventory, history, cross-model search and diff — all of which exist only
// because scan results are kept.

func (s *Server) requireHistory(w http.ResponseWriter) bool {
	if s.History == nil {
		writeErr(w, http.StatusServiceUnavailable, userErrf("no scan history: start with --config to keep results"))
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
		writeErr(w, http.StatusBadRequest, asUserError(err))
		return
	}
	writeJSON(w, d)
}

// recordScan turns an analysed artifact into a history entry.
//
// The taxonomy is resolved here rather than at read time, so a record stays
// searchable by CWE even if the mapping table later changes — a historical
// record should say what was believed when it was written.
// derivation marks a scan as the result of hardening another artifact. Passed
// in at the point of writing rather than patched on afterwards, so a record is
// never briefly on disk claiming to be an ordinary scan of a derived copy.
type derivation struct {
	From       string
	FromTarget string
}

func recordScan(h *store.History, target string, art *tessera.Artifact,
	verdict tessera.GateResult, truncated bool, der *derivation) (store.ScanRecord, error) {
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
		Hardened:  der != nil,
		DerivedFrom: func() string {
			if der != nil {
				return der.From
			}
			return ""
		}(),
		DerivedFromTarget: func() string {
			if der != nil {
				return der.FromTarget
			}
			return ""
		}(),
	})
}

// Suppressions: accepted findings, and the endpoints that manage them.

func (s *Server) handleSuppressions(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, userErrf("no configuration store: start with --config to accept findings"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		sups := s.Store.Suppressions()
		permanent := 0
		for _, x := range sups {
			if x.Permanent() {
				permanent++
			}
		}
		writeJSON(w, map[string]any{
			"suppressions": sups,
			// Surfaced rather than buried: a waiver that never expires is how an
			// accepted risk becomes a forgotten one.
			"permanent": permanent,
		})
	case http.MethodPost:
		var in store.Suppression
		if err := decodeBody(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, asUserError(err))
			return
		}
		// Attribution comes from the session rather than the request body, so
		// nobody can accept a risk in somebody else's name.
		in.By = s.currentUser(r)
		out, err := s.Store.AddSuppression(in)
		if err != nil {
			writeErr(w, http.StatusBadRequest, asUserError(err))
			return
		}
		writeJSON(w, out)
	default:
		writeErr(w, http.StatusMethodNotAllowed, userErrf("method not allowed"))
	}
}

func (s *Server) handleSuppression(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, userErrf("no configuration store"))
		return
	}
	if err := s.Store.RemoveSuppression(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, asUserError(err))
		return
	}
	writeJSON(w, map[string]any{"removed": true})
}

// currentUser is who to attribute an acceptance to. Empty when no identity is
// available, which is itself worth seeing in a review rather than papering over
// with a placeholder like "admin".
func (s *Server) currentUser(r *http.Request) string {
	if s.Auth.OIDC == nil {
		return ""
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	v, ok := s.Auth.OIDC.sessions.Load(c.Value)
	if !ok {
		return ""
	}
	return v.(session).Email
}

// handleTaxonomy hands the interface the CWE and ATLAS table once, so every
// finding can be labelled without a lookup per finding.
//
// Served whether or not a store is configured: the mapping is a property of the
// tool, not of anyone's deployment.
func (s *Server) handleTaxonomy(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	for _, id := range tessera.FindingIDs() {
		c, ok := tessera.Classify(id)
		if !ok {
			continue
		}
		out[id] = map[string]string{
			"cwe": c.CWE, "cweName": c.CWEName,
			"atlas": c.ATLAS, "atlasName": c.ATLASName,
		}
	}
	writeJSON(w, out)
}
