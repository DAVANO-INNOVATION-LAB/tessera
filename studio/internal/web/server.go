// Package web serves Tessera Studio: a local, single-page interface over the
// tessera analyser.
//
// The server is deliberately small and local-only. It binds to the loopback
// interface, holds no state between requests, and stores nothing — an analysis
// is performed and returned, never queued or persisted. That keeps the app in
// the same trust posture as the library it wraps: a person inspecting an
// untrusted artifact on their own machine.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/DAVANO-INNOVATION-LAB/tessera/studio/internal/store"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tessera "github.com/DAVANO-INNOVATION-LAB/tessera"
)

//go:embed ui.html
var assets embed.FS

// maxConcurrentAnalyses bounds how many analyses run at once. Each one hashes
// every file of a model, which for a real model is gigabytes of I/O, and the
// endpoints are unauthenticated by design — so without a bound a handful of
// requests can saturate the machine.
const maxConcurrentAnalyses = 2

// Server serves the UI and the analysis endpoints.
type Server struct {
	// Root confines every analysis to this directory. A path outside it is
	// refused. The UI is a convenience over a security tool, so it must not
	// become a way to read arbitrary files off the host through a browser.
	Root    string
	Version string

	// Auth is how a request proves who it is. The zero value means none, which
	// is only permitted on a loopback bind — see Auth.CheckBind.
	Auth Auth

	// Store persists connections and settings. Nil means the interface runs
	// without configuration, which is the right default for a one-off scan.
	Store *store.Store

	// History keeps scan results. Nil means nothing is kept, and every question
	// that needs yesterday's answer becomes unanswerable — see internal/store.
	History *store.History

	// slots limits concurrent analyses; created lazily on first use.
	slotsOnce sync.Once
	slots     chan struct{}
}

// acquire takes an analysis slot, or reports that the caller went away first.
func (s *Server) acquire(ctx context.Context) error {
	s.slotsOnce.Do(func() { s.slots = make(chan struct{}, maxConcurrentAnalyses) })
	select {
	case s.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) release() { <-s.slots }

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /api/browse", s.handleBrowse)
	mux.HandleFunc("GET /api/analyze", s.handleAnalyze)
	mux.HandleFunc("GET /api/bom", s.handleBOM)
	mux.HandleFunc("GET /api/coverage", s.handleCoverage)
	mux.HandleFunc("GET /api/whoami", s.handleWhoAmI)

	// Configuration. Every one of these sits inside the authenticated mux: an
	// anonymous caller must not be able to read connection endpoints, still
	// less disable sign-in.
	// Methods are explicit: a methodless pattern is broader than "GET /" and
	// Go's mux refuses the pair rather than guessing which wins.
	mux.HandleFunc("GET /api/connections", s.handleConnections)
	mux.HandleFunc("POST /api/connections", s.handleConnections)
	mux.HandleFunc("DELETE /api/connections/{id}", s.handleConnection)
	mux.HandleFunc("DELETE /api/connections/{id}/secret", s.handleConnectionSecret)
	mux.HandleFunc("POST /api/connections/{id}/test", s.handleConnectionTest)
	mux.HandleFunc("GET /api/settings/auth", s.handleAuthSettings)
	mux.HandleFunc("PUT /api/settings/auth", s.handleAuthSettings)
	mux.HandleFunc("GET /api/harden/plan", s.handleHardenPlan)
	mux.HandleFunc("POST /api/harden/apply", s.handleHardenApply)
	mux.HandleFunc("GET /api/lineage", s.handleLineage)
	mux.HandleFunc("GET /api/taxonomy", s.handleTaxonomy)
	mux.HandleFunc("GET /api/suppressions", s.handleSuppressions)
	mux.HandleFunc("POST /api/suppressions", s.handleSuppressions)
	mux.HandleFunc("DELETE /api/suppressions/{id}", s.handleSuppression)
	mux.HandleFunc("GET /api/assets", s.handleAssets)
	mux.HandleFunc("GET /api/scans", s.handleScans)
	mux.HandleFunc("GET /api/search", s.handleSearch)
	mux.HandleFunc("GET /api/compare", s.handleCompare)
	mux.HandleFunc("GET /api/snapshot", s.handleSnapshot)
	mux.HandleFunc("POST /api/restore", s.handleRestore)

	// The sign-in endpoints sit outside the authentication wrapper: requiring
	// a session to reach the page that establishes one is a loop.
	outer := http.NewServeMux()
	outer.Handle("/auth/callback", http.HandlerFunc(s.handleCallback))
	outer.Handle("/auth/logout", http.HandlerFunc(s.handleLogout))
	outer.Handle("/", s.require(mux))

	return s.checkHost(securityHeaders(outer))
}

// AllowedHosts, when non-empty, replaces the default loopback-only host check.
// Set it when serving on a routable address, which is also when you should be
// thinking about who else can reach the port.
var AllowedHosts []string

// checkHost rejects requests whose Host header is not a loopback name.
//
// Binding to 127.0.0.1 keeps other machines out, but it is not a boundary
// against the user's own browser: a page they visit can point a hostname at
// 127.0.0.1, and the browser will then treat this server as same-origin and let
// that page read the responses. That is DNS rebinding, and against this server
// it would disclose the model directory listing, model identities, and the
// SHA-256 of every private artifact. Checking Host closes it, because the
// attacker's page cannot forge a loopback Host header.
func (s *Server) checkHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")

		ok := host == "127.0.0.1" || host == "::1" || host == "localhost"
		for _, allowed := range AllowedHosts {
			if strings.EqualFold(host, allowed) {
				ok = true
			}
		}
		if !ok {
			http.Error(w, "unrecognised Host header", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The page is self-contained, so it needs nothing from anywhere else.
		// frame-ancestors, base-uri and form-action are named explicitly because
		// none of them fall back to default-src.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "+
				"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := assets.ReadFile("ui.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

// resolve confines a user-supplied path to Root and reports the absolute path.
func (s *Server) resolve(rel string) (string, error) {
	root, err := filepath.Abs(s.Root)
	if err != nil {
		return "", err
	}
	// Reject absolute input outright; everything is relative to Root.
	if rel != "" && rel != "." && filepath.IsAbs(rel) {
		return "", fmt.Errorf("path must be relative to the served directory")
	}
	// Every path, including the root itself, goes through the same resolution
	// below. Returning the root early would hand back an unresolved path on any
	// system where the temporary or home directory is itself a symlink, so the
	// value callers get would differ in form depending on the input.
	full := filepath.Join(root, filepath.Clean("/"+rel))
	if full != root && !strings.HasPrefix(full, root+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes the served directory")
	}

	// The lexical check above cannot see a symlink. A link created inside the
	// served directory that points at / would pass it and then let the browser
	// walk the whole filesystem, so containment is confirmed again after
	// resolving both ends.
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("served directory is not resolvable")
	}
	fullReal, err := filepath.EvalSymlinks(full)
	if err != nil {
		// A path that does not exist yet cannot be resolved; judge its parent,
		// which is what decides where it would land.
		parent, perr := filepath.EvalSymlinks(filepath.Dir(full))
		if perr != nil {
			return "", fmt.Errorf("path is not resolvable")
		}
		fullReal = filepath.Join(parent, filepath.Base(full))
	}
	if fullReal != rootReal && !strings.HasPrefix(fullReal, rootReal+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes the served directory")
	}
	return fullReal, nil
}

type browseEntry struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	IsDir  bool   `json:"isDir"`
	Format string `json:"format,omitempty"`
	Size   int64  `json:"size,omitempty"`
}

// handleBrowse lists the served directory so the UI can offer what is there,
// marking which entries tessera recognizes as models.
func (s *Server) handleBrowse(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	dir, err := s.resolve(rel)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}

	entries, err := readDirSorted(dir)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}

	out := make([]browseEntry, 0, len(entries))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		childRel := filepath.Join(rel, e.Name())
		be := browseEntry{Name: e.Name(), Path: filepath.ToSlash(childRel), IsDir: e.IsDir()}
		if !e.IsDir() {
			if info, err := e.Info(); err == nil {
				be.Size = info.Size()
			}
			if f, ok := tessera.Detect(filepath.Join(dir, e.Name())); ok {
				be.Format = string(f)
			}
		}
		out = append(out, be)
	}
	writeJSON(w, map[string]any{"path": filepath.ToSlash(rel), "entries": out})
}

// handleAnalyze runs an analysis and returns the full artifact.
func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	target, err := s.resolve(r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	if err := s.acquire(ctx); err != nil {
		return // the client disconnected while queued
	}
	defer s.release()

	art, err := tessera.Analyze(ctx, target)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}

	// The walk is part of an analysis here rather than a separate request. The
	// formats this tool parses natively cannot carry code; what can is sitting
	// beside them, and a result that showed only the model would be reassuring
	// about the wrong file.
	parsed := len(art.Findings)
	truncated := false
	if r.URL.Query().Get("deep") != "0" {
		if rep, err := tessera.Inspect(ctx, walkRoot(target)); err == nil {
			art.Findings = mergeFindings(art.Findings, rep.Findings)
			truncated = rep.Truncated
		}
	}
	walked := art.Findings[min(parsed, len(art.Findings)):]

	verdict := gateFor(r.URL.Query().Get("path"), art, parsed)
	_ = walked

	// Kept before the response is written, so a result a user saw is a result
	// the history has. Recording after would leave a window where the two
	// disagree, and history that occasionally misses a scan is worse than none
	// — it looks complete.
	var scanID string
	if rec, err := recordScan(s.History, r.URL.Query().Get("path"), art, verdict, truncated, nil); err == nil {
		scanID = rec.ID
	}

	// Suppressions are applied to the response, never to the record. The scan
	// history above already holds every finding exactly as it was found, so an
	// audit can reconstruct what the tool actually saw regardless of what
	// somebody later accepted.
	suppressed := 0
	if s.Store != nil {
		var keep []tessera.Finding
		sups := s.Store.Suppressions()
		digest := art.PrimaryFile().SHA256
		nowT := time.Now()
		for _, f := range art.Findings {
			hidden := false
			for _, sup := range sups {
				if sup.Matches(f.ID, f.Location, digest, nowT) {
					hidden = true
					break
				}
			}
			if hidden {
				suppressed++
				continue
			}
			keep = append(keep, f)
		}
		art.Findings = keep
	}

	writeJSON(w, map[string]any{
		"artifact":  art,
		"worst":     tessera.Worst(art.Findings),
		"verdict":   verdict,
		"hardened":  s.hardenedLabelFor(walkRoot(target), r.URL.Query().Get("path"), art.PrimaryFile().SHA256),
		"truncated": truncated,
		"deep":      r.URL.Query().Get("deep") != "0",
		"scanId":    scanID,
		// Counted, never silently dropped: a finding that vanishes without
		// trace is how an accepted risk becomes an invisible one.
		"suppressed": suppressed,
	})
}

// mergeFindings appends the walk's findings, dropping any the parse already
// reported for the same place. The overlap is deliberate — the parser reads a
// safetensors header to describe the model and the walker reads it again
// because it cannot assume the parser ran — so without this one defect would be
// counted twice and the artifact would score worse for no reason.
func mergeFindings(parsed, walked []tessera.Finding) []tessera.Finding {
	seen := make(map[string]bool, len(parsed))
	for _, f := range parsed {
		seen[f.ID+"\x00"+f.Location] = true
	}
	for _, f := range walked {
		key := f.ID + "\x00" + f.Location
		if seen[key] {
			continue
		}
		seen[key] = true
		parsed = append(parsed, f)
	}
	return parsed
}

// tally counts findings by severity, drift separately, because the gate treats
// drift separately.
func tally(findings []tessera.Finding, driftOnly bool) tessera.SeverityCounts {
	var c tessera.SeverityCounts
	for _, f := range findings {
		if (f.Category == "drift") != driftOnly {
			continue
		}
		switch f.Severity {
		case tessera.SeverityCritical:
			c.Critical++
		case tessera.SeverityHigh:
			c.High++
		case tessera.SeverityMedium:
			c.Medium++
		case tessera.SeverityLow:
			c.Low++
		default:
			c.Unknown++
		}
	}
	return c
}

func boolPtr(b bool) *bool { return &b }

// handleCoverage reports how far a model goes toward a published
// minimum-elements standard.
//
// This is the view a regulated buyer actually wants, and it is the one that has
// to be honest: the elements no static parse can supply are shown alongside the
// ones it fills, with their reasons, rather than being quietly dropped to
// flatter the total.
func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request) {
	target, err := s.resolve(r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	standard := r.URL.Query().Get("standard")
	if standard == "" {
		standard = "g7"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	if err := s.acquire(ctx); err != nil {
		return
	}
	defer s.release()

	rep, err := tessera.Coverage(ctx, standard, target)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	writeJSON(w, rep)
}

// handleBOM returns a rendered bill of materials as a download.
func (s *Server) handleBOM(w http.ResponseWriter, r *http.Request) {
	target, err := s.resolve(r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	format := r.URL.Query().Get("format")

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	if err := s.acquire(ctx); err != nil {
		return
	}
	defer s.release()

	art, err := tessera.Analyze(ctx, target)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}

	// Reproducible by construction: the BOM is stamped from the artifact's own
	// bytes, not the wall clock, so downloading twice yields the same document.
	at := time.Unix(0, 0).UTC()
	if info, err := statFile(target); err == nil {
		at = info.ModTime()
	}

	var (
		data []byte
		ext  string
	)
	switch format {
	case "spdx":
		data, err = tessera.SPDX(art, at)
		ext = ".spdx.json"
	case "sarif":
		data, err = tessera.SARIF(art, at)
		ext = ".sarif.json"
	case "cyclonedx-1.7":
		data, err = tessera.CycloneDXVersion(art, at, tessera.CycloneDX17)
		ext = ".cdx.json"
	default:
		data, err = tessera.CycloneDX(art, at)
		ext = ".cdx.json"
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	name := sanitize(art.Identity.Name) + ext
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	w.Write(data)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// writeErr reports a failure without echoing the underlying error.
//
// The errors that reach here are os.PathError values carrying the absolute path
// of the served directory, which would tell a browser the host's username and
// directory layout — exactly the reconnaissance an attacker wants before aiming
// a traversal. The client gets the category; the detail stays on this side.
func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	// Errors from the filesystem and the network are replaced with a canned
	// message, because their text carries host paths, internal hostnames and
	// occasionally credentials embedded in a proxy URL.
	//
	// Errors this server authored about the request itself are surfaced
	// verbatim. That distinction did not matter while every endpoint took a
	// path; it matters now that the API accepts configuration, because
	// "a suppression needs a reason" arriving as "path is not valid for this
	// server" is both wrong and impossible to act on.
	if ue, ok := err.(userError); ok {
		writeJSONStatus(w, map[string]any{"error": ue.Error()})
		return
	}

	msg := "request failed"
	switch code {
	case http.StatusBadRequest:
		msg = "path is not valid for this server"
	case http.StatusUnprocessableEntity:
		msg = "not a recognised model file"
	case http.StatusNotFound:
		msg = "not found"
	}
	_ = err // host detail deliberately not surfaced
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "model"
	}
	return out
}

// handleWhoAmI lets the interface show who is signed in, and lets a script
// check whether its token works without performing a scan to find out.
func (s *Server) handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"authenticated": true,
		"mode":          "none",
	}
	switch {
	case s.Auth.OIDC != nil:
		out["mode"] = "oidc"
		if c, err := r.Cookie(sessionCookie); err == nil {
			if v, ok := s.Auth.OIDC.sessions.Load(c.Value); ok {
				sess := v.(session)
				out["email"] = sess.Email
				out["name"] = sess.Name
				out["expires"] = sess.Expires.UTC().Format(time.RFC3339)
			}
		}
	case s.Auth.Token != "":
		out["mode"] = "token"
	}
	writeJSON(w, out)
}

// userError marks an error as safe to show the caller: it describes the request
// rather than the host. Anything not wrapped this way is replaced with a canned
// message on the way out.
type userError struct{ error }

// userErrf builds one.
func userErrf(format string, a ...any) error {
	return userError{fmt.Errorf(format, a...)}
}

// asUserError marks an existing error as safe to surface. Used where a lower
// layer already produced a message written for a person — the store's
// validation, for instance.
func asUserError(err error) error {
	if err == nil {
		return nil
	}
	return userError{err}
}

// writeJSONStatus writes a body after the status has already been set.
func writeJSONStatus(w http.ResponseWriter, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// walkRoot is the directory the deep walk should cover.
//
// filepath.Dir on a directory returns its *parent*, so passing it here made a
// scan of one model directory walk every sibling — and attribute their findings
// to the model being viewed. A hardened copy came back carrying the pickle from
// the original next to it, which is the worst possible way for this to be wrong:
// remediation appearing not to work when it had.
func walkRoot(target string) string {
	if info, err := os.Stat(target); err == nil && info.IsDir() {
		return target
	}
	return filepath.Dir(target)
}

// gateFor runs the policy gate over an analysed artifact.
//
// Extracted so the verdict shown on a hardened copy is produced by the same
// code as the verdict shown when that copy is opened. Two call sites computing
// a verdict separately would eventually disagree, and "Approved" here followed
// by "Quarantined" one click later destroys trust in both numbers.
//
// parsed is how many of the findings came from the model file itself; the rest
// came from walking the directory beside it, and the gate weighs the two
// differently.
func gateFor(uri string, art *tessera.Artifact, parsed int) tessera.GateResult {
	if parsed > len(art.Findings) {
		parsed = len(art.Findings)
	}
	self, walked := art.Findings[:parsed], art.Findings[parsed:]
	results := []tessera.ScannerResult{{
		Scanner:    "tessera",
		Status:     tessera.ScannerStatusFor(len(self)),
		Findings:   int32(len(self)),
		Severities: tally(self, false),
		Drift:      tally(self, true),
		Produced:   boolPtr(true),
	}, {
		Scanner:    "model-inspector",
		Status:     tessera.ScannerStatusFor(len(walked)),
		Findings:   int32(len(walked)),
		Severities: tally(walked, false),
	}}
	return tessera.Gate(results, tessera.GateArtifact{
		URI:    uri,
		Digest: art.PrimaryFile().SHA256,
		Format: string(art.Format),
	}, nil, nil, time.Now())
}
