package web

import (
	"errors"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera"
	"github.com/DAVANO-INNOVATION-LAB/tessera/studio/internal/harden"
)

// Hardening over HTTP: propose, then apply to a copy, then prove it.
//
// Plan and apply are separate requests on purpose. A single endpoint that
// analysed and remediated in one call would be a button that changed files
// somebody had not seen a list of, and the list is the part that makes this
// safe to offer at all.

func (s *Server) handleHardenPlan(w http.ResponseWriter, r *http.Request) {
	target, err := s.resolve(r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := contextWithTimeout(r, 5*time.Minute)
	defer cancel()
	if err := s.acquire(ctx); err != nil {
		return
	}
	defer s.release()

	art, dir, _, err := analyseForHardening(ctx, target)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	writeJSON(w, harden.PlanFor(dir, art))
}

// handleHardenApply writes the hardened copy and re-scans it.
//
// The re-scan is not decoration. Applying a plan proves nothing about the
// result; the findings on the copy are the evidence, and returning them lets a
// reader see what hardening did and did not fix.
func (s *Server) handleHardenApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path        string          `json:"path"`
		Destination string          `json:"destination"`
		Actions     []harden.Action `json:"actions"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, asUserError(err))
		return
	}
	target, err := s.resolve(req.Path)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}

	// The destination is confined to the served root like everything else. A
	// remediation endpoint that wrote anywhere on the host would be a worse
	// hole than any finding it fixed. resolve already judges a path that does
	// not exist yet by its parent, which is what decides where it would land.
	if req.Destination == "" {
		writeErr(w, http.StatusBadRequest,
			userErrf("a destination is required; the original is never modified"))
		return
	}
	// resolve clamps a traversing path back inside the root rather than
	// rejecting it, which is right for reading — "../x" simply names nothing new
	// — but wrong for writing. A caller asking for "../hardened" and getting a
	// directory called "hardened" inside the root has had their request silently
	// changed, and the path they were handed back would not name what was
	// written. Writes say so instead of guessing.
	if req.Destination != path.Clean(req.Destination) || strings.HasPrefix(req.Destination, "..") {
		writeErr(w, http.StatusBadRequest, userErrf(
			"the destination must be a plain path inside the served directory, written without %q or %q",
			"..", "./"))
		return
	}
	dest, err := s.resolve(req.Destination)
	if err != nil {
		writeErr(w, http.StatusBadRequest, asUserError(err))
		return
	}

	ctx, cancel := contextWithTimeout(r, 10*time.Minute)
	defer cancel()
	if err := s.acquire(ctx); err != nil {
		return
	}
	defer s.release()

	art, dir, _, err := analyseForHardening(ctx, target)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	before := len(art.Findings)

	res, err := harden.Apply(dir, dest, harden.Plan{Actions: req.Actions})
	if err != nil {
		writeErr(w, http.StatusBadRequest, asUserError(err))
		return
	}

	// Re-scan the copy. If this fails the hardening still happened, so the
	// error is reported without pretending the copy does not exist.
	//
	// The verdict matters more than the count. Two findings fewer is a number;
	// Quarantined becoming Approved is the answer to whether this model can now
	// be deployed, which is the only reason anybody pressed the button. It runs
	// through the same gate as the analysis view, so opening the copy afterwards
	// cannot show a different word.
	after, _, parsed, err := analyseForHardening(ctx, dest)
	if err == nil {
		res.Remaining = after.Findings
		res.After = len(after.Findings)
		res.Verdict = string(gateFor(req.Destination, after, parsed).Verdict)
	}
	res.Before = before

	// The destination goes back as the caller expressed it, not as the host
	// stores it. Every other path in this interface is relative to the served
	// root — and resolve rejects an absolute path outright, so returning one
	// would hand the UI a value it cannot use to open what it just created.
	res.Destination = req.Destination
	writeJSON(w, res)
}

// analyseForHardening parses the artifact and walks its directory, returning
// both the findings and the directory the plan applies to.
func analyseForHardening(ctx contextLike, target string) (*tessera.Artifact, string, int, error) {
	dir := target
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		dir = filepath.Dir(target)
	}

	art, err := tessera.Analyze(ctx, target)
	if err != nil {
		// A directory with no parseable model still gets hardened: it is
		// exactly the PyTorch-pickle layout where removing the dangerous file
		// matters most.
		if !isUnrecognized(err) {
			return nil, "", 0, err
		}
		art = &tessera.Artifact{}
	}
	parsed := len(art.Findings)
	rep, werr := tessera.Inspect(ctx, dir)
	if werr == nil {
		art.Findings = append(art.Findings, rep.Findings...)
	}
	return art, dir, parsed, nil
}

// contextLike is the slice of context the analysis needs, kept narrow so this
// file does not import context solely for a parameter type.
type contextLike = interface {
	Deadline() (time.Time, bool)
	Done() <-chan struct{}
	Err() error
	Value(any) any
}

func isUnrecognized(err error) bool {
	return err != nil && errors.Is(err, tessera.ErrUnrecognized)
}
