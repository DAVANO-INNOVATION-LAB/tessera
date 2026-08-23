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

	art, dir, parsedBefore, err := analyseForHardening(ctx, target)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	before := len(art.Findings)

	// The record written into the copy describes the source as it was at this
	// moment: its digest, what it scanned as, and — if it was itself a hardened
	// copy — the link one step further back.
	parent, _ := harden.ReadProvenance(dir)
	prov := &harden.Provenance{
		Tool: "tessera-studio " + s.Version,
		Source: harden.SourceOf(req.Path, art.PrimaryFile().SHA256,
			art.Identity.Name, string(art.Format),
			string(gateFor(req.Path, art, parsedBefore).Verdict), parent),
		FindingsBefore: before,
	}

	res, err := harden.Apply(dir, dest, harden.Plan{Actions: req.Actions}, prov)
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
		verdict := gateFor(req.Destination, after, parsed)
		res.Verdict = string(verdict.Verdict)

		// The count is only known now, so the record on disk is completed.
		prov.FindingsAfter = res.After
		if werr := harden.WriteProvenance(dest, *prov); werr == nil {
			res.Provenance = prov
		}

		// The scan of the copy is recorded as a derivative. This — not the file
		// in the directory — is what makes the "hardened" label mean anything:
		// it is written by the server, at the moment it did the work, and it
		// cannot be produced by writing a file into a directory.
		recordScan(s.History, req.Destination, after, verdict, false, &derivation{
			From: prov.Source.Digest, FromTarget: prov.Source.Path,
		})
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

// HardenedLabel is what the interface shows about an artifact's derivation.
//
// The two booleans are the whole point of this type, and collapsing them into
// one would be the bug. A hardening record is a file in a directory: this tool
// writes one, and so can anybody else. Treating that file as proof would mean a
// "hardened" badge could be minted for an untouched model by writing a JSON
// file beside it — laundering the exact artifact the badge is supposed to
// vouch against.
//
// So the file supplies the *detail* (what was removed, when, from what), and
// the server's own scan history supplies the *fact*. Where they agree, the
// label is verified. Where only the file is present, it is shown as a claim,
// attributed to the file, and the interface says so plainly rather than
// rendering the same badge with a footnote nobody reads.
type HardenedLabel struct {
	// Claimed is true when the artifact carries a hardening record.
	Claimed bool `json:"claimed"`
	// Verified is true when this server's history records having produced it.
	Verified bool `json:"verified"`
	// Source is the artifact this was derived from, from whichever side is
	// authoritative: history when verified, the file when only claimed.
	Source *harden.ProvenanceSource `json:"source,omitempty"`
	// Applied is the change list from the record, if it has one.
	Applied []harden.Action `json:"applied,omitempty"`
	// HardenedAt is when the record says the copy was written.
	HardenedAt string `json:"hardenedAt,omitempty"`
	// Note explains an unverified claim, so the interface does not have to
	// invent the wording.
	Note string `json:"note,omitempty"`
}

// hardenedLabelFor decides what to say about an artifact's derivation.
func (s *Server) hardenedLabelFor(dir, target, digest string) *HardenedLabel {
	prov, hasFile := harden.ReadProvenance(dir)

	// History is consulted by digest **and** location.
	//
	// Digest alone is wrong here, and wrong in the direction that matters.
	// Hardening usually removes a file beside the model rather than the model
	// itself, so the copy carries the same primary digest as its source — and a
	// digest-only lookup would find the copy's record while looking at the
	// original and stamp the untouched, still-dangerous artifact "hardened".
	// Read from the inventory rather than the raw scans, because the inventory
	// latches the derivation. Only the scan taken immediately after hardening
	// carries it; every later scan of that copy is an ordinary scan and says
	// nothing about where it came from. Asking the raw records would mean a
	// model stopped being hardened the moment somebody looked at it again.
	verified := false
	var histSource *harden.ProvenanceSource
	if s.History != nil && digest != "" {
		for _, a := range s.History.Assets() {
			if a.Digest == digest && a.Target == target && a.Hardened {
				verified = true
				histSource = &harden.ProvenanceSource{
					Digest: a.DerivedFrom, Path: a.DerivedFromTarget,
				}
				break
			}
		}
	}
	if !hasFile && !verified {
		return nil
	}

	label := &HardenedLabel{Claimed: hasFile, Verified: verified}
	switch {
	case verified && hasFile:
		label.Source = &prov.Source
		label.Applied = prov.Applied
		label.HardenedAt = prov.HardenedAt
		// The record could still name a different origin than the one this
		// server remembers. Saying so beats presenting either as settled.
		if histSource != nil && histSource.Digest != "" &&
			prov.Source.Digest != "" && histSource.Digest != prov.Source.Digest {
			label.Note = "the record in this directory names a different source " +
				"than this server's history does; the history is authoritative"
		}
	case verified:
		label.Source = histSource
		label.Note = "hardened by this server; the record inside the copy is missing"
	default:
		label.Source = &prov.Source
		label.Applied = prov.Applied
		label.HardenedAt = prov.HardenedAt
		label.Note = "this is a claim made by a file in the directory, not something " +
			"this server did; treat it as unverified"
	}
	return label
}

// handleLineage returns the derivation chain around one artifact.
func (s *Server) handleLineage(w http.ResponseWriter, r *http.Request) {
	if s.History == nil {
		writeErr(w, http.StatusServiceUnavailable,
			userErrf("no scan history: start with --config to record lineage"))
		return
	}
	digest, path := r.URL.Query().Get("digest"), r.URL.Query().Get("path")
	if digest == "" || path == "" {
		// Both, and the reason is worth stating: hardening usually leaves the
		// model file untouched, so a copy and its source share a digest. Asked
		// for a digest alone this could only guess which end of the chain was
		// meant, and guessing would draw somebody a lineage for the wrong
		// artifact.
		writeErr(w, http.StatusBadRequest, userErrf(
			"a digest and a path are both required: a hardened copy can share "+
				"its source's digest, so the pair is what identifies one artifact"))
		return
	}
	writeJSON(w, s.History.LineageFor(digest, path))
}
