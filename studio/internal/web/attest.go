package web

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera"
	sign "github.com/DAVANO-INNOVATION-LAB/tessera/sign"
	"github.com/DAVANO-INNOVATION-LAB/tessera/studio/internal/store"
)

// Attestation over HTTP: the point where a claim stops being local.
//
// Everything else this server decides is only true inside it. The interface
// refuses to badge an unverified derivation, and the emitters refuse to state
// one structurally — but a document leaving here is just JSON, and a reader
// downstream cannot tell a pedigree this server verified from one somebody
// typed. Signing is what carries the distinction across that boundary.
//
// The output is deliberately identical to what `tessera-sign attest` writes:
// the same record shape from the same package, the document beside it, the same
// `.att.json` suffix. A file produced here must verify with the command-line
// verifier, because the alternative is two formats that drift and a verifier
// that works on half the files it is given.

// handleAttest signs a bill of materials and returns it with its attestation.
func (s *Server) handleAttest(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeErr(w, http.StatusServiceUnavailable,
			userErrf("no configuration store: start with --config to enable signing"))
		return
	}
	cfg := s.Store.SigningConfig()
	if cfg.KeyPath == "" {
		writeErr(w, http.StatusPreconditionFailed, userErrf(
			"no signing key is configured; set one in settings, or generate one with "+
				"tessera-sign keygen"))
		return
	}

	target, err := s.resolve(r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}

	// The key is read from the host path named in configuration, never from
	// anything the request supplies. A signing endpoint that accepted a key
	// location from its caller would sign with whatever a caller could plant.
	keyData, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		// The path is configuration, not user input, but it is still a host
		// path and does not belong in a response.
		writeErr(w, http.StatusInternalServerError,
			userErrf("the configured signing key could not be read"))
		return
	}
	kp, err := sign.ParsePrivate(keyData)
	if err != nil {
		writeErr(w, http.StatusInternalServerError,
			userErrf("the configured signing key is not a valid private key"))
		return
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Minute)
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
	s.attachDerivation(art, walkRoot(target), r.URL.Query().Get("path"))

	// Same reproducibility rule as the plain download: stamped from the
	// artifact's mtime, so attesting twice yields the same document and the
	// same digest, and a filed attestation stays comparable.
	at := time.Unix(0, 0).UTC()
	if info, err := statFile(target); err == nil {
		at = info.ModTime().UTC()
	}

	format := r.URL.Query().Get("format")
	doc, ext, err := renderBOM(art, at, format)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	base := sanitize(art.Identity.Name) + ext
	primary := art.PrimaryFile()
	rec, err := sign.Attest(kp, doc, base, sign.ArtifactRef{
		Path: primary.Path, SHA256: primary.SHA256, Format: string(art.Format),
	}, "tessera-studio", s.Version, time.Now().UTC(), attestedDerivation(art))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	att, err := rec.Marshal()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	// Both files, together. They are useless apart — the attestation pins a
	// digest and the document is what has it — so handing over one at a time
	// would invite exactly the mismatch the digest exists to catch.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []struct {
		name string
		body []byte
	}{{base, doc}, {base + ".att.json", att}} {
		fw, err := zw.Create(f.name)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if _, err := fw.Write(f.body); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	if err := zw.Close(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", sanitize(art.Identity.Name)+"-attested.zip"))
	w.Write(buf.Bytes())
}

// attestedDerivation lifts a verified derivation into the signed payload.
//
// An unverified one is dropped rather than signed, and this is the load-bearing
// line in the file. The rest of the design refuses to *state* an unverified
// claim; signing one would be worse, turning something anybody could have
// written into something carrying this key's name.
func attestedDerivation(art *tessera.Artifact) *sign.AttestedDerivation {
	d := art.Derivation
	if d == nil || d.Unverified {
		return nil
	}
	out := &sign.AttestedDerivation{
		SourceSHA256:  d.Source.SHA256,
		SourcePath:    cmpOr(d.Source.Name, d.Source.Path),
		SourceVerdict: d.Source.Verdict,
	}
	for _, c := range d.Changes {
		out.Changes = append(out.Changes, c.Summary)
		for _, r := range c.Resolves {
			out.Resolves = append(out.Resolves, r.ID)
		}
	}
	return out
}

// handleSigningSettings reads and writes the signing configuration.
func (s *Server) handleSigningSettings(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, userErrf("no configuration store"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg := s.Store.SigningConfig()
		// Whether a key is configured and whether it actually loads are
		// different facts, and reporting only the first sends somebody to debug
		// a download when the problem is a path.
		state := "not configured"
		if cfg.KeyPath != "" {
			if data, err := os.ReadFile(cfg.KeyPath); err != nil {
				state = "configured, but the file cannot be read"
			} else if _, err := sign.ParsePrivate(data); err != nil {
				state = "configured, but the file is not a valid private key"
			} else {
				state = "ready"
			}
		}
		writeJSON(w, map[string]any{
			"keyPath":  cfg.KeyPath,
			"identity": cfg.Identity,
			"state":    state,
		})
	case http.MethodPut:
		var in struct {
			KeyPath  string `json:"keyPath"`
			Identity string `json:"identity"`
		}
		if err := decodeBody(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, asUserError(err))
			return
		}
		if in.KeyPath != "" && !filepath.IsAbs(in.KeyPath) {
			writeErr(w, http.StatusBadRequest, userErrf(
				"the signing key path must be absolute, so it does not depend on where this server was started"))
			return
		}
		if err := s.Store.SetSigning(store.Signing{KeyPath: in.KeyPath, Identity: in.Identity}); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, map[string]any{"saved": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, userErrf("method not allowed"))
	}
}
