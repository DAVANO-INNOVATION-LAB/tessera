package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera"
	sign "github.com/DAVANO-INNOVATION-LAB/tessera/sign"
)

// The attestation format itself now lives in the sign package, so this command
// and the Studio emit the same record and either can verify the other's.
func runAttest(args []string) int {
	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	key := fs.String("key", "", "private key PEM")
	out := fs.String("out", ".", "directory to write documents and attestations into")
	formats := fs.String("format", "cyclonedx,spdx", "documents to attest: cyclonedx, spdx, sarif")
	cdxVersion := fs.String("cyclonedx-version", tessera.CycloneDX16, "CycloneDX spec version: 1.6 or 1.7")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr,
			"Usage: tessera-sign attest <model> --key PRIVATE.pem [--out DIR] [--format cyclonedx,spdx,sarif]")
		fs.PrintDefaults()
	}
	target, err := positional(fs, args)
	if err != nil || *key == "" {
		fs.Usage()
		return exitUsage
	}

	keyData, err := os.ReadFile(*key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
		return exitError
	}
	kp, err := sign.ParsePrivate(keyData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
		return exitError
	}

	art, err := tessera.Analyze(ctxBackground(), target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
		return exitError
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
		return exitError
	}

	// Reproducible by construction: the document is stamped from the artifact's
	// own mtime rather than the wall clock, so attesting the same model twice
	// produces the same bytes and the same digest. An attestation that changed
	// every time it was regenerated could not be compared against a filed one.
	at := time.Unix(0, 0).UTC()
	if info, err := os.Stat(target); err == nil {
		at = info.ModTime().UTC()
	}

	primary := art.PrimaryFile()
	slug := slugOf(art.Identity.Name)
	wrote := 0

	for _, name := range strings.Split(*formats, ",") {
		name = strings.TrimSpace(name)
		var (
			doc []byte
			ext string
		)
		switch name {
		case "cyclonedx":
			doc, err = tessera.CycloneDXVersion(art, at, *cdxVersion)
			ext = ".cdx.json"
		case "spdx":
			doc, err = tessera.SPDX(art, at)
			ext = ".spdx.json"
		case "sarif":
			doc, err = tessera.SARIF(art, at)
			ext = ".sarif.json"
		default:
			fmt.Fprintf(os.Stderr, "tessera-sign: unknown format %q\n", name)
			return exitUsage
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
			return exitError
		}

		docPath := filepath.Join(*out, slug+ext)
		if err := os.WriteFile(docPath, doc, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
			return exitError
		}

		// The signature covers the document bytes. The attestation record binds
		// those bytes to the artifact they describe, and is itself covered
		// because the digests are inside the signed payload.
		rec, err := sign.Attest(kp, doc, filepath.Base(docPath), sign.ArtifactRef{
			Path: primary.Path, SHA256: primary.SHA256, Format: string(art.Format),
		}, "tessera", version, time.Now().UTC(), derivationOf(art))
		if err != nil {
			fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
			return exitError
		}
		enc, err := rec.Marshal()
		if err != nil {
			fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
			return exitError
		}
		attPath := docPath + ".att.json"
		if err := os.WriteFile(attPath, enc, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
			return exitError
		}
		fmt.Fprintf(os.Stderr, "wrote %s and %s\n", docPath, attPath)
		wrote++
	}

	if wrote == 0 {
		fmt.Fprintln(os.Stderr, "tessera-sign: no formats selected")
		return exitUsage
	}
	fmt.Fprintf(os.Stderr, "\nattested %s (%s) with %s\n",
		primary.Path, art.Format, kp.Suite)
	return exitOK
}

// runVerifyAttestation checks both halves: the signature, and whether the
// document still describes the artifact.
//
// Order matters. The signature is checked first because it establishes that the
// document is the one the signer produced; re-deriving claims from a document of
// unknown origin would be checking an unknown against the bytes.
func runVerifyAttestation(args []string) int {
	fs := flag.NewFlagSet("verify-attestation", flag.ContinueOnError)
	pub := fs.String("public", "", "public key PEM")
	artifact := fs.String("artifact", "", "the model the document claims to describe")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr,
			"Usage: tessera-sign verify-attestation <document.att.json> --public PUBLIC.pem --artifact PATH")
		fs.PrintDefaults()
	}
	attPath, err := positional(fs, args)
	if err != nil || *pub == "" {
		fs.Usage()
		return exitUsage
	}

	raw, err := os.ReadFile(attPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
		return exitError
	}
	rec, err := sign.ParseAttestation(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
		return exitUnverified
	}

	docPath := filepath.Join(filepath.Dir(attPath), rec.Document)
	doc, err := os.ReadFile(docPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
		return exitError
	}

	pubData, err := os.ReadFile(*pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
		return exitError
	}
	// The expected keys come from the file the verifier named, never from the
	// attestation. Trusting a key that travels inside the thing being verified
	// verifies nothing.
	pq, ec, err := sign.ParsePublic(pubData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
		return exitError
	}
	if err := rec.VerifyDocument(doc, pq, ec); err != nil {
		fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
		return exitUnverified
	}
	fmt.Fprintf(os.Stderr, "signature verified (%s), signed %s\n",
		rec.Signature.Suite, rec.AttestedAt)

	// A signed derivation is a distinct claim and gets said out loud. "Verified"
	// on a document that quietly descends from something else tells a reader
	// less than they need: what they are holding is not the model they were
	// offered, it is a modified copy, and the modification is the point.
	if d := rec.Derivation; d != nil {
		fmt.Fprintf(os.Stderr, "\nthis is a derived artifact, and the signer attests to producing it\n")
		if d.SourcePath != "" || d.SourceSHA256 != "" {
			fmt.Fprintf(os.Stderr, "  derived from: %s\n", cmpFirst(d.SourcePath, d.SourceSHA256))
		}
		if d.SourceSHA256 != "" {
			fmt.Fprintf(os.Stderr, "  source sha256: %s\n", d.SourceSHA256)
		}
		if d.SourceVerdict != "" {
			fmt.Fprintf(os.Stderr, "  source assessed as: %s\n", d.SourceVerdict)
		}
		for _, c := range d.Changes {
			fmt.Fprintf(os.Stderr, "  change: %s\n", c)
		}
		if len(d.Resolves) > 0 {
			fmt.Fprintf(os.Stderr, "  resolves: %s\n", strings.Join(d.Resolves, ", "))
		}
	}

	// Half of an attestation is who signed it. The other half is whether the
	// document is still true, and only the artifact can answer that.
	if *artifact == "" {
		fmt.Fprintln(os.Stderr,
			"no --artifact given: the signature is valid, but nothing here establishes "+
				"that this document still describes the model it names")
		return exitOK
	}

	res, err := tessera.Verify(ctxBackground(), docPath, *artifact)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
		return exitError
	}
	fmt.Fprintf(os.Stderr, "\nclaims re-derived from %s:\n", *artifact)
	for _, c := range res.Checks {
		fmt.Fprintf(os.Stderr, "  [%s] %s\n", c.Outcome, c.Claim)
	}
	if !res.Verified {
		fmt.Fprintln(os.Stderr,
			"\nNOT VERIFIED: the signature is valid but the document no longer describes these bytes")
		return exitUnverified
	}
	fmt.Fprintln(os.Stderr, "\nVERIFIED: signed by the named key, and still true of this artifact")
	return exitOK
}

// --- small helpers, kept here so the attest commands are self-contained ---

func ctxBackground() context.Context { return context.Background() }

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// slugOf makes a filesystem-safe stem from a model name.
func slugOf(name string) string {
	if name == "" {
		return "model"
	}
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		return "model"
	}
	return s
}

// positional accepts the target before or after the flags, because both orders
// are what people type.
func positional(fs *flag.FlagSet, args []string) (string, error) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		if err := fs.Parse(args[1:]); err != nil {
			return "", err
		}
		return args[0], nil
	}
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() != 1 {
		return "", fmt.Errorf("expected exactly one path")
	}
	return fs.Arg(0), nil
}

// derivationOf lifts a verified derivation onto the attestation.
//
// An unverified one is dropped rather than signed. The emitters already refuse
// to state an unverified derivation structurally; signing one would be strictly
// worse, converting a claim anybody could have written into a claim carrying
// this key's name.
func derivationOf(art *tessera.Artifact) *sign.AttestedDerivation {
	d := art.Derivation
	if d == nil || d.Unverified {
		return nil
	}
	out := &sign.AttestedDerivation{
		SourceSHA256:  d.Source.SHA256,
		SourcePath:    cmpFirst(d.Source.Name, d.Source.Path),
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

func cmpFirst(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
