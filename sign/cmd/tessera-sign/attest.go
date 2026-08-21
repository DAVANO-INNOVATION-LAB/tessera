package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera"
	sign "github.com/DAVANO-INNOVATION-LAB/tessera/sign"
)

// Attestation is the point of this command, and it is a stronger claim than a
// signed document.
//
// A signature answers "who produced this bill of materials". It does not answer
// "does this bill of materials still describe the model in front of me" — and a
// procurement reviewer, six months and three re-uploads later, is asking the
// second question. Signing a document that has drifted from its artifact
// produces a cryptographically impeccable lie.
//
// So an attestation here is two facts bound together: the AI bill of materials,
// signed; and the artifact digest the document was derived from, inside the
// signed payload. Verification checks both — the signature against the key the
// verifier names, and every claim in the document against the bytes on disk.
// Either failing is a failure.
//
// The signature is hybrid post-quantum because these documents are retained.
// An AIBOM filed against a federal contract outlives the assumptions ECDSA
// rests on, and re-signing an archive after the fact is not a thing anyone does.

// attestation is written alongside each document. It is deliberately small and
// readable: somebody auditing this in a decade should not need our source to
// understand what was claimed.
type attestation struct {
	Kind string `json:"kind"`
	// Document names the file this attests to, and DocumentSHA256 pins its
	// bytes, so the attestation cannot be moved onto a different document.
	Document       string `json:"document"`
	DocumentSHA256 string `json:"documentSha256"`
	// Artifact is the model the document describes, pinned by digest. This is
	// what makes the attestation checkable against reality rather than only
	// against itself.
	Artifact       string `json:"artifact"`
	ArtifactSHA256 string `json:"artifactSha256"`
	Format         string `json:"artifactFormat"`
	// Tool records what produced the document, because a claim is only as good
	// as the thing that made it.
	Tool        string       `json:"tool"`
	ToolVersion string       `json:"toolVersion"`
	AttestedAt  string       `json:"attestedAt"`
	Signature   *sign.Bundle `json:"signature"`
}

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
		bundle, err := sign.Sign(kp, doc, time.Now().UTC())
		if err != nil {
			fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
			return exitError
		}
		rec := attestation{
			Kind:           "tessera-aibom-attestation/v1",
			Document:       filepath.Base(docPath),
			DocumentSHA256: sha256Hex(doc),
			Artifact:       primary.Path,
			ArtifactSHA256: primary.SHA256,
			Format:         string(art.Format),
			Tool:           "tessera",
			ToolVersion:    version,
			AttestedAt:     bundle.SignedAt,
			Signature:      bundle,
		}
		enc, err := json.MarshalIndent(&rec, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
			return exitError
		}
		attPath := docPath + ".att.json"
		if err := os.WriteFile(attPath, append(enc, '\n'), 0o644); err != nil {
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
	var rec attestation
	if err := json.Unmarshal(raw, &rec); err != nil {
		fmt.Fprintf(os.Stderr, "tessera-sign: attestation: %v\n", err)
		return exitError
	}
	if rec.Signature == nil {
		fmt.Fprintln(os.Stderr, "tessera-sign: attestation carries no signature")
		return exitUnverified
	}

	docPath := filepath.Join(filepath.Dir(attPath), rec.Document)
	doc, err := os.ReadFile(docPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
		return exitError
	}
	if got := sha256Hex(doc); got != rec.DocumentSHA256 {
		fmt.Fprintf(os.Stderr,
			"tessera-sign: %s does not match the digest this attestation covers\n", rec.Document)
		return exitUnverified
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
	if err := sign.Verify(rec.Signature, doc, pq, ec); err != nil {
		fmt.Fprintf(os.Stderr, "tessera-sign: signature does not verify: %v\n", err)
		return exitUnverified
	}
	fmt.Fprintf(os.Stderr, "signature verified (%s), signed %s\n",
		rec.Signature.Suite, rec.AttestedAt)

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
