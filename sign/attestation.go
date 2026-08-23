package sign

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Attestation: a bill of materials, the artifact it describes, and a signature
// binding the two.
//
// The format lives here rather than in the command that first wrote it, because
// two producers now emit it — the CLI and the Studio — and a wire format defined
// inside one caller drifts the moment the second one is written. Anything this
// package produces must verify with anything else this package produces,
// whichever program made it.
//
// A signature answers "who produced this document". It does not answer "does
// this document still describe the model in front of me", and a procurement
// reviewer six months and three re-uploads later is asking the second question.
// Signing a document that has drifted from its artifact yields a
// cryptographically impeccable lie. So the artifact digest lives inside the
// signed payload, and verification checks both.
//
// The signature is hybrid post-quantum because these documents are retained. An
// AIBOM filed against a federal contract outlives the assumptions ECDSA rests
// on, and nobody re-signs an archive after the fact.

// AttestationKind identifies the format. Version it rather than guessing: a
// reader that meets a future record should say so, not misread fields.
const AttestationKind = "tessera-aibom-attestation/v1"

// Attestation is written alongside each document. Deliberately small and
// readable: somebody auditing this in a decade should not need our source.
type Attestation struct {
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
	// Derivation is present only when the document describes an artifact the
	// signer produced from another one and could verify having produced.
	//
	// Its presence is the whole reason a hardened copy is worth attesting. In
	// the interface, a derivation is trustworthy because this server remembers
	// doing the work — a fact that dies the moment the document is copied
	// somewhere else. Inside a signed payload it travels: a reader who trusts
	// the key can trust that this key's holder performed these changes, on an
	// artifact with this digest, and can check the source digest against the
	// original if they hold it.
	//
	// An unverified claim must never appear here. Signing one would convert a
	// claim anybody could have written into a claim bearing our name, which is
	// exactly the laundering the rest of this design refuses.
	Derivation *AttestedDerivation `json:"derivation,omitempty"`
	// Tool records what produced the document, because a claim is only as good
	// as the thing that made it.
	Tool        string  `json:"tool"`
	ToolVersion string  `json:"toolVersion"`
	AttestedAt  string  `json:"attestedAt"`
	Signature   *Bundle `json:"signature"`
}

// AttestedDerivation is the signed form of a hardening derivation.
type AttestedDerivation struct {
	// SourceSHA256 is the artifact this was derived from. A reader holding the
	// original can confirm the link rather than taking it on faith.
	SourceSHA256  string `json:"sourceSha256,omitempty"`
	SourcePath    string `json:"sourcePath,omitempty"`
	SourceVerdict string `json:"sourceVerdict,omitempty"`
	// Changes are one-line summaries of what was done, and Resolves the finding
	// identifiers they answered.
	Changes  []string `json:"changes,omitempty"`
	Resolves []string `json:"resolves,omitempty"`
}

// ArtifactRef is the model an attestation covers.
type ArtifactRef struct {
	Path   string
	SHA256 string
	Format string
}

// Attest signs a document and binds it to the artifact it describes.
//
// documentName is the filename the attestation will sit beside; it is recorded
// so a reader can pair them, and pinned by digest so the pairing cannot be
// swapped.
func Attest(kp *KeyPair, document []byte, documentName string, art ArtifactRef,
	tool, toolVersion string, at time.Time, derivation *AttestedDerivation) (*Attestation, error) {
	if kp == nil {
		return nil, fmt.Errorf("attestation needs a signing key")
	}
	if len(document) == 0 {
		return nil, fmt.Errorf("refusing to attest an empty document")
	}
	b, err := Sign(kp, document, at)
	if err != nil {
		return nil, err
	}
	return &Attestation{
		Kind:           AttestationKind,
		Document:       documentName,
		DocumentSHA256: SHA256Hex(document),
		Artifact:       art.Path,
		ArtifactSHA256: art.SHA256,
		Format:         art.Format,
		Derivation:     derivation,
		Tool:           tool,
		ToolVersion:    toolVersion,
		AttestedAt:     b.SignedAt,
		Signature:      b,
	}, nil
}

// Marshal renders an attestation the way both producers write it, so a file
// from one is byte-comparable with a file from the other.
func (a *Attestation) Marshal() ([]byte, error) {
	enc, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(enc, '\n'), nil
}

// ParseAttestation reads a record, refusing one this build cannot interpret.
func ParseAttestation(data []byte) (*Attestation, error) {
	var a Attestation
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("attestation: %w", err)
	}
	if a.Kind != AttestationKind {
		return nil, fmt.Errorf("attestation is %q; this build reads %s", a.Kind, AttestationKind)
	}
	if a.Signature == nil {
		return nil, fmt.Errorf("attestation carries no signature")
	}
	return &a, nil
}

// VerifyDocument checks that the document is the one this attestation covers
// and that the signature is the named key's.
//
// Order matters. The digest is checked first so a mismatched document is
// rejected before any cryptography runs on it, and the signature second because
// it is what makes the digest worth anything.
func (a *Attestation) VerifyDocument(document, expectedPQPub, expectedECPub []byte) error {
	if got := SHA256Hex(document); got != a.DocumentSHA256 {
		return fmt.Errorf("%s does not match the digest this attestation covers", a.Document)
	}
	return Verify(a.Signature, document, expectedPQPub, expectedECPub)
}

// SHA256Hex is the digest form used throughout the attestation format.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
