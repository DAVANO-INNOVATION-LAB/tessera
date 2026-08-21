// Package sign produces and verifies hybrid post-quantum signatures over the
// documents Tessera emits.
//
// This is the embedding surface. The implementation stays in internal/ so its
// shape can change without breaking importers; this file is what has to stay
// stable, and it is deliberately small.
//
// Every signature is two signatures. A lattice scheme and an elliptic curve
// sign the same payload independently and both must verify. The reason is that
// nobody knows which of the two will fail first: ML-DSA rests on assumptions
// that are a decade old, and ECDSA rests on assumptions a cryptographically
// relevant quantum computer would end. Requiring both means a break in either
// family degrades this to the other rather than to nothing.
//
// It lives in a separate module from tessera itself so that the library's
// zero-dependency guarantee survives. Signing needs a lattice implementation;
// parsing a model does not, and an embedder who wants only the parser should
// not inherit one.
package sign

import (
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/sign/internal/bundle"
)

type (
	// Suite names the algorithm set a signature uses.
	Suite = bundle.Suite
	// KeyPair holds both halves of a hybrid identity.
	KeyPair = bundle.KeyPair
	// Bundle is a detached signature over one document.
	Bundle = bundle.Bundle
)

const (
	// SuiteHybridMLDSA87 is the default: ML-DSA-87 (FIPS 204, Category 5) with
	// ECDSA P-384, over SHA-384.
	SuiteHybridMLDSA87 = bundle.SuiteHybridMLDSA87
	// SuiteHybridSLHDSA is the conservative alternative: SLH-DSA-SHA2-256s
	// (FIPS 205) with ECDSA P-384. Hash-based, so it rests on strictly weaker
	// assumptions than a lattice; signatures are an order of magnitude larger.
	SuiteHybridSLHDSA = bundle.SuiteHybridSLHDSA
)

// Generate creates a new hybrid key pair.
func Generate(suite Suite) (*KeyPair, error) { return bundle.Generate(suite) }

// Sign produces a detached signature over document.
func Sign(kp *KeyPair, document []byte, at time.Time) (*Bundle, error) {
	return bundle.Sign(kp, document, at)
}

// Verify checks a signature against a document and the public keys the verifier
// expects.
//
// The expected keys are parameters rather than being read from the bundle. A
// verifier that trusts the key travelling inside the thing it is verifying is
// not verifying anything, and that mistake is common enough in this space to be
// worth designing against rather than documenting around.
func Verify(b *Bundle, document, expectedPQPub, expectedECPub []byte) error {
	return bundle.Verify(b, document, expectedPQPub, expectedECPub)
}

// MarshalPrivate encodes a key pair as PEM. The result is secret.
func MarshalPrivate(kp *KeyPair) ([]byte, error) { return bundle.MarshalPrivate(kp) }

// MarshalPublic encodes the public halves as PEM.
func MarshalPublic(kp *KeyPair) ([]byte, error) { return bundle.MarshalPublic(kp) }

// ParsePrivate reads a private key pair from PEM.
func ParsePrivate(data []byte) (*KeyPair, error) { return bundle.ParsePrivate(data) }

// ParsePublic reads the public halves from PEM.
func ParsePublic(data []byte) (pq, ec []byte, err error) { return bundle.ParsePublic(data) }
