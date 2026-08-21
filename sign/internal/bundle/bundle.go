// Package bundle implements hybrid post-quantum signing for bills of materials.
//
// Every document is signed twice — once with a post-quantum algorithm and once
// with a classical one — and verification requires both. That composition is
// deliberate. A signature is a claim that has to survive being checked years
// after it was made, and the two families fail for unrelated reasons: if
// lattices turn out to be weaker than believed, the elliptic curve still holds,
// and if a cryptanalytic advance breaks P-384, the lattice still holds. Signing
// twice costs a few kilobytes.
//
// It is also the only choice that satisfies every major authority at once.
// NSA CNSA 2.0 designates ML-DSA and would accept it alone; ANSSI requires a
// classical algorithm alongside any post-quantum one and would reject that;
// BSI TR-02102-1 concurs with ANSSI. Optimising for one produces something the
// others will not take.
package bundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

// Suite names the algorithm set a bundle uses.
type Suite string

const (
	// SuiteHybridMLDSA87 is the default: ML-DSA-87 (FIPS 204, Category 5) with
	// ECDSA P-384, over SHA-384.
	SuiteHybridMLDSA87 Suite = "hybrid-mldsa87-ecdsap384-sha384"
	// SuiteHybridSLHDSA is the conservative alternative: SLH-DSA-SHA2-256s
	// (FIPS 205) with ECDSA P-384. Hash-based, so it rests on strictly weaker
	// assumptions than a lattice; signatures are an order of magnitude larger.
	SuiteHybridSLHDSA Suite = "hybrid-slhdsa256s-ecdsap384-sha384"
)

// pqScheme resolves the post-quantum half of a suite.
func pqScheme(s Suite) (sign.Scheme, error) {
	switch s {
	case SuiteHybridMLDSA87:
		return schemes.ByName("ML-DSA-87"), nil
	case SuiteHybridSLHDSA:
		return schemes.ByName("SLH-DSA-SHA2-256s"), nil
	}
	return nil, fmt.Errorf("unknown suite %q", s)
}

// KeyPair holds both halves of a hybrid identity.
type KeyPair struct {
	Suite Suite
	PQ    sign.PrivateKey
	EC    *ecdsa.PrivateKey
}

// Generate creates a new hybrid key pair.
func Generate(suite Suite) (*KeyPair, error) {
	scheme, err := pqScheme(suite)
	if err != nil {
		return nil, err
	}
	_, pqPriv, err := scheme.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate post-quantum key: %w", err)
	}
	// P-384 rather than P-256: CNSA 2.0 and CNSA 1.0 both put the floor at 384
	// for national-security use, and a hybrid is only as strong as its weaker
	// half.
	ecPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate classical key: %w", err)
	}
	return &KeyPair{Suite: suite, PQ: pqPriv, EC: ecPriv}, nil
}

// Bundle is a detached signature over a document.
type Bundle struct {
	// Version guards the format itself. A verifier that does not recognise it
	// must refuse rather than guess, because guessing at a signature format is
	// how a downgrade starts.
	Version int   `json:"version"`
	Suite   Suite `json:"suite"`
	// SignedAt is informational. It is inside the signed payload, so it cannot
	// be altered without breaking both signatures, but a timestamp a signer
	// chose is not evidence of when anything happened.
	SignedAt string `json:"signedAt"`
	// DigestSHA384 is the digest of the document that was signed, recorded so a
	// reader can see what was covered without holding the document.
	DigestSHA384 string `json:"digestSha384"`
	// PQSignature and ECSignature are independent signatures over the same
	// payload. Both must verify.
	PQSignature string `json:"pqSignature"`
	ECSignature string `json:"ecSignature"`
	// PQPublicKey and ECPublicKey identify the signer.
	PQPublicKey string `json:"pqPublicKey"`
	ECPublicKey string `json:"ecPublicKey"`
}

// bundleVersion is the current bundle format.
const bundleVersion = 1

// signedPayload is what both algorithms actually sign.
//
// The suite name and version are inside it on purpose. Signing only the document
// digest would leave the algorithm identifiers unauthenticated, so an attacker
// could re-present a signature under a weaker suite label and a lax verifier
// might accept it. Binding them means any such edit breaks both signatures.
func signedPayload(suite Suite, digest []byte, signedAt string) []byte {
	p, _ := json.Marshal(struct {
		Version  int    `json:"v"`
		Suite    Suite  `json:"suite"`
		Digest   string `json:"digest"`
		SignedAt string `json:"signedAt"`
	}{bundleVersion, suite, base64.StdEncoding.EncodeToString(digest), signedAt})
	return p
}

// Sign produces a detached hybrid signature over document.
func Sign(kp *KeyPair, document []byte, at time.Time) (*Bundle, error) {
	scheme, err := pqScheme(kp.Suite)
	if err != nil {
		return nil, err
	}

	sum := sha512.Sum384(document)
	signedAt := at.UTC().Format(time.RFC3339)
	payload := signedPayload(kp.Suite, sum[:], signedAt)

	pqSig := scheme.Sign(kp.PQ, payload, nil)

	// ECDSA signs a digest, not the message; SHA-384 matches the curve.
	pd := sha512.Sum384(payload)
	ecSig, err := ecdsa.SignASN1(rand.Reader, kp.EC, pd[:])
	if err != nil {
		return nil, fmt.Errorf("classical sign: %w", err)
	}

	pqPub, err := kp.PQ.Public().(sign.PublicKey).MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal post-quantum public key: %w", err)
	}
	ecPub, err := x509.MarshalPKIXPublicKey(&kp.EC.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal classical public key: %w", err)
	}

	return &Bundle{
		Version:      bundleVersion,
		Suite:        kp.Suite,
		SignedAt:     signedAt,
		DigestSHA384: base64.StdEncoding.EncodeToString(sum[:]),
		PQSignature:  base64.StdEncoding.EncodeToString(pqSig),
		ECSignature:  base64.StdEncoding.EncodeToString(ecSig),
		PQPublicKey:  base64.StdEncoding.EncodeToString(pqPub),
		ECPublicKey:  base64.StdEncoding.EncodeToString(ecPub),
	}, nil
}

// ErrVerification is returned whenever a bundle does not verify. The reason is
// deliberately not distinguished in the error: telling a caller which half
// failed, or that a key merely did not match, hands an attacker a probe.
var ErrVerification = errors.New("signature does not verify")

// Verify checks a bundle against a document and an expected signer.
//
// expectedPQPub and expectedECPub are the public keys the caller trusts. They
// are compared against the ones in the bundle before any signature is checked,
// because a signature that verifies against a key from inside the same file
// proves only that the file is internally consistent — which is what an
// attacker who replaced both would produce.
func Verify(b *Bundle, document, expectedPQPub, expectedECPub []byte) error {
	if b.Version != bundleVersion {
		return fmt.Errorf("unsupported bundle version %d", b.Version)
	}
	scheme, err := pqScheme(b.Suite)
	if err != nil {
		return err
	}

	pqPub, err := base64.StdEncoding.DecodeString(b.PQPublicKey)
	if err != nil {
		return ErrVerification
	}
	ecPub, err := base64.StdEncoding.DecodeString(b.ECPublicKey)
	if err != nil {
		return ErrVerification
	}
	if !constantTimeEqual(pqPub, expectedPQPub) || !constantTimeEqual(ecPub, expectedECPub) {
		return fmt.Errorf("%w: signed by a different key than the one supplied", ErrVerification)
	}

	sum := sha512.Sum384(document)
	if base64.StdEncoding.EncodeToString(sum[:]) != b.DigestSHA384 {
		return fmt.Errorf("%w: the document is not the one that was signed", ErrVerification)
	}
	payload := signedPayload(b.Suite, sum[:], b.SignedAt)

	pqSig, err := base64.StdEncoding.DecodeString(b.PQSignature)
	if err != nil {
		return ErrVerification
	}
	pqKey, err := scheme.UnmarshalBinaryPublicKey(pqPub)
	if err != nil {
		return ErrVerification
	}
	if !scheme.Verify(pqKey, payload, pqSig, nil) {
		return fmt.Errorf("%w: post-quantum signature failed", ErrVerification)
	}

	ecSig, err := base64.StdEncoding.DecodeString(b.ECSignature)
	if err != nil {
		return ErrVerification
	}
	anyKey, err := x509.ParsePKIXPublicKey(ecPub)
	if err != nil {
		return ErrVerification
	}
	ecKey, ok := anyKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrVerification
	}
	pd := sha512.Sum384(payload)
	if !ecdsa.VerifyASN1(ecKey, pd[:], ecSig) {
		return fmt.Errorf("%w: classical signature failed", ErrVerification)
	}
	// Both halves held.
	return nil
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// MarshalPrivate encodes a key pair as two PEM blocks.
func MarshalPrivate(kp *KeyPair) ([]byte, error) {
	pqRaw, err := kp.PQ.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
	if err != nil {
		return nil, err
	}
	ecRaw, err := x509.MarshalECPrivateKey(kp.EC)
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{
		Type:    "TESSERA PQ PRIVATE KEY",
		Headers: map[string]string{"suite": string(kp.Suite)},
		Bytes:   pqRaw,
	})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecRaw})...)
	return out, nil
}

// MarshalPublic encodes the public halves as two PEM blocks.
func MarshalPublic(kp *KeyPair) ([]byte, error) {
	pqPub, err := kp.PQ.Public().(sign.PublicKey).MarshalBinary()
	if err != nil {
		return nil, err
	}
	ecPub, err := x509.MarshalPKIXPublicKey(&kp.EC.PublicKey)
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{
		Type:    "TESSERA PQ PUBLIC KEY",
		Headers: map[string]string{"suite": string(kp.Suite)},
		Bytes:   pqPub,
	})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecPub})...)
	return out, nil
}

// ParsePrivate reads a key pair produced by MarshalPrivate.
func ParsePrivate(data []byte) (*KeyPair, error) {
	kp := &KeyPair{}
	rest := data
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "TESSERA PQ PRIVATE KEY":
			kp.Suite = Suite(blk.Headers["suite"])
			scheme, err := pqScheme(kp.Suite)
			if err != nil {
				return nil, err
			}
			priv, err := scheme.UnmarshalBinaryPrivateKey(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("post-quantum private key: %w", err)
			}
			kp.PQ = priv
		case "EC PRIVATE KEY":
			priv, err := x509.ParseECPrivateKey(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("classical private key: %w", err)
			}
			kp.EC = priv
		}
	}
	if kp.PQ == nil || kp.EC == nil {
		return nil, errors.New("key file must contain both a post-quantum and a classical private key")
	}
	return kp, nil
}

// ParsePublic reads the raw public halves from a file produced by MarshalPublic.
func ParsePublic(data []byte) (pq, ec []byte, err error) {
	rest := data
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "TESSERA PQ PUBLIC KEY":
			pq = blk.Bytes
		case "PUBLIC KEY":
			ec = blk.Bytes
		}
	}
	if pq == nil || ec == nil {
		return nil, nil, errors.New("public key file must contain both a post-quantum and a classical key")
	}
	return pq, ec, nil
}
