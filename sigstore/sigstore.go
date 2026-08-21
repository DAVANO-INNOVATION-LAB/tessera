// Package sigstore verifies that a model artifact was signed by a publisher you
// trust, and reports what that signature actually covers.
//
// This is the embedding surface. The implementation stays in internal/ so it
// can change without breaking importers.
//
// It is a separate module from tessera for one reason: sigstore-go brings a
// large dependency tree, and tessera has none. An embedder who wants to parse a
// model file should not inherit an AWS SDK to do it. Splitting the module is
// what lets both statements stay true at once.
//
// The distinction this package is careful about is between a signature that
// exists and a signature that means something. A bundle present on disk, a
// bundle that verifies against an unknown key, and a bundle that verifies
// against a publisher named in policy are three different facts, and only the
// third is evidence. Each is reported as its own finding rather than collapsed
// into a boolean.
package sigstore

import (
	"github.com/DAVANO-INNOVATION-LAB/tessera/sigstore/internal/provenance"
)

type (
	// Policy names the publishers whose signatures are trusted, and where the
	// Sigstore trust root is found.
	Policy = provenance.Policy
	// Publisher is one trusted signing identity.
	Publisher = provenance.Publisher
	// Verifier checks artifacts against a policy.
	Verifier = provenance.Verifier
	// Result is the outcome of verifying one artifact.
	Result = provenance.Result
	// Finding is one observation about an artifact's provenance.
	Finding = provenance.Finding
	// Inventory is what a workspace holds: artifacts, and the signatures that
	// claim to cover them.
	Inventory = provenance.Inventory
	// Signature is one signature file found beside an artifact.
	Signature = provenance.Signature
	// SignatureKind distinguishes a Sigstore bundle from a model-transparency
	// manifest from a detached key signature.
	SignatureKind = provenance.SignatureKind
)

// NewVerifier builds a verifier for a policy.
//
// An error here means the policy could not be made usable — a trust root that
// will not load, a publisher with no identity. It is deliberately not a
// verifier that returns "unverified" for everything: a misconfigured verifier
// that reports every artifact as unsigned is indistinguishable from a working
// one looking at unsigned artifacts, and the difference matters enormously.
func NewVerifier(policy Policy) (*Verifier, error) { return provenance.NewVerifier(policy) }

// Discover inventories the signatures and artifacts in a workspace without
// verifying anything.
func Discover(workspace string) (*Inventory, error) { return provenance.Discover(workspace) }

// ExecutableFormat reports the model format a filename implies when that format
// can execute code on load, and the empty string otherwise. An unsigned
// safetensors file is a different risk from an unsigned pickle.
func ExecutableFormat(name string) string { return provenance.ExecutableFormat(name) }

// Finding identifiers this package emits. They are exported because a policy or
// a waiver has to be able to name one, and a rule naming an identifier that
// does not exist suppresses nothing while appearing to.
const (
	// FindingVerified: a signature verified against a trusted publisher. This
	// is a finding rather than silence so a report can state positively what
	// was checked, instead of leaving a verified artifact indistinguishable
	// from one nobody looked at.
	FindingVerified = provenance.FindingVerified
	// FindingUnsigned: no signature was found.
	FindingUnsigned = provenance.FindingUnsigned
	// FindingInvalid: a signature was found and does not verify.
	FindingInvalid = provenance.FindingInvalid
	// FindingUntrustedSigner: a signature verifies, but against an identity no
	// policy names. Cryptographically sound and worth nothing.
	FindingUntrustedSigner = provenance.FindingUntrustedSigner
	// FindingNoTransparencyLog: the signature has no transparency-log entry.
	FindingNoTransparencyLog = provenance.FindingNoTransparencyLog
	// FindingPartialCoverage: the signature covers some of the artifact's
	// files. The uncovered ones are named, because that is where something
	// unsigned would be placed.
	FindingPartialCoverage = provenance.FindingPartialCoverage
	// FindingNotConfigured: verification could not run. Reported rather than
	// passed, because a check that did not happen is not a check that passed.
	FindingNotConfigured = provenance.FindingNotConfigured
)
