package model

import "sort"

// Taxonomy maps Tessera's findings onto vocabularies a security engineer
// already speaks: CWE, and MITRE ATLAS where a technique genuinely applies.
//
// The reason this file exists is narrow and worth stating. `TESS-PICKLE-001`
// means nothing to somebody who has never used this tool. **CWE-502** means
// "deserialization of untrusted data" to everyone in the field, maps onto their
// existing risk register, and slots into a ticket template they already have.
// A finding nobody can classify is a finding nobody actions.
//
// Two rules govern the entries below.
//
// **A mapping is only added where it is true.** An operational finding — a file
// that could not be read, a walk that was truncated, a licence that was not
// declared — is not a weakness in the artifact and gets no CWE. Padding the
// table would make the coverage look better and every downstream aggregation
// worse, because a CWE-defined weakness class is how other tools decide what to
// escalate.
//
// **ATLAS is applied more sparingly still.** ATLAS describes what an adversary
// does across an ML system; most of what a static parse sees is a property of
// one artifact rather than evidence of a campaign. Where the technique is
// unambiguous — a poisoned artifact obtained from a supply chain, code that runs
// on load — it is named. Where it would be a guess, it is left out.

// Classification is what a finding maps onto outside this tool.
type Classification struct {
	// CWE is the identifier without the prefix, e.g. "502". Empty when the
	// finding is operational rather than a weakness.
	CWE string
	// CWEName is the short CWE title, so a reader does not have to look it up.
	CWEName string
	// ATLAS is a MITRE ATLAS technique id, e.g. "AML.T0010". Empty unless the
	// technique genuinely applies.
	ATLAS string
	// ATLASName is that technique's name.
	ATLASName string
}

// Classify returns the taxonomy entry for a finding id, and whether one exists.
func Classify(id string) (Classification, bool) {
	c, ok := taxonomy[id]
	return c, ok
}

// ClassifiedCount reports how many findings carry a CWE, so documentation and
// tests can state coverage from the data rather than from a number somebody
// typed and then forgot to update.
func ClassifiedCount() (withCWE, withATLAS int) {
	for _, c := range taxonomy {
		if c.CWE != "" {
			withCWE++
		}
		if c.ATLAS != "" {
			withATLAS++
		}
	}
	return withCWE, withATLAS
}

const (
	cweDeserialization  = "502"
	cweOSCommand        = "78"
	cweCodeInjection    = "94"
	cweEvalInjection    = "95"
	cwePathTraversal    = "22"
	cweLinkFollowing    = "59"
	cweDecompression    = "409"
	cweUntrustedSearch  = "426"
	cweIncludeCode      = "829"
	cweIntegerOverflow  = "190"
	cweBufferSize       = "131"
	cweStackExhaustion  = "674"
	cweImproperInput    = "20"
	cweIncorrectType    = "843"
	cweMissingIntegrity = "353"
	cweUnverifiedOrigin = "345"
	cweExternalControl  = "610"
	cweSSRF             = "918"
)

const (
	atlasSupplyChainModel = "AML.T0010"
	atlasSupplyChainName  = "AI Supply Chain Compromise"
	atlasUnsafeML         = "AML.T0011"
	atlasUnsafeMLName     = "User Execution: Unsafe ML Artifacts"
	atlasBackdoor         = "AML.T0018"
	atlasBackdoorName     = "Manipulate AI Model: Backdoor AI Model"
)

// taxonomy is the table. Each entry is a judgement about what the check
// actually detects, not about what its name suggests.
var taxonomy = map[string]Classification{
	// ── Code that runs when the artifact is loaded ─────────────────────────
	"TESS-PICKLE-001": {cweDeserialization, "Deserialization of Untrusted Data", atlasUnsafeML, atlasUnsafeMLName},
	"TESS-PICKLE-002": {cweDeserialization, "Deserialization of Untrusted Data", atlasUnsafeML, atlasUnsafeMLName},
	"TESS-PICKLE-003": {cweDeserialization, "Deserialization of Untrusted Data", "", ""},
	"TESS-PICKLE-004": {cweDeserialization, "Deserialization of Untrusted Data", "", ""},
	"TESS-NPY-001":    {cweDeserialization, "Deserialization of Untrusted Data", atlasUnsafeML, atlasUnsafeMLName},
	"TESS-PY-004":     {cweDeserialization, "Deserialization of Untrusted Data", "", ""},

	// trust_remote_code and auto_map cause code shipped with the model to be
	// imported. That is inclusion of functionality from an untrusted sphere,
	// and it is the clearest supply-chain case in the whole table.
	"TESS-HF-001":     {cweIncludeCode, "Inclusion of Functionality from Untrusted Control Sphere", atlasSupplyChainModel, atlasSupplyChainName},
	"TESS-HF-002":     {cweIncludeCode, "Inclusion of Functionality from Untrusted Control Sphere", atlasSupplyChainModel, atlasSupplyChainName},
	"TESS-CONFIG-001": {cweIncludeCode, "Inclusion of Functionality from Untrusted Control Sphere", atlasUnsafeML, atlasUnsafeMLName},

	"TESS-PY-001":     {cweOSCommand, "OS Command Injection", atlasUnsafeML, atlasUnsafeMLName},
	"TESS-PY-002":     {cweEvalInjection, "Eval Injection", atlasUnsafeML, atlasUnsafeMLName},
	"TESS-PY-005":     {cweCodeInjection, "Code Injection", "", ""},
	"TESS-PY-003":     {cweSSRF, "Server-Side Request Forgery", "", ""},
	"TESS-PY-006":     {cweUntrustedSearch, "Untrusted Search Path", "", ""},
	"TESS-NATIVE-001": {cweUntrustedSearch, "Untrusted Search Path", atlasSupplyChainModel, atlasSupplyChainName},

	// A Lambda layer carries serialized Python; a foreign module resolves code
	// from outside the framework. Both execute on load.
	"TESS-KERAS-001": {cweDeserialization, "Deserialization of Untrusted Data", atlasUnsafeML, atlasUnsafeMLName},
	"TESS-KERAS-003": {cweIncludeCode, "Inclusion of Functionality from Untrusted Control Sphere", atlasUnsafeML, atlasUnsafeMLName},
	"TESS-KERAS-002": {cweExternalControl, "Externally Controlled Reference to a Resource", "", ""},
	"TESS-TF-001":    {cweCodeInjection, "Code Injection", atlasUnsafeML, atlasUnsafeMLName},
	"TESS-ONNX-001":  {cweCodeInjection, "Code Injection", atlasUnsafeML, atlasUnsafeMLName},
	"TESS-ONNX-010":  {cweUntrustedSearch, "Untrusted Search Path", "", ""},

	// Executables and scripts riding along inside a model artifact.
	"TESS-BIN-001":   {cweIncludeCode, "Inclusion of Functionality from Untrusted Control Sphere", atlasSupplyChainModel, atlasSupplyChainName},
	"TESS-BIN-002":   {cweIncludeCode, "Inclusion of Functionality from Untrusted Control Sphere", atlasSupplyChainModel, atlasSupplyChainName},
	"TESS-BIN-003":   {cweIncludeCode, "Inclusion of Functionality from Untrusted Control Sphere", atlasSupplyChainModel, atlasSupplyChainName},
	"TESS-SHELL-001": {cweIncludeCode, "Inclusion of Functionality from Untrusted Control Sphere", "", ""},
	"TESS-SHELL-002": {cweIncludeCode, "Inclusion of Functionality from Untrusted Control Sphere", "", ""},
	"TESS-EXEC-001":  {cweIncludeCode, "Inclusion of Functionality from Untrusted Control Sphere", "", ""},

	// ── Paths that leave where they were supposed to stay ─────────────────
	"TESS-ARCHIVE-003": {cwePathTraversal, "Improper Limitation of a Pathname to a Restricted Directory", "", ""},
	"TESS-ONNX-002":    {cwePathTraversal, "Improper Limitation of a Pathname to a Restricted Directory", "", ""},
	"TESS-ONNX-011":    {cwePathTraversal, "Improper Limitation of a Pathname to a Restricted Directory", "", ""},
	"TESS-FILE-003":    {cweLinkFollowing, "Improper Link Resolution Before File Access", "", ""},
	"TESS-LINK-001":    {cweLinkFollowing, "Improper Link Resolution Before File Access", "", ""},
	"TESS-ARCHIVE-004": {cweLinkFollowing, "Improper Link Resolution Before File Access", "", ""},

	// ── Resource exhaustion ───────────────────────────────────────────────
	"TESS-ARCHIVE-002": {cweDecompression, "Improper Handling of Highly Compressed Data", "", ""},
	"TESS-ARCHIVE-005": {cweDecompression, "Improper Handling of Highly Compressed Data", "", ""},
	"TESS-ARCHIVE-006": {cweDecompression, "Improper Handling of Highly Compressed Data", "", ""},
	"TESS-GGUF-006":    {cweStackExhaustion, "Uncontrolled Recursion", "", ""},

	// ── Malformed structure the parser had to defend against ──────────────
	// These are weaknesses in the *artifact*, and each names the class the cap
	// exists to prevent rather than the cap itself.
	"TESS-GGUF-002":    {cweBufferSize, "Incorrect Calculation of Buffer Size", "", ""},
	"TESS-GGUF-005":    {cweBufferSize, "Incorrect Calculation of Buffer Size", "", ""},
	"TESS-GGUF-003":    {cweBufferSize, "Incorrect Calculation of Buffer Size", "", ""},
	"TESS-GGUF-007":    {cweBufferSize, "Incorrect Calculation of Buffer Size", "", ""},
	"TESS-GGUF-011":    {cweIntegerOverflow, "Integer Overflow or Wraparound", "", ""},
	"TESS-GGUF-004":    {cweImproperInput, "Improper Input Validation", "", ""},
	"TESS-GGUF-001":    {cweImproperInput, "Improper Input Validation", "", ""},
	"TESS-GGUF-008":    {cweImproperInput, "Improper Input Validation", "", ""},
	"TESS-ST-001":      {cweImproperInput, "Improper Input Validation", "", ""},
	"TESS-ST-002":      {cweImproperInput, "Improper Input Validation", "", ""},
	"TESS-ST-003":      {cweImproperInput, "Improper Input Validation", "", ""},
	"TESS-NPY-002":     {cweImproperInput, "Improper Input Validation", "", ""},
	"TESS-ARCHIVE-001": {cweImproperInput, "Improper Input Validation", "", ""},

	// A template rendered unsandboxed is injection into whatever renders it.
	"TESS-GGUF-010": {cweCodeInjection, "Code Injection", atlasUnsafeML, atlasUnsafeMLName},

	// ── Declared versus measured ──────────────────────────────────────────
	// Drift is not a code-execution weakness, and pretending otherwise would
	// mislead. It is an integrity problem: the artifact's own description does
	// not match its contents, which is exactly what a swapped or tampered model
	// looks like. CWE-345 is the honest class, and the backdoor technique is
	// named only where a mismatch could conceal one.
	"TESS-DRIFT-001": {cweUnverifiedOrigin, "Insufficient Verification of Data Authenticity", atlasBackdoor, atlasBackdoorName},
	"TESS-DRIFT-002": {cweUnverifiedOrigin, "Insufficient Verification of Data Authenticity", "", ""},
	"TESS-DRIFT-008": {cweUnverifiedOrigin, "Insufficient Verification of Data Authenticity", "", ""},
	"TESS-DRIFT-003": {cweUnverifiedOrigin, "Insufficient Verification of Data Authenticity", "", ""},
	"TESS-DRIFT-004": {cweMissingIntegrity, "Missing Support for Integrity Check", atlasSupplyChainModel, atlasSupplyChainName},
	"TESS-DRIFT-007": {cweUnverifiedOrigin, "Insufficient Verification of Data Authenticity", atlasBackdoor, atlasBackdoorName},
	"TESS-DRIFT-006": {cweIncorrectType, "Access of Resource Using Incompatible Type", atlasUnsafeML, atlasUnsafeMLName},

	// Deliberately unmapped, and each for a reason:
	//
	//   TESS-DRIFT-005    a claim nothing present can verify — an absence of
	//                     evidence, not a weakness
	//   TESS-COVERAGE-001 the walk was truncated — a property of the scan
	//   TESS-FILE-001/002 a file could not be read, or the cap was hit
	//   TESS-IO-001/002   the same, one layer down
	//   TESS-KERAS-004    a container that could not be examined
	//   TESS-GGUF-009     the same, for a GGUF header
	//   TESS-ONNX-005/006 the parse stopped early
	//   TESS-LIC-001      no licence disclosed — a documentation gap
	//
	// Every one of these says "this was not examined" or "this was not stated".
	// Giving them a CWE would inflate the coverage number and corrupt any
	// downstream aggregation that treats a CWE as a weakness class.
}

// FindingIDs lists every identifier that appears in the taxonomy, sorted.
//
// This is the classified set rather than every emittable id: the ten
// operational findings deliberately carry no classification, and a caller
// asking for the taxonomy wants the entries that have one.
func FindingIDs() []string {
	out := make([]string, 0, len(taxonomy))
	for id := range taxonomy {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
