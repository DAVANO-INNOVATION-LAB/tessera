// Package model defines Tessera's format-neutral intermediate representation.
//
// The whole tool turns on this one type. Parsers (GGUF, safetensors, ONNX)
// write an Artifact; emitters (CycloneDX, SPDX) read one. Neither side knows
// the other exists, so a new format is one parser and a new standard is one
// emitter. The rule the IR enforces is that nothing read off disk is ever
// silently dropped: every field a parser sees lands in a typed slot if one
// exists and in Raw regardless, so an emitter can always account for what the
// bytes disclosed.
package model

// Format names the container a parser recognized.
type Format string

const (
	FormatGGUF        Format = "gguf"
	FormatSafetensors Format = "safetensors"
	FormatONNX        Format = "onnx"
)

// Artifact is the normalized description of one model, assembled from whatever
// the file format disclosed plus what enrichment could add (hashes, resolved
// licenses, findings).
type Artifact struct {
	// Format is the container the primary file was parsed as.
	Format Format `json:"format"`
	// Identity is who/what the model claims to be.
	Identity Identity `json:"identity"`
	// Licenses holds every license the file disclosed, raw and resolved.
	Licenses []License `json:"licenses,omitempty"`
	// Lineage is where the model says it came from.
	Lineage Lineage `json:"lineage"`

	// Derivation is set when this artifact was produced from another by a
	// transformation this tool performed, rather than parsed from the file.
	Derivation *Derivation `json:"derivation,omitempty"`

	// Considerations carries the governance prose from a model card.
	Considerations Considerations `json:"considerations,omitempty"`
	// Params describes the model's shape and training, as measured from the
	// binary itself.
	Params Parameters `json:"params"`
	// Declared is what the model's sidecar files claim about it. It is kept
	// separate from Params on purpose: one side is what the artifact says, the
	// other is what it is, and the whole point of comparing them is that they
	// can disagree. Collapsing them into one set of fields would destroy the
	// only signal that matters here.
	Declared Declared `json:"declared,omitempty"`
	// Files are the physical files that make up the model — the primary file
	// plus any shards or external tensor data. Each is hashed independently so
	// a multi-file model is a set of pinned components, not one opaque blob.
	Files []FileComponent `json:"files,omitempty"`
	// Tensors is a bounded inventory of the model's tensors. It is capped: a
	// model with a million tensors records the count, not a million entries.
	Tensors     []Tensor `json:"tensors,omitempty"`
	TensorCount int      `json:"tensorCount"`
	// Runtime is what a loader needs and what a loader risks: framework, ONNX
	// opset imports, custom operator domains.
	Runtime Runtime `json:"runtime"`
	// Raw preserves every disclosed field verbatim, keyed by its native name
	// (general.license, producer_name, __metadata__.format, ...). It is the
	// backstop that guarantees the IR never loses information the typed slots
	// don't model.
	Raw map[string]string `json:"raw,omitempty"`
	// Findings are the security observations the scan produced from the parsed
	// metadata. They travel with the BOM so the bill of materials and the risk
	// verdict never separate.
	Findings []Finding `json:"findings,omitempty"`
}

// Identity is the model's self-declared name and provenance handles.
type Identity struct {
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	Author       string `json:"author,omitempty"`
	Organization string `json:"organization,omitempty"`
	Description  string `json:"description,omitempty"`
	UUID         string `json:"uuid,omitempty"`
	URL          string `json:"url,omitempty"`
	RepoURL      string `json:"repoURL,omitempty"`
	DOI          string `json:"doi,omitempty"`
}

// License is one license claim: what the file said, and what that resolves to
// as an SPDX identifier if it resolves at all.
type License struct {
	// Raw is the license string exactly as read from the file.
	Raw string `json:"raw,omitempty"`
	// SPDXID is the resolved SPDX identifier, or "" if it could not be matched.
	// A model-specific license that has no SPDX id resolves to a LicenseRef-*.
	SPDXID string `json:"spdxID,omitempty"`
	// Confidence is how the SPDX id was reached: exact, normalized, or none.
	Confidence string `json:"confidence,omitempty"`
	// URL is a link to the license text, if the file provided one.
	URL string `json:"url,omitempty"`
}

// Lineage is the model's claimed ancestry.
type Lineage struct {
	BaseModels []Reference `json:"baseModels,omitempty"`
	Sources    []Reference `json:"sources,omitempty"`
	Datasets   []Reference `json:"datasets,omitempty"`
}

// Reference is a named pointer to another artifact or dataset.
type Reference struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
	DOI  string `json:"doi,omitempty"`
}

// Declared holds claims read from files that sit beside the model — config.json
// most often — rather than from the model binary. Every field records where it
// came from, because a claim is only worth comparing if you can say who made it.
type Declared struct {
	// Source names the file the claims were read from.
	Source string `json:"source,omitempty"`
	// Architecture is the architecture the config names, e.g. LlamaForCausalLM.
	Architecture string `json:"architecture,omitempty"`
	// DType is the declared tensor precision, e.g. bfloat16.
	DType string `json:"dtype,omitempty"`
	// Quantization is the declared quantization scheme, when one is named.
	Quantization string `json:"quantization,omitempty"`
	// Task is the pipeline the card advertises, e.g. text-generation. It is a
	// claim, not a measurement — nothing in a weights file states what a model
	// is for — so it lives here rather than in Parameters.
	Task string `json:"task,omitempty"`
	// Library is the framework the card names, e.g. transformers. Since
	// August 2024 a config.json no longer implies transformers, so this is
	// the only place the framework is stated rather than assumed.
	Library string `json:"library,omitempty"`
	// ParameterCount is a declared parameter count, when present.
	ParameterCount string `json:"parameterCount,omitempty"`
	// BaseModel is the parent this artifact claims to derive from.
	BaseModel string `json:"baseModel,omitempty"`
	// ShardCount is how many shards the index claims the model has.
	ShardCount int `json:"shardCount,omitempty"`
}

// Empty reports whether anything was declared at all.
func (d Declared) Empty() bool {
	return d.Architecture == "" && d.DType == "" && d.Quantization == "" &&
		d.ParameterCount == "" && d.BaseModel == "" && d.ShardCount == 0
}

// Parameters is the model's shape and training description.
type Parameters struct {
	Architecture       string `json:"architecture,omitempty"`
	ArchitectureFamily string `json:"architectureFamily,omitempty"`
	// DType is the precision holding the most parameters, measured from the
	// tensor headers rather than declared anywhere.
	DType string `json:"dtype,omitempty"`
	// Quantization is a GGUF-only first-class datum (general.file_type).
	Quantization string `json:"quantization,omitempty"`
	// ParameterCount is a declared/label form, e.g. GGUF general.size_label "8B".
	ParameterCount string `json:"parameterCount,omitempty"`
	// MeasuredParameters is the true count summed from every tensor's shape,
	// across the whole file rather than the bounded inventory. It is the figure
	// the declared count is checked against, and the one the EU AI Act Annex XI
	// calls "the number of parameters".
	MeasuredParameters int64             `json:"measuredParameters,omitempty"`
	Hyperparameters    map[string]string `json:"hyperparameters,omitempty"`
	Inputs             []IOSpec          `json:"inputs,omitempty"`
	Outputs            []IOSpec          `json:"outputs,omitempty"`
}

// IOSpec is one model input or output tensor's declared type.
type IOSpec struct {
	Name   string  `json:"name,omitempty"`
	DType  string  `json:"dtype,omitempty"`
	Shape  []int64 `json:"shape,omitempty"`
	Format string  `json:"format,omitempty"`
}

// FileComponent is one physical file the model is made of.
type FileComponent struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	// SHA256 is kept because it is what the surrounding ecosystem reads: BOM
	// references, registry digests and most existing tooling assume it.
	SHA256 string `json:"sha256,omitempty"`
	// SHA384 is the digest national-security guidance asks for. CNSA 2.0
	// requires SHA-384 or stronger, and BSI TR-02102-1 and ANSSI concur, so a
	// document carrying only SHA-256 cannot be used where those apply. Both are
	// emitted: one for interoperability, one for assurance, computed in a single
	// pass over the file.
	SHA384 string `json:"sha384,omitempty"`
	// SHA512 is the digest BSI TR-03183-2 names. Its §5.2.2 requires the hash
	// value of a deployable component "as SHA-512", not as a digest of at
	// least that strength — so a document carrying SHA-384 is stronger by
	// CNSA's measure and still not conformant by BSI's. With no Commission
	// implementing act under CRA Article 13(24) and no cited harmonised
	// standard, TR-03183-2 is the operative specification of what a CRA SBOM
	// has to contain, which makes this a required field rather than a third
	// opinion.
	SHA512 string `json:"sha512,omitempty"`
	// Role is primary, shard, or external-data.
	Role string `json:"role,omitempty"`
}

// Tensor is one weight tensor's shape, for the bounded inventory.
type Tensor struct {
	Name  string  `json:"name"`
	DType string  `json:"dtype,omitempty"`
	Shape []int64 `json:"shape,omitempty"`
}

// Runtime is the load-time contract and its risk surface.
type Runtime struct {
	Framework    string  `json:"framework,omitempty"`
	Producer     string  `json:"producer,omitempty"`
	IRVersion    string  `json:"irVersion,omitempty"`
	OpsetImports []Opset `json:"opsetImports,omitempty"`
	// CustomDomains lists ONNX operator domains outside the standard set. A
	// custom domain means the graph resolves ops to out-of-tree native kernels.
	CustomDomains []string `json:"customDomains,omitempty"`
}

// Opset is one ONNX operator-set import.
type Opset struct {
	Domain  string `json:"domain"`
	Version int64  `json:"version"`
}

// Finding is one security observation. It mirrors the shape a downstream
// scanner or policy engine expects, so findings serialize cleanly into a VDR.
type Finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Category    string `json:"category,omitempty"`
	Location    string `json:"location,omitempty"`
	Description string `json:"description,omitempty"`
}

// SetRaw records a disclosed field verbatim, skipping empty values so the Raw
// map stays a record of what was actually present.
func (a *Artifact) SetRaw(key, value string) {
	if value == "" {
		return
	}
	if a.Raw == nil {
		a.Raw = map[string]string{}
	}
	a.Raw[key] = value
}

// AddFinding appends a security observation.
func (a *Artifact) AddFinding(f Finding) {
	a.Findings = append(a.Findings, f)
}

// PrimaryFile returns the file marked as the model's primary file, or the
// first file if none is marked, or a zero value if there are none.
func (a *Artifact) PrimaryFile() FileComponent {
	for _, f := range a.Files {
		if f.Role == "primary" {
			return f
		}
	}
	if len(a.Files) > 0 {
		return a.Files[0]
	}
	return FileComponent{}
}

// HasFinding reports whether a finding with the given ID has already been
// recorded. Conditions that can recur while walking one artifact use it to
// report themselves once rather than once per occurrence.
func (a *Artifact) HasFinding(id string) bool {
	for _, f := range a.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

// SeverityCounts is a tally of findings by severity.
//
// It lives here, beside Finding, because more than one subsystem needs to count
// the same things: the gate weighs them into a verdict and the ingestion
// parsers produce them from other scanners' output. Defining it twice — which
// is how it started — meant one library exposing two structurally identical
// types for one concept, and every consumer writing a conversion between them
// that could only ever be the identity function.
type SeverityCounts struct {
	Critical int32 `json:"critical,omitempty"`
	High     int32 `json:"high,omitempty"`
	Medium   int32 `json:"medium,omitempty"`
	Low      int32 `json:"low,omitempty"`
	Unknown  int32 `json:"unknown,omitempty"`
}

// Total is every finding counted, whatever its severity.
func (s SeverityCounts) Total() int32 {
	return s.Critical + s.High + s.Medium + s.Low + s.Unknown
}

// Derivation records that this artifact was produced from another one by an
// automated transformation — today, hardening.
//
// Deliberately separate from Lineage. Lineage is what the model's own metadata
// *claims* about its ancestry: the base model it was fine-tuned from, the
// datasets it saw. This is what a tool *did*, to specific bytes, at a known
// time, and it is knowable exactly rather than read off a model card. Merging
// the two would put a verifiable fact and an unverified assertion in the same
// list with nothing to tell them apart.
type Derivation struct {
	Source  DerivationSource   `json:"source"`
	Changes []DerivationChange `json:"changes,omitempty"`
	// ProducedAt is when the derivative was written, RFC 3339 in UTC.
	ProducedAt string `json:"producedAt,omitempty"`
	Tool       string `json:"tool,omitempty"`
	// Notes carries commentary that belongs with the pedigree rather than with
	// any single change — including, when it applies, the fact that the
	// derivation could not be verified.
	Notes string `json:"notes,omitempty"`
	// Unverified marks a derivation the producer could not confirm it performed.
	//
	// Such a derivation is reported but never asserted: no ancestor, no change,
	// no resolved finding is emitted structurally on its word, because a
	// consumer reads structure and ignores prose. Only the note survives, which
	// tells a human a claim exists without telling a machine it is true.
	Unverified bool `json:"unverified,omitempty"`
}

// DerivationSource identifies the artifact a derivative came from.
type DerivationSource struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	// Path is what an operator called it; useful to a human, not authoritative.
	Path string `json:"path,omitempty"`
	// SHA256 is the durable link and the part a reader can check for
	// themselves. A pedigree naming only a path asserts something unfalsifiable;
	// naming a digest lets anybody holding the original confirm or refute it.
	SHA256 string `json:"sha256,omitempty"`
	PURL   string `json:"purl,omitempty"`
	// Verdict is what the source scanned as, so the improvement is legible from
	// the document alone.
	Verdict string `json:"verdict,omitempty"`
}

// DerivationChange is one deviation from the source.
type DerivationChange struct {
	// Summary is a short mechanical description: "removed tokenizer.pkl".
	Summary string `json:"summary"`
	// Description is why it was done.
	Description string `json:"description,omitempty"`
	// Consequence states what the change may break.
	Consequence string `json:"consequence,omitempty"`
	// Resolves are the findings this change answers.
	Resolves []DerivationIssue `json:"resolves,omitempty"`
}

// DerivationIssue is a finding a change resolves.
type DerivationIssue struct {
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	References  []string `json:"references,omitempty"`
}

// Considerations is the governance half of a model card: who it is for, what it
// must not be used for, and what it gets wrong.
//
// CycloneDX has a modelCard.considerations block for exactly this, and it is the
// part regulators read. The EU AI Act asks about intended purpose and known
// limitations; NIST AI RMF asks who is affected. A document that carries
// architecture and precision but leaves this empty answers the engineer's
// questions and none of the reviewer's.
//
// Every field here is *declared*. Nothing in a weights file states an intended
// use, and this package is careful elsewhere to separate what was measured from
// what was claimed — so these travel as prose read from a model card, attributed
// to it, and never presented as verified.
type Considerations struct {
	// Users are the intended audiences.
	Users []string `json:"users,omitempty"`
	// UseCases are the intended applications.
	UseCases []string `json:"useCases,omitempty"`
	// TechnicalLimitations is what the model is known to do badly.
	TechnicalLimitations []string `json:"technicalLimitations,omitempty"`
	// PerformanceTradeoffs records where accuracy was traded for something else.
	PerformanceTradeoffs []string `json:"performanceTradeoffs,omitempty"`
	// EthicalConsiderations are named risks, each optionally with a mitigation.
	EthicalConsiderations []Risk `json:"ethicalConsiderations,omitempty"`
	// Source names the file these were read from, so a reader can go and check.
	Source string `json:"source,omitempty"`
}

// Risk is a named concern and what, if anything, is done about it.
type Risk struct {
	Name               string `json:"name"`
	MitigationStrategy string `json:"mitigationStrategy,omitempty"`
}

// Empty reports whether anything was found.
func (c Considerations) Empty() bool {
	return len(c.Users) == 0 && len(c.UseCases) == 0 && len(c.TechnicalLimitations) == 0 &&
		len(c.PerformanceTradeoffs) == 0 && len(c.EthicalConsiderations) == 0
}
