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
