// Package emit serializes a parsed Artifact into standard bills of materials.
// Two emitters read the identical IR — CycloneDX (1.6 or 1.7) and SPDX 3.0.1 —
// so the
// two documents can never disagree about the same model. Both are deterministic
// given their inputs: the only varying field is the timestamp, which the caller
// supplies, so the same file and the same clock produce byte-identical output.
package emit

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/strutil"
)

// Tool identifies the generator in the BOM metadata.
//
// It is a value rather than a package global on purpose. Globals here were a
// real defect: the shared-library entry point assigned one on every call, which
// is a data race between concurrent FFI callers, and the CLI's build stamp
// never reached the emitter at all, so released binaries wrote "dev" into the
// tools section of every document they produced. A BOM consumer reads that
// field to decide which scanner version made the claim, so it has to be true.
type Tool struct {
	Name    string
	Version string
	Vendor  string
}

// Supported CycloneDX specification versions.
//
// 1.6 stays the default because it is what the surrounding ecosystem consumes
// today; 1.7 is offered for readers that require the current spec. The two are
// interchangeable for this document: the modelCard and componentData schemas
// are property-for-property identical across them, verified against both
// published schemas rather than assumed, so the same IR serializes to either
// without losing or inventing a field. What 1.7 adds — citations, patent
// assertions, component version ranges — describes facts a model binary does
// not carry, so nothing here would populate them.
const (
	CycloneDX16 = "1.6"
	CycloneDX17 = "1.7"

	// CycloneDXDefault is the version CycloneDX emits when none is named.
	CycloneDXDefault = CycloneDX16
)

// CycloneDX renders the artifact as a CycloneDX ML-BOM at the default spec
// version. The modelCard is hand-serialized because the reference cyclonedx
// libraries still do not model it (CycloneDX/cyclonedx-python-lib#912);
// emitting the schema directly is the only faithful path today.
func CycloneDX(a *model.Artifact, generatedAt time.Time, tool Tool) ([]byte, error) {
	return CycloneDXVersion(a, generatedAt, tool, CycloneDXDefault)
}

// CycloneDXVersion renders the artifact at a named CycloneDX spec version.
//
// An unrecognized version is an error rather than a silent fallback. A document
// whose specVersion does not match the shape it was written to is worse than no
// document: it validates against the wrong schema and misleads every reader
// downstream.
func CycloneDXVersion(a *model.Artifact, generatedAt time.Time, tool Tool, specVersion string) ([]byte, error) {
	switch specVersion {
	case CycloneDX16, CycloneDX17:
	default:
		return nil, fmt.Errorf(
			"unsupported CycloneDX version %q; supported: %s, %s",
			specVersion, CycloneDX16, CycloneDX17)
	}

	primary := a.PrimaryFile()
	modelRef := "urn:tessera:model:" + shortID(primary.SHA256, a.Identity.Name)

	doc := cdxDoc{
		BOMFormat:    "CycloneDX",
		SpecVersion:  specVersion,
		SerialNumber: "urn:uuid:" + deterministicUUID(primary.SHA256+a.Identity.Name),
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: generatedAt.UTC().Format(time.RFC3339),
			// The lifecycle stage this document describes. "post-build" is the
			// honest answer and a distinctive one: Tessera reads a shipped
			// artifact, not a build. The ENISA/CISA baseline elements, ISO/IEC
			// 27036-3 Annex B and CISA's 2026 minimum elements all ask for it
			// under the name "generation context" or "life cycle".
			Lifecycles: []cdxLifecycle{{Phase: "post-build"}},
			Tools: cdxTools{Components: []cdxComponent{{
				Type: "application", Name: tool.Name, Version: tool.Version, Publisher: tool.Vendor,
			}}},
			Component: modelComponent(a, modelRef),
		},
	}

	// Shards and external-data files become file subcomponents, each pinned by
	// its own hash — a multi-file model is a set of components, not one blob.
	for _, f := range a.Files {
		if f.Role == "primary" {
			continue
		}
		doc.Components = append(doc.Components, cdxComponent{
			Type:   "file",
			BOMRef: "urn:tessera:file:" + shortID(f.SHA256, f.Path),
			Name:   f.Path,
			Hashes: hashesOf(f),
			Properties: append([]cdxProp{
				{Name: "tessera:role", Value: f.Role},
				{Name: "tessera:size", Value: fmt.Sprintf("%d", f.Size)},
			}, bsiProperties(a, f)...),
		})
	}

	// ONNX custom operator domains are required runtime components: the graph
	// cannot execute without their native kernel libraries.
	for _, dom := range a.Runtime.CustomDomains {
		doc.Components = append(doc.Components, cdxComponent{
			Type:   "library",
			BOMRef: "urn:tessera:op-domain:" + strutil.Slug(dom, "x"),
			Name:   dom,
			Properties: []cdxProp{
				{Name: "tessera:role", Value: "custom-operator-domain"},
				{Name: "tessera:note", Value: "resolves to an out-of-tree native kernel at load time"},
			},
		})
	}

	// Findings ride along as a vulnerability-disclosure report affecting the
	// model component, so the BOM and the risk verdict stay together.
	for _, f := range a.Findings {
		doc.Vulnerabilities = append(doc.Vulnerabilities, cdxVuln{
			ID:          f.ID,
			Source:      cdxSource{Name: "Tessera"},
			Ratings:     []cdxRating{{Severity: strings.ToLower(f.Severity), Method: "other"}},
			Description: f.Title + " — " + f.Description,
			Affects:     []cdxAffect{{Ref: modelRef}},
		})
	}

	return marshal(doc)
}

func modelComponent(a *model.Artifact, ref string) cdxComponent {
	c := cdxComponent{
		Type:        "machine-learning-model",
		BOMRef:      ref,
		Name:        a.Identity.Name,
		Version:     a.Identity.Version,
		Description: a.Identity.Description,
		PURL:        purlFor(a),
		Hashes:      hashesOf(a.PrimaryFile()),
		Licenses:    licenseChoices(a.Licenses),
	}
	if a.Identity.Author != "" || a.Identity.Organization != "" {
		c.Supplier = &cdxOrg{Name: cmp.Or(a.Identity.Organization, a.Identity.Author)}
	}
	if a.Identity.Author != "" {
		c.Publisher = a.Identity.Author
	}
	c.ExternalReferences = externalRefs(a)
	c.ModelCard = modelCard(a)
	c.Properties = modelProperties(a)
	if ped := pedigree(a); ped != nil {
		c.Pedigree = ped
	}
	return c
}

func modelCard(a *model.Artifact) *cdxModelCard {
	mp := &cdxModelParams{
		ArchitectureFamily: a.Params.ArchitectureFamily,
		ModelArchitecture:  a.Params.Architecture,
		// Declared, not measured: nothing in a weights file says what a model
		// is for. It is emitted because CycloneDX has a field for it and the
		// G7 minimum elements ask for it, not because it was verified.
		Task: a.Declared.Task,
	}
	for _, ds := range a.Lineage.Datasets {
		mp.Datasets = append(mp.Datasets, cdxDataset{Type: "dataset", Name: ds.Name})
	}
	for _, io := range a.Params.Inputs {
		mp.Inputs = append(mp.Inputs, cdxIO{Format: ioFormat(io)})
	}
	for _, io := range a.Params.Outputs {
		mp.Outputs = append(mp.Outputs, cdxIO{Format: ioFormat(io)})
	}
	// Omit an all-empty modelParameters rather than emit a hollow object.
	var mpp *cdxModelParams
	if mp.ArchitectureFamily != "" || mp.ModelArchitecture != "" || len(mp.Datasets) > 0 ||
		mp.Task != "" || len(mp.Inputs) > 0 || len(mp.Outputs) > 0 {
		mpp = mp
	}

	var props []cdxProp
	if a.Params.Quantization != "" {
		props = append(props, cdxProp{Name: "tessera:quantization", Value: a.Params.Quantization})
	}
	if a.Params.ParameterCount != "" {
		props = append(props, cdxProp{Name: "tessera:parameterCount", Value: a.Params.ParameterCount})
	}
	for _, k := range slices.Sorted(maps.Keys(a.Params.Hyperparameters)) {
		props = append(props, cdxProp{Name: "hyperparameter:" + k, Value: a.Params.Hyperparameters[k]})
	}

	if mpp == nil && len(props) == 0 {
		return nil
	}
	return &cdxModelCard{ModelParameters: mpp, Properties: props}
}

// bsiProperties emits the three component properties BSI TR-03183-2 §5.2.2
// requires, plus the filename, under the names BSI's own CycloneDX property
// taxonomy defines.
//
// They are emitted rather than only measured. A coverage report claiming an
// element is populated when the document does not carry it is a claim of
// conformance with nothing behind it, which is the same defect as a compliance
// mapping citing a finding ID nothing emits.
func bsiProperties(a *model.Artifact, f model.FileComponent) []cdxProp {
	props := []cdxProp{
		{Name: "bsi:component:executable", Value: a.FileExecutableProperty(f)},
		{Name: "bsi:component:archive", Value: a.ArchiveProperty()},
		{Name: "bsi:component:structured", Value: a.FileStructuredProperty(f)},
	}
	if f.Path != "" {
		props = append(props, cdxProp{Name: "bsi:component:filename", Value: f.Path})
	}
	return props
}

func modelProperties(a *model.Artifact) []cdxProp {
	var props []cdxProp
	add := func(name, val string) {
		if val != "" {
			props = append(props, cdxProp{Name: name, Value: val})
		}
	}
	add("tessera:format", string(a.Format))
	add("tessera:framework", a.Runtime.Framework)
	add("tessera:uuid", a.Identity.UUID)
	add("tessera:irVersion", a.Runtime.IRVersion)
	add("tessera:producer", a.Runtime.Producer)
	if a.TensorCount > 0 {
		add("tessera:tensorCount", fmt.Sprintf("%d", a.TensorCount))
	}
	props = append(props, bsiProperties(a, a.PrimaryFile())...)
	if p := a.PrimaryFile().Path; p != "" {
		// The model component is named for the model, so the primary file's own
		// path would otherwise be unrecoverable — and a document that cannot
		// identify its primary component cannot be verified against one.
		add("tessera:primaryFile", p)
	}
	if a.Params.MeasuredParameters > 0 {
		// Distinct from any declared size label. This is the figure summed from
		// every tensor shape in the file, and the one EU AI Act Annex XI 1(d)
		// means by "the number of parameters".
		add("tessera:measuredParameters", fmt.Sprintf("%d", a.Params.MeasuredParameters))
	}
	for _, op := range a.Runtime.OpsetImports {
		dom := op.Domain
		if dom == "" {
			dom = "ai.onnx"
		}
		add("onnx:opset:"+dom, fmt.Sprintf("%d", op.Version))
	}
	return props
}

func pedigree(a *model.Artifact) *cdxPedigree {
	var ancestors []cdxComponent
	for _, ref := range a.Lineage.BaseModels {
		ancestors = append(ancestors, cdxComponent{
			Type: "machine-learning-model", Name: ref.Name,
			ExternalReferences: refToExt(ref),
		})
	}
	for _, ref := range a.Lineage.Sources {
		ancestors = append(ancestors, cdxComponent{
			Type: "machine-learning-model", Name: ref.Name,
			ExternalReferences: refToExt(ref),
		})
	}
	if len(ancestors) == 0 {
		return nil
	}
	return &cdxPedigree{Ancestors: ancestors}
}

func externalRefs(a *model.Artifact) []cdxExtRef {
	var refs []cdxExtRef
	if a.Identity.URL != "" {
		refs = append(refs, cdxExtRef{Type: "website", URL: a.Identity.URL})
	}
	if a.Identity.RepoURL != "" && a.Identity.RepoURL != a.Identity.URL {
		refs = append(refs, cdxExtRef{Type: "vcs", URL: a.Identity.RepoURL})
	}
	if a.Identity.DOI != "" {
		refs = append(refs, cdxExtRef{Type: "other", URL: "https://doi.org/" + strings.TrimPrefix(a.Identity.DOI, "doi:")})
	}
	return refs
}

func refToExt(ref model.Reference) []cdxExtRef {
	var out []cdxExtRef
	if ref.URL != "" {
		out = append(out, cdxExtRef{Type: "vcs", URL: ref.URL})
	}
	if ref.DOI != "" {
		out = append(out, cdxExtRef{Type: "other", URL: "https://doi.org/" + strings.TrimPrefix(ref.DOI, "doi:")})
	}
	return out
}

func licenseChoices(licenses []model.License) []cdxLicenseChoice {
	var out []cdxLicenseChoice
	for _, l := range licenses {
		lic := cdxLicense{}
		switch {
		case l.SPDXID != "" && !strings.HasPrefix(l.SPDXID, "LicenseRef-"):
			lic.ID = l.SPDXID
		case l.SPDXID != "":
			lic.Name = l.SPDXID // LicenseRef- is not a valid CDX license id enum
		default:
			lic.Name = l.Raw
		}
		if l.URL != "" {
			lic.URL = l.URL
		}
		out = append(out, cdxLicenseChoice{License: lic})
	}
	return out
}

func ioFormat(io model.IOSpec) string {
	if io.DType == "" && len(io.Shape) == 0 {
		return io.Format
	}
	dims := make([]string, len(io.Shape))
	for i, d := range io.Shape {
		if d < 0 {
			// A symbolic axis — a named batch dimension, say. Rendering it as
			// -1 would read as a real extent; "?" says it is dynamic.
			dims[i] = "?"
		} else {
			dims[i] = fmt.Sprintf("%d", d)
		}
	}
	return fmt.Sprintf("%s[%s]", io.DType, strings.Join(dims, ","))
}

// hashesOf emits every digest computed for a component.
//
// All three are carried deliberately, because three published requirements
// name three different digests and none of them accepts a substitute:
//
//   - SHA-256 is what the surrounding ecosystem reads. A document without it
//     is illegible to most existing tooling.
//   - SHA-384 is the weakest digest CNSA 2.0 permits, and BSI TR-02102-1 and
//     ANSSI concur. A document without it cannot be used under
//     national-security guidance.
//   - SHA-512 is what BSI TR-03183-2 §5.2.2 names for a deployable component
//     — by algorithm, not by strength — so SHA-384 does not satisfy it even
//     though CNSA considers it sufficient.
//
// The G7 minimum elements ask for the algorithm to be named from the IANA
// registry precisely so a verifier can pick one and recompute it. Emitting
// all three lets the verifier pick the one their own rules name.
func hashesOf(f model.FileComponent) []cdxHash {
	var out []cdxHash
	if f.SHA256 != "" {
		out = append(out, cdxHash{Alg: "SHA-256", Content: f.SHA256})
	}
	if f.SHA384 != "" {
		out = append(out, cdxHash{Alg: "SHA-384", Content: f.SHA384})
	}
	if f.SHA512 != "" {
		out = append(out, cdxHash{Alg: "SHA-512", Content: f.SHA512})
	}
	return out
}

// --- CycloneDX JSON model ---

type cdxDoc struct {
	BOMFormat       string         `json:"bomFormat"`
	SpecVersion     string         `json:"specVersion"`
	SerialNumber    string         `json:"serialNumber"`
	Version         int            `json:"version"`
	Metadata        cdxMetadata    `json:"metadata"`
	Components      []cdxComponent `json:"components,omitempty"`
	Vulnerabilities []cdxVuln      `json:"vulnerabilities,omitempty"`
}

type cdxLifecycle struct {
	Phase string `json:"phase"`
}

type cdxMetadata struct {
	Timestamp  string         `json:"timestamp"`
	Tools      cdxTools       `json:"tools"`
	Component  cdxComponent   `json:"component"`
	Lifecycles []cdxLifecycle `json:"lifecycles,omitempty"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type               string             `json:"type"`
	BOMRef             string             `json:"bom-ref,omitempty"`
	Name               string             `json:"name"`
	Version            string             `json:"version,omitempty"`
	PURL               string             `json:"purl,omitempty"`
	Description        string             `json:"description,omitempty"`
	Publisher          string             `json:"publisher,omitempty"`
	Supplier           *cdxOrg            `json:"supplier,omitempty"`
	Licenses           []cdxLicenseChoice `json:"licenses,omitempty"`
	Hashes             []cdxHash          `json:"hashes,omitempty"`
	ExternalReferences []cdxExtRef        `json:"externalReferences,omitempty"`
	ModelCard          *cdxModelCard      `json:"modelCard,omitempty"`
	Pedigree           *cdxPedigree       `json:"pedigree,omitempty"`
	Properties         []cdxProp          `json:"properties,omitempty"`
}

type cdxOrg struct {
	Name string `json:"name"`
}

type cdxLicenseChoice struct {
	License cdxLicense `json:"license"`
}

type cdxLicense struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxExtRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type cdxModelCard struct {
	ModelParameters *cdxModelParams `json:"modelParameters,omitempty"`
	Properties      []cdxProp       `json:"properties,omitempty"`
}

type cdxModelParams struct {
	// Task is CycloneDX's field for what the model is for.
	Task               string       `json:"task,omitempty"`
	ArchitectureFamily string       `json:"architectureFamily,omitempty"`
	ModelArchitecture  string       `json:"modelArchitecture,omitempty"`
	Datasets           []cdxDataset `json:"datasets,omitempty"`
	Inputs             []cdxIO      `json:"inputs,omitempty"`
	Outputs            []cdxIO      `json:"outputs,omitempty"`
}

type cdxDataset struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

type cdxIO struct {
	Format string `json:"format,omitempty"`
}

type cdxPedigree struct {
	Ancestors []cdxComponent `json:"ancestors,omitempty"`
}

type cdxProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxVuln struct {
	BOMRef      string      `json:"bom-ref,omitempty"`
	ID          string      `json:"id"`
	Source      cdxSource   `json:"source"`
	Ratings     []cdxRating `json:"ratings,omitempty"`
	Description string      `json:"description,omitempty"`
	Affects     []cdxAffect `json:"affects,omitempty"`
}

type cdxSource struct {
	Name string `json:"name"`
}

type cdxRating struct {
	Severity string `json:"severity"`
	Method   string `json:"method,omitempty"`
}

type cdxAffect struct {
	Ref string `json:"ref"`
}

// --- shared helpers ---

func marshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// shortID builds a stable short reference from a hash and a fallback string.
func shortID(sha, fallback string) string {
	if len(sha) >= 16 {
		return sha[:16]
	}
	return strutil.Slug(fallback, "x")
}

// deterministicUUID derives a stable RFC-4122-shaped UUID (v4 nibbles) from a
// seed, so the BOM serial number is reproducible for the same input.
func deterministicUUID(seed string) string {
	sum := sha256.Sum256([]byte("tessera:" + seed))
	h := hex.EncodeToString(sum[:16])
	b := []byte(h)
	b[12] = '4'                   // version 4
	b[16] = "89ab"[int(sum[8])%4] // variant
	return fmt.Sprintf("%s-%s-%s-%s-%s", b[0:8], b[8:12], b[12:16], b[16:20], b[20:32])
}
