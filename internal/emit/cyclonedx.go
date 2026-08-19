// Package emit serializes a parsed Artifact into standard bills of materials.
// Two emitters read the identical IR — CycloneDX 1.6 and SPDX 3.0.1 — so the
// two documents can never disagree about the same model. Both are deterministic
// given their inputs: the only varying field is the timestamp, which the caller
// supplies, so the same file and the same clock produce byte-identical output.
package emit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
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

// CycloneDX renders the artifact as a CycloneDX 1.6 ML-BOM. The modelCard is
// hand-serialized because the reference cyclonedx libraries still do not model
// it (CycloneDX/cyclonedx-python-lib#912); emitting the schema directly is the
// only faithful path today.
func CycloneDX(a *model.Artifact, generatedAt time.Time, tool Tool) ([]byte, error) {
	primary := a.PrimaryFile()
	modelRef := "urn:tessera:model:" + shortID(primary.SHA256, a.Identity.Name)

	doc := cdxDoc{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + deterministicUUID(primary.SHA256+a.Identity.Name),
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: generatedAt.UTC().Format(time.RFC3339),
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
			Hashes: hashesOf(f.SHA256),
			Properties: []cdxProp{
				{Name: "tessera:role", Value: f.Role},
				{Name: "tessera:size", Value: fmt.Sprintf("%d", f.Size)},
			},
		})
	}

	// ONNX custom operator domains are required runtime components: the graph
	// cannot execute without their native kernel libraries.
	for _, dom := range a.Runtime.CustomDomains {
		doc.Components = append(doc.Components, cdxComponent{
			Type:   "library",
			BOMRef: "urn:tessera:op-domain:" + sanitize(dom),
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
		Hashes:      hashesOf(a.PrimaryFile().SHA256),
		Licenses:    licenseChoices(a.Licenses),
	}
	if a.Identity.Author != "" || a.Identity.Organization != "" {
		c.Supplier = &cdxOrg{Name: firstNonEmpty(a.Identity.Organization, a.Identity.Author)}
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
		len(mp.Inputs) > 0 || len(mp.Outputs) > 0 {
		mpp = mp
	}

	var props []cdxProp
	if a.Params.Quantization != "" {
		props = append(props, cdxProp{Name: "tessera:quantization", Value: a.Params.Quantization})
	}
	if a.Params.ParameterCount != "" {
		props = append(props, cdxProp{Name: "tessera:parameterCount", Value: a.Params.ParameterCount})
	}
	for _, k := range sortedKeys(a.Params.Hyperparameters) {
		props = append(props, cdxProp{Name: "hyperparameter:" + k, Value: a.Params.Hyperparameters[k]})
	}

	if mpp == nil && len(props) == 0 {
		return nil
	}
	return &cdxModelCard{ModelParameters: mpp, Properties: props}
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
		dims[i] = fmt.Sprintf("%d", d)
	}
	return fmt.Sprintf("%s[%s]", io.DType, strings.Join(dims, ","))
}

func hashesOf(sha string) []cdxHash {
	if sha == "" {
		return nil
	}
	return []cdxHash{{Alg: "SHA-256", Content: sha}}
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

type cdxMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     cdxTools     `json:"tools"`
	Component cdxComponent `json:"component"`
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// simple insertion sort to avoid importing sort here
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// shortID builds a stable short reference from a hash and a fallback string.
func shortID(sha, fallback string) string {
	if len(sha) >= 16 {
		return sha[:16]
	}
	return sanitize(fallback)
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

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "x"
	}
	return out
}
