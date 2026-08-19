package emit

import (
	"cmp"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/strutil"
)

// SPDX renders the artifact as an SPDX 3.0.1 JSON-LD document using the AI and
// Dataset profiles. The model is an ai_AIPackage; its physical files are Files
// verified by SHA-256 Hash elements; datasets are dataset_DatasetPackages; the
// license is attached with a hasDeclaredLicense relationship. It is a faithful
// subset of the profile — the fields a static file parse can actually populate
// — not the whole schema, and it says so.
func SPDX(a *model.Artifact, generatedAt time.Time, tool Tool) ([]byte, error) {
	ns := "https://spdx.org/spdxdocs/tessera/" + deterministicUUID(a.PrimaryFile().SHA256+a.Identity.Name)
	id := func(local string) string { return ns + "#" + local }

	created := generatedAt.UTC().Format(time.RFC3339)

	creationInfo := map[string]any{
		"type":         "CreationInfo",
		"@id":          "_:creationinfo",
		"specVersion":  "3.0.1",
		"created":      created,
		"createdBy":    []string{id("tool-tessera")},
		"createdUsing": []string{id("tool-tessera")},
	}

	// The document element. Without it a reader has no root to start from, and
	// no way to see which profiles the document claims to implement — which is
	// the first question a conformance reviewer asks. profileConformance is how
	// SPDX 3 answers it; omitting it leaves the AI profile an inference.
	docElement := map[string]any{
		"type":         "SpdxDocument",
		"spdxId":       id("document"),
		"creationInfo": "_:creationinfo",
		"name":         a.Identity.Name + " bill of materials",
		"profileConformance": []string{
			"core", "software", "ai", "dataset", "simpleLicensing",
		},
		// No dataLicense: it is an SPDX 2.x property, and the 3.0.1 schema sets
		// unevaluatedProperties:false, so carrying it over rejects the whole
		// document element rather than just the one field.
		"rootElement": []string{id("model")},
	}

	graph := []any{
		docElement,
		creationInfo,
		map[string]any{
			"type":         "Tool",
			"spdxId":       id("tool-tessera"),
			"creationInfo": "_:creationinfo",
			"name":         tool.Name + " " + tool.Version,
		},
	}

	// The model as an AI package.
	aiPkg := map[string]any{
		"type":                      "ai_AIPackage",
		"spdxId":                    id("model"),
		"creationInfo":              "_:creationinfo",
		"name":                      a.Identity.Name,
		"software_primaryPurpose":   "other",
		"software_downloadLocation": cmp.Or(a.Identity.URL, a.Identity.RepoURL, "NOASSERTION"),
	}
	if a.Identity.Version != "" {
		aiPkg["software_packageVersion"] = a.Identity.Version
	}
	if sup := cmp.Or(a.Identity.Organization, a.Identity.Author); sup != "" {
		aiPkg["suppliedBy"] = id("supplier")
		graph = append(graph, map[string]any{
			"type":         "Organization",
			"spdxId":       id("supplier"),
			"creationInfo": "_:creationinfo",
			"name":         sup,
		})
	}
	if a.Identity.Description != "" {
		aiPkg["description"] = a.Identity.Description
	}
	if a.Params.Architecture != "" {
		// ai_typeOfModel is multi-valued in the SPDX 3.0.1 model, so it has to
		// be an array even when there is exactly one value. Emitting a bare
		// string parses as JSON but fails the published schema, and the schema
		// sets unevaluatedProperties:false, so the whole object is rejected
		// rather than just the one field.
		aiPkg["ai_typeOfModel"] = []string{a.Params.Architecture}
	}
	// Hyperparameters + quantization as DictionaryEntry values.
	var hp []any
	entry := func(k, v string) map[string]any {
		return map[string]any{"type": "DictionaryEntry", "key": k, "value": v}
	}
	if a.Params.Quantization != "" {
		hp = append(hp, entry("quantization", a.Params.Quantization))
	}
	if a.Params.ParameterCount != "" {
		hp = append(hp, entry("parameterCount", a.Params.ParameterCount))
	}
	// The measured count, kept distinct from any declared label. EU AI Act
	// Annex XI 1(d) asks for "the number of parameters"; this is the one figure
	// in that annex a reader can recompute from the bytes.
	if a.Params.MeasuredParameters > 0 {
		hp = append(hp, entry("measuredParameters", strconv.FormatInt(a.Params.MeasuredParameters, 10)))
	}
	if io := ioSummary(a); io != "" {
		hp = append(hp, entry("inputOutputSignature", io))
	}
	for _, k := range slices.Sorted(maps.Keys(a.Params.Hyperparameters)) {
		hp = append(hp, entry(k, a.Params.Hyperparameters[k]))
	}
	// The primary file's hash verifies the package, and its path is recorded so
	// a verifier can tell which file on disk the package refers to.
	primary := a.PrimaryFile()
	if primary.Path != "" {
		hp = append(hp, entry("primaryFile", primary.Path))
	}
	if len(hp) > 0 {
		aiPkg["ai_hyperparameter"] = hp
	}
	if primary.SHA256 != "" {
		aiPkg["verifiedUsing"] = hashElements(primary)
	}
	graph = append(graph, aiPkg)

	// Physical files (shards, external data) as Software Files, each hashed.
	var relationships []any
	for _, f := range a.Files {
		if f.Role == "primary" {
			continue
		}
		fileID := id("file-" + shortID(f.SHA256, f.Path))
		graph = append(graph, map[string]any{
			"type":          "software_File",
			"spdxId":        fileID,
			"creationInfo":  "_:creationinfo",
			"name":          f.Path,
			"verifiedUsing": hashElements(f),
		})
		relationships = append(relationships, relationship(id, "rel-file-"+shortID(f.SHA256, f.Path),
			id("model"), "contains", []string{fileID}))
	}

	// Datasets as dataset packages, linked by a trainedOn relationship.
	var datasetIDs []string
	for i, ds := range a.Lineage.Datasets {
		dsID := id("dataset-" + strutil.Slug(ds.Name, "x") + "-" + strconv.Itoa(i))
		datasetIDs = append(datasetIDs, dsID)
		graph = append(graph, map[string]any{
			"type":         "dataset_DatasetPackage",
			"spdxId":       dsID,
			"creationInfo": "_:creationinfo",
			"name":         ds.Name,
			// dataset_datasetType is mandatory on a DatasetPackage. A model
			// file names its training datasets but never says what kind they
			// were, so "other" is the honest value — inferring "text" from a
			// name like "wikipedia" would be a guess presented as a fact.
			"dataset_datasetType": []string{"other"},
			// The dataset is referenced by name only; the model file carries no
			// location for it.
			"software_downloadLocation": "NOASSERTION",
		})
	}
	if len(datasetIDs) > 0 {
		relationships = append(relationships, relationship(id, "rel-trainedon",
			id("model"), "trainedOn", datasetIDs))
	}

	// Base models as ancestry.
	var ancestorIDs []string
	for i, ref := range a.Lineage.BaseModels {
		bmID := id("basemodel-" + strutil.Slug(ref.Name, "x") + "-" + strconv.Itoa(i))
		ancestorIDs = append(ancestorIDs, bmID)
		graph = append(graph, map[string]any{
			"type":                      "ai_AIPackage",
			"spdxId":                    bmID,
			"creationInfo":              "_:creationinfo",
			"name":                      ref.Name,
			"software_downloadLocation": cmp.Or(ref.URL, "NOASSERTION"),
		})
	}
	if len(ancestorIDs) > 0 {
		relationships = append(relationships, relationship(id, "rel-ancestry",
			id("model"), "descendantOf", ancestorIDs))
	}

	// License, via a declared-license relationship to a license-expression node.
	if lic := firstResolvedLicense(a); lic != "" {
		licID := id("license")
		graph = append(graph, map[string]any{
			"type":                              "simplelicensing_LicenseExpression",
			"spdxId":                            licID,
			"creationInfo":                      "_:creationinfo",
			"simplelicensing_licenseExpression": lic,
		})
		relationships = append(relationships, relationship(id, "rel-license",
			id("model"), "hasDeclaredLicense", []string{licID}))
	}

	// Findings travel in the SPDX document too. The package doc claims the two
	// bills of materials can never disagree about the same model, and a document
	// carrying the components while the other carries the risk would be exactly
	// that disagreement. SPDX has no vulnerability class in 3.0.1, so each
	// finding becomes an ai_limitation on the package: a stated limit on what
	// the artifact can be relied upon for, which is what a finding is.
	if lims := findingLimitations(a); len(lims) > 0 {
		aiPkg["ai_limitation"] = strings.Join(lims, "\n")
	}

	graph = append(graph, relationships...)

	doc := map[string]any{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		"@graph":   graph,
	}
	return marshal(doc)
}

// ioSummary renders the graph signature as a single line.
//
// Annex XI 1(e) asks for "the modality and format of inputs and outputs". SPDX
// has no structured slot for a tensor signature, so it goes in as a
// hyperparameter entry rather than being dropped.
func ioSummary(a *model.Artifact) string {
	render := func(specs []model.IOSpec) string {
		var parts []string
		for _, s := range specs {
			d := s.DType
			if len(s.Shape) > 0 {
				dims := make([]string, 0, len(s.Shape))
				for _, n := range s.Shape {
					if n < 0 {
						dims = append(dims, "?") // symbolic axis, e.g. batch
					} else {
						dims = append(dims, strconv.FormatInt(n, 10))
					}
				}
				d += "[" + strings.Join(dims, "x") + "]"
			}
			parts = append(parts, cmp.Or(s.Name, "?")+":"+d)
		}
		return strings.Join(parts, ", ")
	}
	in, out := render(a.Params.Inputs), render(a.Params.Outputs)
	if in == "" && out == "" {
		return ""
	}
	return "in(" + in + ") -> out(" + out + ")"
}

// findingLimitations renders findings as human-readable limitation lines,
// most severe first so the worst is read first.
func findingLimitations(a *model.Artifact) []string {
	order := map[string]int{"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
	sorted := append([]model.Finding(nil), a.Findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return order[sorted[i].Severity] < order[sorted[j].Severity]
	})
	out := make([]string, 0, len(sorted))
	for _, f := range sorted {
		out = append(out, "["+f.Severity+"] "+f.ID+": "+f.Title)
	}
	return out
}

// hashElements emits every digest as an SPDX Hash. See hashesOf in the
// CycloneDX emitter for why both are carried.
func hashElements(f model.FileComponent) []any {
	var out []any
	if f.SHA256 != "" {
		out = append(out, hashElement("sha256", f.SHA256))
	}
	if f.SHA384 != "" {
		out = append(out, hashElement("sha384", f.SHA384))
	}
	return out
}

func hashElement(alg, value string) map[string]any {
	return map[string]any{
		"type":      "Hash",
		"algorithm": alg,
		"hashValue": value,
	}
}

func relationship(id func(string) string, local, from, typ string, to []string) map[string]any {
	return map[string]any{
		"type":             "Relationship",
		"spdxId":           id(local),
		"creationInfo":     "_:creationinfo",
		"from":             from,
		"relationshipType": typ,
		"to":               to,
	}
}

func firstResolvedLicense(a *model.Artifact) string {
	for _, l := range a.Licenses {
		if l.SPDXID != "" {
			return l.SPDXID
		}
	}
	for _, l := range a.Licenses {
		if l.Raw != "" {
			return l.Raw
		}
	}
	return ""
}
