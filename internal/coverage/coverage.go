// Package coverage reports which elements of a published minimum-elements
// standard a bill of materials actually populates.
//
// The G7 "SBOM for AI — Minimum Elements" (May 2026) is the checklist a defence
// or regulated buyer will hold this output against, and India's CERT-In
// guidelines publish a comparable table. Both enumerate elements; neither ships
// anything that measures conformance.
//
// The point of reporting coverage rather than claiming it is that the gaps are
// the honest part. A model file cannot disclose its training datasets or its
// evaluation metrics, and no amount of parsing will change that — so a tool that
// quietly omits those rows is inviting a buyer to discover them later. Naming
// them, with the reason, is worth more than a higher percentage.
package coverage

import (
	"fmt"
	"sort"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// Standard identifies a published minimum-elements list.
type Standard string

const (
	// G7 is "Software Bill of Materials (SBOM) for Artificial Intelligence —
	// Minimum Elements", G7 Cybersecurity Working Group, 12 May 2026.
	G7 Standard = "g7"
	// CERTIn is CERT-In's "Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and
	// HBOM" v2.0, section 9, 9 July 2025.
	CERTIn Standard = "cert-in"
)

// Status of one element.
type Status string

const (
	// Populated means this artifact supplied the element.
	Populated Status = "populated"
	// Absent means the element is derivable in principle but this particular
	// artifact did not disclose it.
	Absent Status = "absent"
	// OutOfScope means no static parse of a model file can ever supply it.
	// Distinguished from Absent because the remedy is different: one is a
	// property of the artifact, the other a property of the method.
	OutOfScope Status = "out-of-scope"
)

// Element is one row of a standard's minimum-element table.
type Element struct {
	Cluster string `json:"cluster"`
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Value   string `json:"value,omitempty"`
	// Note explains an out-of-scope element, so the gap carries its reason
	// rather than reading as an omission.
	Note string `json:"note,omitempty"`
}

// Report is the coverage of one standard by one artifact.
type Report struct {
	Standard   Standard  `json:"standard"`
	Title      string    `json:"title"`
	Elements   []Element `json:"elements"`
	Populated  int       `json:"populated"`
	Absent     int       `json:"absent"`
	OutOfScope int       `json:"outOfScope"`
}

// Standards lists what can be reported against.
func Standards() []Standard { return []Standard{G7, CERTIn} }

// Assess reports coverage of a standard by an artifact.
func Assess(std Standard, a *model.Artifact) (*Report, error) {
	switch std {
	case G7:
		return assess(G7, "G7 SBOM for AI — Minimum Elements (12 May 2026)", g7Elements(a)), nil
	case CERTIn:
		return assess(CERTIn, "CERT-In Technical Guidelines v2.0 §9 — AIBOM (9 July 2025)", certInElements(a)), nil
	}
	return nil, fmt.Errorf("unknown standard %q (known: g7, cert-in)", std)
}

func assess(std Standard, title string, els []Element) *Report {
	r := &Report{Standard: std, Title: title, Elements: els}
	for _, e := range els {
		switch e.Status {
		case Populated:
			r.Populated++
		case Absent:
			r.Absent++
		case OutOfScope:
			r.OutOfScope++
		}
	}
	sort.SliceStable(r.Elements, func(i, j int) bool {
		if r.Elements[i].Cluster != r.Elements[j].Cluster {
			return r.Elements[i].Cluster < r.Elements[j].Cluster
		}
		return r.Elements[i].Name < r.Elements[j].Name
	})
	return r
}

// have reports an element as populated when the value is non-empty.
func have(cluster, name, value string) Element {
	if value == "" {
		return Element{Cluster: cluster, Name: name, Status: Absent}
	}
	return Element{Cluster: cluster, Name: name, Status: Populated, Value: value}
}

// cannot marks an element no static parse can supply.
func cannot(cluster, name, why string) Element {
	return Element{Cluster: cluster, Name: name, Status: OutOfScope, Note: why}
}

// g7Elements maps the G7 minimum elements onto what was parsed.
//
// The Models cluster is where this tool is strongest, because the G7 document
// made a model hash a required element and named the algorithm from the IANA
// registry so a verifier could recompute it — which is precisely a measured
// fact rather than a declared one.
func g7Elements(a *model.Artifact) []Element {
	primary := a.PrimaryFile()
	var els []Element

	// Cluster 1 — Metadata.
	els = append(els,
		have("Metadata", "SBOM author", "tessera"),
		have("Metadata", "Timestamp", "generated per document"),
		have("Metadata", "Generation context", "post-build"),
	)

	// Cluster 3 — Models.
	els = append(els,
		have("Models", "Model name", a.Identity.Name),
		have("Models", "Model version", a.Identity.Version),
		have("Models", "Model producer", firstOf(a.Identity.Organization, a.Identity.Author, a.Runtime.Producer)),
		have("Models", "Model description", a.Identity.Description),
		have("Models", "Model hash value", primary.SHA384),
		have("Models", "Model hash algorithm", hashAlgorithms(primary)),
		have("Models", "Model license", licenseOf(a)),
		have("Models", "Model identifier", a.Identity.UUID),
		have("Models", "Model properties", architectureOf(a)),
		have("Models", "Model input-output properties", ioOf(a)),
		cannot("Models", "Model training properties",
			"training compute, duration and procedure are not recorded in a weights file"),
		have("Models", "Model external references", firstOf(a.Identity.RepoURL, a.Identity.URL, a.Identity.DOI)),
	)

	// Cluster 4 — Datasets. A model file may name its training datasets, but
	// naming is a claim; the dataset's own hash and properties are not present.
	els = append(els,
		have("Datasets", "Dataset name", datasetNames(a)),
		cannot("Datasets", "Dataset hash value",
			"hashing a dataset requires the dataset, which does not ship with the model"),
		cannot("Datasets", "Dataset properties",
			"size, provenance and preprocessing are properties of data this tool never sees"),
	)

	// Cluster 2 / 5 — System and infrastructure.
	els = append(els,
		have("System", "Model dependencies", customDomains(a)),
		cannot("System", "System-level properties",
			"describes the deployed system, which is not derivable from an artifact on disk"),
		cannot("Infrastructure", "Compute and runtime environment",
			"describes where the model runs, not what it is"),
	)

	// Cluster 6 — Security properties.
	els = append(els,
		have("Security", "Known vulnerabilities and findings", findingSummary(a)),
		have("Security", "Integrity verification", integrityStatement(primary)),
	)

	// Cluster 7 — KPIs.
	els = append(els, cannot("KPI", "Performance indicators",
		"accuracy and benchmark results come from evaluation, not from the file"))

	return els
}

// certInElements maps CERT-In's 18-element AIBOM table.
//
// Notably its table has no hash element at all — eighteen declared facts plus a
// signature field — so this tool exceeds it on the measured axis while falling
// short on the descriptive one.
func certInElements(a *model.Artifact) []Element {
	primary := a.PrimaryFile()
	return []Element{
		have("AIBOM", "Model Name", a.Identity.Name),
		have("AIBOM", "Model Version", a.Identity.Version),
		have("AIBOM", "Model Type", architectureOf(a)),
		have("AIBOM", "Model Developer", firstOf(a.Identity.Organization, a.Identity.Author)),
		have("AIBOM", "Model Licensing Information", licenseOf(a)),
		have("AIBOM", "Software Dependencies", customDomains(a)),
		have("AIBOM", "ML Models and Algorithms", architectureOf(a)),
		cannot("AIBOM", "Model Performance Metrics",
			"benchmark results come from evaluation, not from the file"),
		have("AIBOM", "Data Source", datasetNames(a)),
		have("AIBOM", "Data Sets", datasetNames(a)),
		cannot("AIBOM", "Hardware", "the training and serving hardware is not recorded in a weights file"),
		have("AIBOM", "Security Requirements", findingSummary(a)),
		have("AIBOM", "Input", inputsOf(a)),
		have("AIBOM", "Output", outputsOf(a)),
		cannot("AIBOM", "Intended Usage", "intent is stated by a publisher, not encoded in weights"),
		cannot("AIBOM", "Out of Scope Usage", "the same"),
		cannot("AIBOM", "Environmental Impact",
			"training energy and emissions are not recorded in a weights file"),
		have("AIBOM", "Vulnerabilities", findingSummary(a)),
		// The one element CERT-In asks for that this tool supplies by a
		// different route: attestation is a signature over the document, which
		// tessera-sign produces.
		have("AIBOM", "Attestations", integrityStatement(primary)),
	}
}
