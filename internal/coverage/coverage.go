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
	"strings"

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
	// BSI is BSI TR-03183-2 "Cyber Resilience Requirements for Manufacturers
	// and Products — Part 2: Software Bill of Materials (SBOM)", v2.1.0.
	//
	// It is here because it is the only published technical specification of
	// what a Cyber Resilience Act SBOM must contain. The CRA itself requires
	// one "in a commonly used and machine-readable format covering at the very
	// least the top-level dependencies" and stops there; the Article 13(24)
	// implementing act that would define the format has not been adopted, and
	// no harmonised standard has been cited in the Official Journal. Until one
	// is, this document is what an assessor has to work from.
	BSI Standard = "bsi"
	// CISA2026 is "2026 Minimum Elements for a Software Bill of Materials
	// (SBOM)", CISA / NSA / FBI with sixteen international partners, published
	// 29 July 2026. It updates and replaces the 2021 NTIA minimum elements.
	//
	// It is here because it is the baseline a US federal buyer now cites, and
	// because its own text says the elements "apply to SBOMs for all software,
	// including open-source software, AI software, and software-as-a-service" —
	// so a model artifact is squarely in scope rather than covered only by the
	// AI-specific G7 list.
	//
	// The document separates Data Fields, which describe the document, from
	// Practices and Processes, which describe how an organization operates. Only
	// the first can be assessed from an artifact; the second is reported as
	// out-of-scope with that reason attached rather than silently dropped, since
	// a reader comparing against the published table would otherwise find rows
	// missing.
	CISA2026 Standard = "cisa-2026"
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
func Standards() []Standard { return []Standard{G7, CERTIn, BSI, CISA2026} }

// Assess reports coverage of a standard by an artifact.
func Assess(std Standard, a *model.Artifact) (*Report, error) {
	switch std {
	case G7:
		return assess(G7, "G7 SBOM for AI — Minimum Elements (12 May 2026)", g7Elements(a)), nil
	case CERTIn:
		return assess(CERTIn, "CERT-In Technical Guidelines v2.0 §9 — AIBOM (9 July 2025)", certInElements(a)), nil
	case BSI:
		return assess(BSI, "BSI TR-03183-2 v2.1.0 — SBOM required data fields", bsiElements(a)), nil
	case CISA2026:
		return assess(CISA2026, "CISA/NSA/FBI 2026 Minimum Elements for an SBOM (29 July 2026)", cisa2026Elements(a)), nil
	}
	return nil, fmt.Errorf("unknown standard %q (known: g7, cert-in, bsi, cisa-2026)", std)
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

// bsiElements maps BSI TR-03183-2 §5.2 onto what was parsed.
//
// Two things make this table different from the AI-specific ones above.
//
// First, it is not an AI standard at all — it is a general SBOM specification,
// and a model artifact enters it as an ordinary component. That is the point:
// the Cyber Resilience Act's SBOM obligation is technology-neutral, so the
// question an assessor asks is not "is this a good AIBOM" but "is this an SBOM
// at all". A tool that only measures itself against AI checklists never answers
// that.
//
// Second, three of its required fields are determinations rather than
// disclosures. §5.2.2 requires an executable, an archive and a structured
// property on every component, and no model file states any of them. They are
// computed from what the format does — see model.ExecutableProperty — and
// written into the document under BSI's own CycloneDX property names, so the
// coverage claimed here is coverage the emitted document actually carries.
func bsiElements(a *model.Artifact) []Element {
	primary := a.PrimaryFile()
	var els []Element

	// §5.2.1 — required data fields for the SBOM itself.
	els = append(els,
		have("SBOM", "Creator of the SBOM", "https://github.com/DAVANO-INNOVATION-LAB/tessera"),
		have("SBOM", "Timestamp", "generated per document, UTC"),
	)

	// §5.2.3 — additional data fields for the SBOM itself.
	els = append(els, have("SBOM", "SBOM-URI", "urn:uuid, derived from the primary file digest"))

	// §4 — format. CycloneDX 1.6 or higher, SPDX 3.0.1 or higher, and only
	// officially released versions. This row is worth stating because it is
	// the one most existing SBOM tooling fails: an SPDX 2.3 document is not
	// conformant no matter how complete its fields are.
	els = append(els, have("SBOM", "Format and version",
		"CycloneDX 1.6 and SPDX 3.0.1 — the minimum versions §4 permits"))

	// §5.2.2 — required data fields for each component.
	els = append(els,
		// §5.2.2 does not ask who made the component, it asks for a contact:
		// "email address of the entity that created and, if applicable,
		// maintains the respective component. If no email address is available
		// this MUST be a Uniform Resource Locator (URL)". A bare organization
		// name is not either of those, so it does not populate this element
		// however well it identifies the publisher.
		have("Component", "Component creator", creatorContact(a)),
		have("Component", "Component name", a.Identity.Name),
		have("Component", "Component version", a.Identity.Version),
		have("Component", "Filename of the component", primary.Path),
		// The one element a model artifact structurally cannot supply, and the
		// reason a model bill of materials has to be merged rather than used
		// alone.
		dependencyElement(a),
		have("Component", "Distribution licences", licenseOf(a)),
		have("Component", "Hash value of the deployable component (SHA-512)", primary.SHA512),
		have("Component", "Executable property", a.ExecutableProperty()),
		have("Component", "Archive property", a.ArchiveProperty()),
		have("Component", "Structured property", a.StructuredProperty()),
	)

	// §5.2.4 — additional data fields, required where they exist.
	els = append(els,
		have("Component", "Source code URI", a.Identity.RepoURL),
		have("Component", "URI of the deployable form", firstOf(a.Identity.URL, a.Identity.RepoURL)),
		// The emitted document carries a purl when the model discloses a
		// Hugging Face repository, and omits one otherwise — a purl pointing at
		// the wrong repository is a false provenance claim. So the element is
		// reported from the handles that were actually disclosed rather than
		// from a purl that may not have been derivable.
		have("Component", "Other unique identifiers",
			firstOf(a.Identity.DOI, a.Identity.UUID, a.Identity.RepoURL)),
		have("Component", "Original licences", originalLicense(a)),
	)

	return els
}

// dependencyElement reports the component set and why it is not the whole
// answer.
//
// §5.1 requires recursive dependency resolution "on each path downward at
// least up to and including the first component that is outside the scope of
// delivery", and §5.2.2 requires that "the completeness of this enumeration
// MUST be clearly indicated". The first half is a build-time fact: what a
// model depends on to run — the framework, the kernel libraries, the
// interpreter — is a property of the delivery item, not of a weights file, and
// no amount of parsing recovers it.
//
// So this is reported out of scope even when the artifact's own file set is
// fully enumerated, and the enumeration is carried in the note. Marking it
// populated would state that a model bill of materials alone satisfies the
// CRA's dependency requirement, which it does not: it has to be merged with
// the SBOM of the thing that loads it.
func dependencyElement(a *model.Artifact) Element {
	return Element{
		Cluster: "Component",
		Name:    "Dependencies on other components",
		Status:  OutOfScope,
		Note: "recursive resolution to the edge of the delivery scope is a build-time " +
			"fact; a weights file does not record the runtime that loads it. " +
			componentSetStatement(a) +
			" Merge this document with the delivery item's SBOM to satisfy §5.1.",
	}
}

// componentSetStatement describes what the artifact's own component set does
// cover, and whether that enumeration is itself complete.
func componentSetStatement(a *model.Artifact) string {
	n := len(a.Files)
	if n == 0 {
		return "No component files were enumerated."
	}
	if a.HasFinding("TESS-FILE-002") {
		return fmt.Sprintf("%s of the artifact's own are enumerated and the set is "+
			"incomplete, see TESS-FILE-002.", plural(n, "file"))
	}
	if extra := len(a.Runtime.CustomDomains); extra > 0 {
		return fmt.Sprintf("The artifact's own set of %s and %s is complete.",
			plural(n, "file"), plural(extra, "custom operator domain"))
	}
	return fmt.Sprintf("The artifact's own set of %s is complete.", plural(n, "file"))
}

// creatorContact returns a contact of the shape §5.2.2 requires — an email
// address, or a URL where none is available — and nothing else.
func creatorContact(a *model.Artifact) string {
	for _, candidate := range []string{a.Identity.Author, a.Identity.Organization} {
		if strings.Contains(candidate, "@") && strings.Contains(candidate, ".") {
			return candidate
		}
	}
	return firstOf(a.Identity.RepoURL, a.Identity.URL)
}

// originalLicense is the licence as the creator assigned it, before resolution
// to an SPDX identifier. TR-03183-2 §3.2.8 distinguishes original from
// distribution licences, and collapsing them would lose the distinction the
// guideline draws.
func originalLicense(a *model.Artifact) string {
	for _, l := range a.Licenses {
		if l.Raw != "" {
			return l.Raw
		}
	}
	return ""
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// cisa2026Elements maps the 2026 CISA/NSA/FBI minimum elements onto what was
// parsed. Element names are verbatim from Appendix A, Table 1, so a reader can
// lay this report beside the published table row for row.
//
// Two of the seventeen data fields are properties of the emitted document
// rather than of the artifact — the format's name and version. They are
// reported as populated because Tessera does emit them, and the value names
// which document is meant: a coverage report that ignored its own output would
// be answering a different question from the one the standard asks.
func cisa2026Elements(a *model.Artifact) []Element {
	primary := a.PrimaryFile()
	var els []Element

	const data = "Data Fields"

	els = append(els,
		// The artifact is one component; shards and external tensor data are
		// its subcomponents, and each is emitted as a related component with
		// its own digest.
		have(data, "Component Dependency Relationship", componentRelationships(a)),
		have(data, "Component Hash Algorithm", hashAlgorithms(primary)),
		have(data, "Component Hash Value", primary.SHA256),
		have(data, "Component Identifiers", componentIdentifiers(a)),
		have(data, "Component License", licenseOf(a)),
		have(data, "Component Name", a.Identity.Name),
		have(data, "Component Producer", firstOf(a.Identity.Organization, a.Identity.Author)),
		have(data, "Component Version", a.Identity.Version),

		have(data, "SBOM Author", "tessera"),
		// The signature is a separate signing step over a finished document,
		// not something a parse of the model can produce.
		cannot(data, "SBOM Author Signature",
			"a signature is applied to the finished document by a signing step, not derived from the artifact"),
		have(data, "SBOM Data Format Name", "CycloneDX and SPDX"),
		have(data, "SBOM Data Format Version", "CycloneDX 1.6 or 1.7; SPDX 3.0.1"),
		// The document's own lifecycle phase. Tessera reads a shipped artifact,
		// so the honest answer is always post-build, and both emitters say so.
		have(data, "SBOM Generation Context", "post-build"),
		have(data, "SBOM Timestamp", "generated per document"),
		have(data, "SBOM Tool Name", "tessera"),
		have(data, "SBOM Tool Version", "stamped into each document"),
		// The SBOM's own revision number, which only the system that stores and
		// reissues documents can assign.
		have(data, "SBOM Version", "1"),
	)

	// Practices and Processes describe how an organization runs its SBOM
	// programme — distribution, update cadence, error handling. None is a
	// property of a model file, so each is reported with the reason rather than
	// omitted, and the counts stay honest.
	const practice = "Practices and Processes"
	els = append(els,
		cannot(practice, "Accommodation of Updates to SBOM Data",
			"an organizational process for correcting published documents, not a property of an artifact"),
		// Coverage here is the standard's own word for dependency depth, not
		// this package's name. A model artifact's components are its physical
		// files, and every one of them is enumerated and hashed.
		have(practice, "Coverage", componentCoverage(a)),
		cannot(practice, "Distribution and Delivery",
			"how documents are published and access-controlled is decided by the distributing organization"),
		// The one practice this tool implements directly: an element that could
		// not be determined is reported as absent or out-of-scope with a
		// reason, never omitted or guessed.
		have(practice, "Explicitly Identifying Unknown Information",
			"unknown elements are reported as absent or out-of-scope with a reason"),
		cannot(practice, "Frequency",
			"how often an SBOM is regenerated is set by the requesting organization's policy"),
		have(practice, "Machine-Processable Data", "JSON: CycloneDX, SPDX 3.0.1 JSON-LD, SARIF"),
	)
	return els
}
