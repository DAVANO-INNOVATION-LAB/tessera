package emit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

func sampleArtifact() *model.Artifact {
	return &model.Artifact{
		Format: model.FormatGGUF,
		Identity: model.Identity{
			Name: "TinyTest", Version: "1.0", Author: "Davano",
			Organization: "Davano Innovation Lab", Description: "a test model",
			URL: "https://example.com/model",
		},
		Licenses: []model.License{{Raw: "apache-2.0", SPDXID: "Apache-2.0", Confidence: "normalized"}},
		Lineage: model.Lineage{
			BaseModels: []model.Reference{{Name: "Meta-Llama-3-8B", URL: "https://hf.co/x"}},
			Datasets:   []model.Reference{{Name: "the-stack"}},
		},
		Params: model.Parameters{
			Architecture: "llama", ArchitectureFamily: "llama", Quantization: "Q4_K_M",
			Hyperparameters: map[string]string{"context_length": "8192"},
		},
		Runtime: model.Runtime{Framework: "gguf/ggml", CustomDomains: nil},
		Files: []model.FileComponent{
			{Path: "tiny.gguf", Size: 1024, SHA256: strings.Repeat("a", 64), Role: "primary"},
			{Path: "tiny-00002-of-00002.gguf", Size: 2048, SHA256: strings.Repeat("b", 64), Role: "shard"},
		},
		TensorCount: 1,
		Findings: []model.Finding{
			{ID: "TESS-GGUF-010", Title: "Executable chat template", Severity: "High", Description: "jinja"},
		},
	}
}

var fixedTime = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

var testTool = Tool{Name: "tessera", Version: "test", Vendor: "Davano Innovation Lab"}

func TestCycloneDXValidAndComplete(t *testing.T) {
	data, err := CycloneDX(sampleArtifact(), fixedTime, testTool)
	if err != nil {
		t.Fatalf("CycloneDX: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" || doc["specVersion"] != "1.6" {
		t.Errorf("wrong header: %v / %v", doc["bomFormat"], doc["specVersion"])
	}
	if !strings.HasPrefix(doc["serialNumber"].(string), "urn:uuid:") {
		t.Errorf("serial = %v", doc["serialNumber"])
	}

	meta := doc["metadata"].(map[string]any)
	comp := meta["component"].(map[string]any)
	if comp["type"] != "machine-learning-model" {
		t.Errorf("component type = %v", comp["type"])
	}
	if comp["name"] != "TinyTest" {
		t.Errorf("component name = %v", comp["name"])
	}
	// License resolved to an SPDX id.
	lics := comp["licenses"].([]any)
	lic := lics[0].(map[string]any)["license"].(map[string]any)
	if lic["id"] != "Apache-2.0" {
		t.Errorf("license id = %v", lic["id"])
	}
	// modelCard present with architecture + hyperparameters.
	mc, ok := comp["modelCard"].(map[string]any)
	if !ok {
		t.Fatalf("modelCard missing")
	}
	mp := mc["modelParameters"].(map[string]any)
	if mp["modelArchitecture"] != "llama" {
		t.Errorf("modelArchitecture = %v", mp["modelArchitecture"])
	}
	// Hash present on the model component.
	if comp["hashes"] == nil {
		t.Errorf("no hashes on model component")
	}
	// Pedigree ancestor from base model.
	if comp["pedigree"] == nil {
		t.Errorf("no pedigree")
	}
	// Shard is a file subcomponent.
	comps, _ := doc["components"].([]any)
	if len(comps) < 1 {
		t.Errorf("shard subcomponent missing")
	}
	// Finding rode along as a vulnerability.
	vulns, _ := doc["vulnerabilities"].([]any)
	if len(vulns) != 1 {
		t.Fatalf("vulnerabilities = %v", vulns)
	}
	if vulns[0].(map[string]any)["id"] != "TESS-GGUF-010" {
		t.Errorf("vuln id = %v", vulns[0])
	}
}

func TestSPDXValidAndComplete(t *testing.T) {
	data, err := SPDX(sampleArtifact(), fixedTime, testTool)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc["@context"] == nil {
		t.Errorf("missing @context")
	}
	graph, ok := doc["@graph"].([]any)
	if !ok || len(graph) == 0 {
		t.Fatalf("empty @graph")
	}
	// Find the AI package.
	var aiPkg map[string]any
	for _, e := range graph {
		m := e.(map[string]any)
		if m["type"] == "ai_AIPackage" && m["name"] == "TinyTest" {
			aiPkg = m
		}
	}
	if aiPkg == nil {
		t.Fatalf("no ai_AIPackage in graph")
	}
	// Multi-valued in the SPDX model, so an array even for a single value.
	if got, ok := aiPkg["ai_typeOfModel"].([]any); !ok || len(got) != 1 || got[0] != "llama" {
		t.Errorf("ai_typeOfModel = %v, want [llama]", aiPkg["ai_typeOfModel"])
	}
	if aiPkg["verifiedUsing"] == nil {
		t.Errorf("AI package not verified by hash")
	}
	// A hasDeclaredLicense relationship should exist.
	foundLicenseRel := false
	for _, e := range graph {
		m := e.(map[string]any)
		if m["type"] == "Relationship" && m["relationshipType"] == "hasDeclaredLicense" {
			foundLicenseRel = true
		}
	}
	if !foundLicenseRel {
		t.Errorf("no hasDeclaredLicense relationship")
	}
}

func TestDeterministicOutput(t *testing.T) {
	a := sampleArtifact()
	first, _ := CycloneDX(a, fixedTime, testTool)
	second, _ := CycloneDX(a, fixedTime, testTool)
	if string(first) != string(second) {
		t.Errorf("CycloneDX output is not deterministic for identical input")
	}
}

// derivedArtifact is a hardened copy: it descends from a declared base model
// (a model-card claim) and from an artifact this tool actually transformed.
func derivedArtifact() *model.Artifact {
	a := &model.Artifact{
		Identity: model.Identity{Name: "llama-hardened"},
		Format:   "gguf",
		Files:    []model.FileComponent{{Path: "model.gguf", Role: "primary", SHA256: "aa" + strings.Repeat("0", 62)}},
	}
	a.Lineage.BaseModels = []model.Reference{{Name: "llama-base", URL: "https://example.invalid/llama"}}
	a.Derivation = &model.Derivation{
		Source: model.DerivationSource{
			Name: "llama", Path: "models/llama",
			SHA256: "bb" + strings.Repeat("1", 62), Verdict: "Quarantined",
		},
		Tool: "tessera-studio test", ProducedAt: "2026-08-22T00:00:00Z",
		Changes: []model.DerivationChange{{
			Summary: "remove-file tokenizer.pkl", Description: "executes code when loaded",
			Resolves: []model.DerivationIssue{{
				ID: "TESS-PICKLE-001", Name: "Deserialization of Untrusted Data",
				References: []string{"https://cwe.mitre.org/data/definitions/502.html"},
			}},
		}},
	}
	return a
}

// A derivation becomes CycloneDX pedigree: the source as an ancestor carrying
// its digest, and each change as an unofficial patch resolving a security
// issue. The digest is the point — it turns "descended from X" into something a
// reader holding the original can check.
func TestCycloneDXEmitsDerivationAsPedigree(t *testing.T) {
	data, err := CycloneDX(derivedArtifact(), time.Unix(0, 0).UTC(), Tool{Name: "tessera"})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Metadata struct {
			Component struct {
				Pedigree struct {
					Ancestors []struct {
						Name   string `json:"name"`
						Hashes []struct {
							Alg     string `json:"alg"`
							Content string `json:"content"`
						} `json:"hashes"`
					} `json:"ancestors"`
					Patches []struct {
						Type     string `json:"type"`
						Resolves []struct {
							Type       string   `json:"type"`
							ID         string   `json:"id"`
							References []string `json:"references"`
						} `json:"resolves"`
					} `json:"patches"`
					Notes string `json:"notes"`
				} `json:"pedigree"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	p := doc.Metadata.Component.Pedigree

	// The declared base model and the transformed source are both ancestors,
	// and a reader must be able to tell them apart: only one carries a digest.
	var hashed, bare int
	for _, a := range p.Ancestors {
		if len(a.Hashes) > 0 {
			hashed++
		} else {
			bare++
		}
	}
	if hashed != 1 || bare != 1 {
		t.Errorf("ancestors: %d hashed, %d bare — want one of each (%+v)", hashed, bare, p.Ancestors)
	}

	if len(p.Patches) != 1 {
		t.Fatalf("patches = %d, want one per change", len(p.Patches))
	}
	if p.Patches[0].Type != "unofficial" {
		t.Errorf("patch type = %q; hardening is not published by the model's supplier",
			p.Patches[0].Type)
	}
	if len(p.Patches[0].Resolves) != 1 || p.Patches[0].Resolves[0].Type != "security" {
		t.Errorf("resolves = %+v, want one security issue", p.Patches[0].Resolves)
	}
	if p.Patches[0].Resolves[0].ID != "TESS-PICKLE-001" {
		t.Errorf("issue id = %q", p.Patches[0].Resolves[0].ID)
	}
	if len(p.Patches[0].Resolves[0].References) == 0 {
		t.Error("no CWE reference: the finding id is meaningless outside this tool")
	}
	if !strings.Contains(p.Notes, "Quarantined") {
		t.Errorf("notes do not say what the source was assessed as: %q", p.Notes)
	}
}

// An unverified derivation must contribute prose and nothing else.
//
// A consumer reads structure and ignores notes. Emitting an ancestor or a
// resolved finding on an unverifiable claim would let anyone mint a document
// asserting that a live pickle had been removed, with this tool named as the
// source of the claim.
func TestUnverifiedDerivationAssertsNothingStructural(t *testing.T) {
	a := derivedArtifact()
	a.Lineage.BaseModels = nil // isolate: only the derivation could add an ancestor
	a.Derivation.Unverified = true
	a.Derivation.Notes = "could not be verified"

	data, err := CycloneDX(a, time.Unix(0, 0).UTC(), Tool{Name: "tessera"})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Metadata struct {
			Component struct {
				Pedigree *struct {
					Ancestors []any  `json:"ancestors"`
					Patches   []any  `json:"patches"`
					Notes     string `json:"notes"`
				} `json:"pedigree"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	p := doc.Metadata.Component.Pedigree
	if p == nil {
		t.Fatal("the claim vanished entirely; it should survive as a note")
	}
	if len(p.Ancestors) != 0 {
		t.Errorf("an unverified derivation produced %d ancestor(s)", len(p.Ancestors))
	}
	if len(p.Patches) != 0 {
		t.Errorf("an unverified derivation asserted %d resolved finding(s)", len(p.Patches))
	}
	if p.Notes == "" {
		t.Error("the claim was dropped silently")
	}
	// And the prose must not go on to state the derivation as fact.
	if strings.Contains(p.Notes, "Derived from") {
		t.Errorf("notes assert the derivation after saying it is unverified: %q", p.Notes)
	}

	// The SPDX side must hold the same line.
	sp, err := SPDX(a, time.Unix(0, 0).UTC(), Tool{Name: "tessera"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sp), "descendantOf") {
		t.Error("SPDX emitted a descendantOf edge for an unverified derivation")
	}
}
