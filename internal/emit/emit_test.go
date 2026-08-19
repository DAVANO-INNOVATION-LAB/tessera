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
