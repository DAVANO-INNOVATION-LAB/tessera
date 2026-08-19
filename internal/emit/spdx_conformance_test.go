package emit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// SPDX 3.0.1 conformance regression tests.
//
// The published SPDX 3.0.1 JSON schema sets unevaluatedProperties:false on
// every class, which makes it unusually unforgiving: one property of the wrong
// shape does not produce one error about that property, it rejects the entire
// object. Both cases below were caught by validating real output against the
// published schema, and each one silently invalidated a whole document while
// still being valid JSON — so nothing but a conformance check would notice.
//
// Full validation against the real schema runs in CI (scripts/validate-boms.sh),
// which needs a JSON-schema implementation. These tests pin the same invariants
// with no dependency, so the module keeps its empty dependency tree.

func spdxGraph(t *testing.T, a *model.Artifact) []map[string]any {
	t.Helper()
	data, err := SPDX(a, time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC), testTool)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	var doc struct {
		Graph []map[string]any `json:"@graph"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("SPDX output is not valid JSON: %v", err)
	}
	return doc.Graph
}

func findType(graph []map[string]any, typ string) map[string]any {
	for _, n := range graph {
		if n["type"] == typ {
			return n
		}
	}
	return nil
}

func TestSPDXTypeOfModelIsAnArray(t *testing.T) {
	a := &model.Artifact{
		Format:   model.FormatGGUF,
		Identity: model.Identity{Name: "m"},
		Params:   model.Parameters{Architecture: "llama"},
	}
	pkg := findType(spdxGraph(t, a), "ai_AIPackage")
	if pkg == nil {
		t.Fatal("no ai_AIPackage in the graph")
	}

	v, ok := pkg["ai_typeOfModel"]
	if !ok {
		t.Fatal("ai_typeOfModel missing even though an architecture was set")
	}
	arr, ok := v.([]any)
	if !ok {
		t.Fatalf("ai_typeOfModel is %T, want an array — SPDX models it as multi-valued, "+
			"and a bare string makes the schema reject the whole AIPackage", v)
	}
	if len(arr) != 1 || arr[0] != "llama" {
		t.Errorf("ai_typeOfModel = %v, want [llama]", arr)
	}
}

func TestSPDXDatasetPackageCarriesRequiredFields(t *testing.T) {
	a := &model.Artifact{
		Format:   model.FormatGGUF,
		Identity: model.Identity{Name: "m"},
		Lineage:  model.Lineage{Datasets: []model.Reference{{Name: "the-stack"}}},
	}
	ds := findType(spdxGraph(t, a), "dataset_DatasetPackage")
	if ds == nil {
		t.Fatal("no dataset_DatasetPackage in the graph")
	}

	// dataset_datasetType is mandatory and multi-valued.
	dt, ok := ds["dataset_datasetType"].([]any)
	if !ok || len(dt) == 0 {
		t.Errorf("dataset_datasetType = %v, want a non-empty array; it is required "+
			"and its absence invalidates the whole DatasetPackage", ds["dataset_datasetType"])
	}
	if _, ok := ds["software_downloadLocation"]; !ok {
		t.Error("dataset_DatasetPackage is missing software_downloadLocation")
	}
}

// TestSPDXEveryNodeIsIdentified guards a whole class of schema failures: any
// element in the graph that lacks a type or a stable identifier will be
// rejected, and the failure message points at the graph index rather than at
// whatever produced it, which is painful to trace back by hand.
func TestSPDXEveryNodeIsIdentified(t *testing.T) {
	a := &model.Artifact{
		Format:   model.FormatGGUF,
		Identity: model.Identity{Name: "m", Organization: "Org"},
		Licenses: []model.License{{Raw: "mit", SPDXID: "MIT"}},
		Lineage: model.Lineage{
			Datasets:   []model.Reference{{Name: "d"}},
			BaseModels: []model.Reference{{Name: "b"}},
		},
		Params: model.Parameters{Architecture: "llama"},
		Files: []model.FileComponent{
			{Path: "m.gguf", Role: "primary", SHA256: "aa"},
			{Path: "s.gguf", Role: "shard", SHA256: "bb"},
		},
	}
	for i, n := range spdxGraph(t, a) {
		if _, ok := n["type"]; !ok {
			t.Errorf("@graph[%d] has no type", i)
		}
		_, hasSpdxID := n["spdxId"]
		_, hasAtID := n["@id"]
		if !hasSpdxID && !hasAtID {
			t.Errorf("@graph[%d] (type %v) has neither spdxId nor @id", i, n["type"])
		}
	}
}
