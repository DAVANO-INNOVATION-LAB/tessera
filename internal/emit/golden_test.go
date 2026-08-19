package emit

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// Golden tests for the two serializers.
//
// A bill of materials is a document other systems read, diff, and sign, so the
// exact bytes are the contract — not merely "some valid JSON containing the
// right facts". Assertions on individual fields cannot catch a key that moved,
// a value that changed shape, or an element that quietly disappeared; a golden
// file catches all three, and shows the change as a readable diff in review.
//
// Regenerate after an intended change:
//
//	go test ./internal/emit -update
//
// and read the resulting diff before committing it. That review is the point of
// the test — an update applied without reading it is the one way this technique
// fails.

var update = flag.Bool("update", false, "rewrite the golden files from current output")

// goldenArtifact exercises every branch either emitter has: identity, supplier,
// a resolved licence, both kinds of lineage, hyperparameters, multiple physical
// files with distinct roles, custom runtime domains, and findings at more than
// one severity.
func goldenArtifact() *model.Artifact {
	return &model.Artifact{
		Format: model.FormatGGUF,
		Identity: model.Identity{
			Name: "Golden-Test-Model", Version: "2.1", Author: "A. Author",
			Organization: "Example Org", Description: "a model used only by tests",
			URL:     "https://huggingface.co/example-org/golden-test-model",
			RepoURL: "https://huggingface.co/example-org/golden-test-model",
			UUID:    "6f0b7a1e-0000-4000-8000-000000000000",
		},
		Licenses: []model.License{
			{Raw: "apache-2.0", SPDXID: "Apache-2.0", Confidence: "normalized"},
		},
		Lineage: model.Lineage{
			BaseModels: []model.Reference{
				{Name: "Base-One", URL: "https://huggingface.co/example-org/base-one"},
				{Name: "Base Two"},
			},
			Datasets: []model.Reference{{Name: "the-stack"}, {Name: "wikipedia"}},
		},
		Params: model.Parameters{
			Architecture: "llama", ArchitectureFamily: "llama",
			DType: "BF16", Quantization: "Q4_K_M", ParameterCount: "8B",
			// A map, so its iteration order is random per run: this is what
			// proves the emitters sort rather than happening to agree.
			Hyperparameters: map[string]string{
				"attention.head_count": "32",
				"block_count":          "32",
				"context_length":       "8192",
				"embedding_length":     "4096",
			},
		},
		Runtime: model.Runtime{
			Framework: "gguf/ggml", Producer: "quantizer 1.0",
			CustomDomains: []string{"com.example.custom"},
			OpsetImports:  []model.Opset{{Domain: "", Version: 18}},
		},
		Files: []model.FileComponent{
			{Path: "model.gguf", Size: 4096, SHA256: strings.Repeat("a", 64), Role: "primary"},
			{Path: "model-00002-of-00002.gguf", Size: 2048, SHA256: strings.Repeat("b", 64), Role: "shard"},
			{Path: "weights.bin", Size: 128, SHA256: strings.Repeat("c", 64), Role: "external-data"},
		},
		TensorCount: 291,
		Raw:         map[string]string{"general.source.commit": "ABC123"},
		Findings: []model.Finding{
			{ID: "TESS-GGUF-010", Title: "Executable chat template", Severity: "High",
				Category: "model", Location: "model.gguf", Description: "jinja control logic"},
			{ID: "TESS-LIC-001", Title: "No license disclosed", Severity: "Low",
				Category: "license", Location: "model.gguf"},
		},
	}
}

var goldenTime = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
var goldenTool = Tool{Name: "tessera", Version: "golden", Vendor: "Davano Innovation Lab"}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)

	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s missing; run: go test ./internal/emit -update (%v)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden file.\n"+
			"If the change is intended, run `go test ./internal/emit -update` and review the diff.\n"+
			"%s", name, firstDifference(want, got))
	}
}

// firstDifference reports the first line that differs, which is far easier to
// read in a failure than two whole documents.
func firstDifference(want, got []byte) string {
	w := strings.Split(string(want), "\n")
	g := strings.Split(string(got), "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return "first difference at line " + strconv.Itoa(i+1) + ":\n  want: " + wl + "\n  got:  " + gl
		}
	}
	return "(documents differ only in trailing bytes)"
}

func TestGoldenCycloneDX(t *testing.T) {
	got, err := CycloneDX(goldenArtifact(), goldenTime, goldenTool)
	if err != nil {
		t.Fatalf("CycloneDX: %v", err)
	}
	if !json.Valid(got) {
		t.Fatal("output is not valid JSON")
	}
	checkGolden(t, "model.cdx.json", got)
}

func TestGoldenSPDX(t *testing.T) {
	got, err := SPDX(goldenArtifact(), goldenTime, goldenTool)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	if !json.Valid(got) {
		t.Fatal("output is not valid JSON")
	}
	checkGolden(t, "model.spdx.json", got)
}

// TestEmittersAreDeterministicAcrossBuilds builds the artifact separately for
// each run rather than reusing one value.
//
// That distinction is the whole test. Serializing the same pointer twice will
// agree even if the emitter iterates a map in random order, because the same
// process visits the same map the same way within a single marshal. Building it
// twice gives the runtime a fresh map each time, which is what actually exposes
// unsorted iteration.
func TestEmittersAreDeterministicAcrossBuilds(t *testing.T) {
	for i := 0; i < 8; i++ {
		cdx1, _ := CycloneDX(goldenArtifact(), goldenTime, goldenTool)
		cdx2, _ := CycloneDX(goldenArtifact(), goldenTime, goldenTool)
		if !bytes.Equal(cdx1, cdx2) {
			t.Fatalf("CycloneDX output differs between builds of an identical artifact (iteration %d)", i)
		}
		s1, _ := SPDX(goldenArtifact(), goldenTime, goldenTool)
		s2, _ := SPDX(goldenArtifact(), goldenTime, goldenTool)
		if !bytes.Equal(s1, s2) {
			t.Fatalf("SPDX output differs between builds of an identical artifact (iteration %d)", i)
		}
	}
}

// TestGoldenEmptyArtifact pins the degenerate case: a model that disclosed
// nothing at all must still produce a well-formed document rather than one with
// empty or missing required fields.
func TestGoldenEmptyArtifact(t *testing.T) {
	empty := &model.Artifact{Format: model.FormatSafetensors, Identity: model.Identity{Name: "unnamed"}}

	cdx, err := CycloneDX(empty, goldenTime, goldenTool)
	if err != nil {
		t.Fatalf("CycloneDX: %v", err)
	}
	checkGolden(t, "empty.cdx.json", cdx)

	spdx, err := SPDX(empty, goldenTime, goldenTool)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	checkGolden(t, "empty.spdx.json", spdx)
}
