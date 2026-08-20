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
			// A measured count that deliberately disagrees with the "8B" label,
			// and a graph signature — the two EU AI Act Annex XI 1(d)/(e) facts.
			MeasuredParameters: 7_504_924_672,
			Inputs: []model.IOSpec{
				{Name: "input_ids", DType: "int64", Shape: []int64{-1, -1}, Format: "tensor"},
			},
			Outputs: []model.IOSpec{
				{Name: "logits", DType: "float", Shape: []int64{-1, -1, 128256}, Format: "tensor"},
			},
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
			{Path: "model.gguf", Size: 4096, SHA256: strings.Repeat("a", 64), SHA384: strings.Repeat("1", 96), SHA512: strings.Repeat("d", 128), Role: "primary"},
			{Path: "model-00002-of-00002.gguf", Size: 2048, SHA256: strings.Repeat("b", 64), SHA384: strings.Repeat("2", 96), SHA512: strings.Repeat("e", 128), Role: "shard"},
			{Path: "weights.bin", Size: 128, SHA256: strings.Repeat("c", 64), SHA384: strings.Repeat("3", 96), SHA512: strings.Repeat("f", 128), Role: "external-data"},
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
			msg := "first difference at line " + strconv.Itoa(i+1) + ":\n  want: " + wl + "\n  got:  " + gl
			// Two lines that print identically differ in something invisible.
			// Line-ending translation on checkout is the usual cause, and
			// saying so beats leaving the reader staring at two equal-looking
			// strings.
			if strings.TrimRight(wl, "\r\t ") == strings.TrimRight(gl, "\r\t ") {
				msg += "\n  (the lines differ only in trailing whitespace or line endings —" +
					" check that .gitattributes marks the golden files -text)"
			}
			return msg
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

// The 1.7 document is the 1.6 document with a different declared specVersion.
// That is the whole claim, so the test asserts it directly: any future 1.7-only
// field would break this and force a deliberate decision rather than silently
// diverging the two outputs.
func TestGoldenCycloneDX17(t *testing.T) {
	got, err := CycloneDXVersion(goldenArtifact(), goldenTime, goldenTool, CycloneDX17)
	if err != nil {
		t.Fatalf("CycloneDXVersion: %v", err)
	}
	if !json.Valid(got) {
		t.Fatal("output is not valid JSON")
	}
	checkGolden(t, "model.cdx17.json", got)
}

func TestCycloneDXVersionsDifferOnlyInSpecVersion(t *testing.T) {
	v16, err := CycloneDXVersion(goldenArtifact(), goldenTime, goldenTool, CycloneDX16)
	if err != nil {
		t.Fatal(err)
	}
	v17, err := CycloneDXVersion(goldenArtifact(), goldenTime, goldenTool, CycloneDX17)
	if err != nil {
		t.Fatal(err)
	}
	normalized := bytes.Replace(v17, []byte(`"specVersion": "1.7"`), []byte(`"specVersion": "1.6"`), 1)
	if !bytes.Equal(v16, normalized) {
		t.Errorf("1.6 and 1.7 differ beyond specVersion.\n%s", firstDifference(v16, normalized))
	}
}

func TestCycloneDXRejectsUnknownVersion(t *testing.T) {
	for _, v := range []string{"", "1.5", "1.8", "2.0", "v1.7", "1.7.1"} {
		if _, err := CycloneDXVersion(goldenArtifact(), goldenTime, goldenTool, v); err == nil {
			t.Errorf("version %q was accepted; an unknown version must be an error, "+
				"not a silent fallback to the default", v)
		}
	}
}

// The default has to stay 1.6 until it is changed deliberately: it is what
// downstream consumers and the embedding scanner already read.
func TestCycloneDXDefaultIs16(t *testing.T) {
	got, err := CycloneDX(goldenArtifact(), goldenTime, goldenTool)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"specVersion": "1.6"`)) {
		t.Error("the default CycloneDX output no longer declares specVersion 1.6")
	}
}

func TestGoldenSARIF(t *testing.T) {
	got, err := SARIF(goldenArtifact(), goldenTime, goldenTool)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	if !json.Valid(got) {
		t.Fatal("output is not valid JSON")
	}
	checkGolden(t, "model.sarif.json", got)
}

// A clean model must still produce a usable log. An empty or absent file reads
// downstream as a failed scan step rather than as "nothing was wrong".
func TestSARIFCleanArtifactIsValidEmptyRun(t *testing.T) {
	a := goldenArtifact()
	a.Findings = nil
	got, err := SARIF(a, goldenTime, goldenTool)
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Results   []any `json:"results"`
			Artifacts []any `json:"artifacts"`
			Tool      struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(got, &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	if log.Runs[0].Results == nil {
		t.Error("results is null; it must serialize as [] so consumers read a clean scan, not a malformed log")
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("results = %d, want 0", len(log.Runs[0].Results))
	}
	if len(log.Runs[0].Artifacts) == 0 {
		t.Error("a clean run must still record which artifact it examined")
	}
	if log.Runs[0].Tool.Driver.Name == "" {
		t.Error("tool.driver.name is required by the SARIF schema")
	}
}

// Every result must resolve to a rule descriptor. Consumers drop results whose
// ruleId has no matching rule, which would silently lose findings.
func TestSARIFEveryResultHasARule(t *testing.T) {
	got, err := SARIF(goldenArtifact(), goldenTime, goldenTool)
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string `json:"id"`
						Properties struct {
							SecuritySeverity string `json:"security-severity"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID              string            `json:"ruleId"`
				Level               string            `json:"level"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(got, &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	rules := map[string]bool{}
	for _, r := range run.Tool.Driver.Rules {
		rules[r.ID] = true
		if r.Properties.SecuritySeverity == "" {
			t.Errorf("rule %s has no security-severity; GitHub renders it as an undifferentiated warning", r.ID)
		}
	}
	if len(run.Results) == 0 {
		t.Fatal("the golden artifact has findings; results must not be empty")
	}
	valid := map[string]bool{"error": true, "warning": true, "note": true, "none": true}
	for _, res := range run.Results {
		if !rules[res.RuleID] {
			t.Errorf("result %s has no rule descriptor; consumers drop it", res.RuleID)
		}
		if !valid[res.Level] {
			t.Errorf("result %s has level %q, which is not a SARIF level", res.RuleID, res.Level)
		}
		if res.PartialFingerprints["tesseraFindingV1"] == "" {
			t.Errorf("result %s has no fingerprint; it will re-alert on every run", res.RuleID)
		}
	}
}
