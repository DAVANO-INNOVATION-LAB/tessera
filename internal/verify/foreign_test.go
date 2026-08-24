package verify

import (
	"os"
	"path/filepath"
	"testing"
)

// Documents produced by other tools must verify here.
//
// This is the difference between being one more AIBOM generator and being the
// thing that checks them. Every tool in this space emits a bill of materials;
// none of the ones surveyed opens the model file to find out whether the
// document is true. That check only has reach if it accepts their output, not
// just our own.
//
// The fixtures are real: golden output committed by the projects themselves,
// not documents written here to be easy to parse.
func TestForeignDocumentsAreReadable(t *testing.T) {
	for _, tc := range []struct {
		file string
		// spec is the version the file declares, which is deliberately not
		// always one we emit — a verifier that only reads its own output is a
		// round trip, not a check.
		spec string
		// wantModel is the model the document is about. For system-level
		// documents this is NOT the top-level component.
		wantModel string
		why       string
	}{
		{
			file: "k8s-aibom-vllm.cdx.json", spec: "CycloneDX 1.6",
			wantModel: "meta-llama/Llama-3.1-8B-Instruct",
			why: "a system-level generator: metadata.component is the workload " +
				"(vllm-llama3, type application) and the models sit beneath it",
		},
		{
			file: "manifest-cyber-llama32.cdx.json", spec: "CycloneDX 1.5",
			wantModel: "meta-llama/Llama-3.2-1B-Instruct",
			why:       "no metadata.component at all; the model is only in components[]",
		},
		{
			file: "manifest-cyber-qwen25.cdx.json", spec: "CycloneDX 1.5",
			wantModel: "Qwen/Qwen2.5-7B-Instruct",
			why:       "same shape, a different publisher's model",
		},
	} {
		t.Run(tc.file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "foreign", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := readCycloneDX(raw)
			if err != nil {
				t.Fatalf("could not read a document another tool published: %v", err)
			}
			if doc.Format != tc.spec {
				t.Errorf("format = %q, want %q", doc.Format, tc.spec)
			}
			if doc.ModelName != tc.wantModel {
				t.Errorf("model = %q, want %q\n  (%s)", doc.ModelName, tc.wantModel, tc.why)
			}
		})
	}
}

// The specific regression: comparing an artifact against a Deployment name.
//
// A system-level document puts the workload at metadata.component. Reading the
// model name from there produced "vllm-llama3" — not a model at all — and
// reported a mismatch that told the reader nothing about their artifact.
func TestWorkloadComponentIsNotMistakenForTheModel(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "foreign", "k8s-aibom-vllm.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := readCycloneDX(raw)
	if err != nil {
		t.Fatal(err)
	}
	if doc.ModelName == "vllm-llama3" {
		t.Fatal("the workload name was read as the model name")
	}
	if doc.ModelName == "" {
		t.Fatal("no model found; the document does contain machine-learning-model components")
	}
}

// A hub-published name and a file's own name are the same model.
//
// Documents from hubs say "meta-llama/Llama-3.2-1B-Instruct"; a GGUF's
// general.name says "Llama-3.2-1B-Instruct". Reporting drift between those two
// would fail on the most ordinary model there is, in the first check a reader
// looks at — and a verifier that cries wolf on the common case does not get
// used on the uncommon one.
func TestPublisherPrefixIsNotDrift(t *testing.T) {
	for _, tc := range []struct {
		declared, measured string
		agree              bool
		why                string
	}{
		{"meta-llama/Llama-3.2-1B-Instruct", "Llama-3.2-1B-Instruct", true, "hub prefix"},
		{"Qwen/Qwen2.5-7B-Instruct", "Qwen2.5-7B-Instruct", true, "hub prefix"},
		{"Llama-3.2-1B-Instruct", "meta-llama/Llama-3.2-1B-Instruct", true, "reversed"},
		{"meta-llama/Llama-3.2-1B", "meta-llama/Llama-3.2-1B", true, "identical"},

		// The prefix is forgiven; nothing else is.
		{"meta-llama/Llama-3.2-1B", "Llama-3.2-3B", false, "different model"},
		{"meta-llama/Llama-3.2-1B", "Qwen2.5-7B", false, "different model entirely"},
		{"a/b/Llama-3.2-1B", "Llama-3.2-1B", false,
			"several slashes is a path, not a publisher prefix; collapsing it would " +
				"let unrelated models match on their last segment"},
	} {
		if got := modelNamesAgree(tc.declared, tc.measured); got != tc.agree {
			t.Errorf("modelNamesAgree(%q, %q) = %v, want %v (%s)",
				tc.declared, tc.measured, got, tc.agree, tc.why)
		}
	}
}
