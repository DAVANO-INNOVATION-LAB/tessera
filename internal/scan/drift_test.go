package scan

import (
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

func driftIDs(a *model.Artifact) []string {
	var ids []string
	for _, f := range analyzeDrift(a) {
		ids = append(ids, f.ID)
	}
	return ids
}

func hasIn(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestDriftDType(t *testing.T) {
	cases := []struct {
		name, declared, measured string
		wantFinding              bool
	}{
		{"vocabularies agree", "bfloat16", "BF16", false},
		{"float16 agrees", "float16", "F16", false},
		{"same string", "F32", "F32", false},
		{"quantized sold as full precision", "bfloat16", "F8_E4M3", true},
		{"nothing declared", "", "BF16", false},
		{"nothing measured", "bfloat16", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := &model.Artifact{
				Declared: model.Declared{Source: "config.json", DType: c.declared},
				Params:   model.Parameters{DType: c.measured},
			}
			got := hasIn(driftIDs(a), DriftDType)
			if got != c.wantFinding {
				t.Errorf("declared=%q measured=%q: finding=%v, want %v",
					c.declared, c.measured, got, c.wantFinding)
			}
		})
	}
}

func TestDriftArchitecture(t *testing.T) {
	// The two naming conventions must not be reported as a mismatch, or every
	// model on the hub becomes a finding and the check is worthless.
	agree := &model.Artifact{
		Declared: model.Declared{Source: "config.json", Architecture: "LlamaForCausalLM"},
		Params:   model.Parameters{Architecture: "llama"},
	}
	if hasIn(driftIDs(agree), DriftArchitecture) {
		t.Error("LlamaForCausalLM vs llama should agree")
	}

	disagree := &model.Artifact{
		Declared: model.Declared{Source: "config.json", Architecture: "MistralForCausalLM"},
		Params:   model.Parameters{Architecture: "llama"},
	}
	if !hasIn(driftIDs(disagree), DriftArchitecture) {
		t.Error("MistralForCausalLM vs llama should be reported")
	}

	// A GGUF that omits its architecture is worth reporting: the format records
	// one, so its absence is a property of this artifact.
	unchecked := &model.Artifact{
		Format:   model.FormatGGUF,
		Declared: model.Declared{Source: "config.json", Architecture: "LlamaForCausalLM"},
	}
	if !hasIn(driftIDs(unchecked), DriftUncheckable) {
		t.Error("a GGUF declaring an architecture it does not record should be reported")
	}

	// The same claim over safetensors is not news. Neither safetensors nor ONNX
	// records an architecture, so reporting it describes the format rather than
	// the artifact — and measured against twenty-five real Hugging Face models
	// it fired on 84% of them, which is a finding nobody will read twice.
	for _, f := range []model.Format{model.FormatSafetensors, model.FormatONNX} {
		quiet := &model.Artifact{
			Format:   f,
			Declared: model.Declared{Source: "config.json", Architecture: "LlamaForCausalLM"},
		}
		if hasIn(driftIDs(quiet), DriftUncheckable) {
			t.Errorf("%s cannot record an architecture; an unverifiable claim there is not a finding", f)
		}
	}
}

func TestDriftShardCount(t *testing.T) {
	short := &model.Artifact{
		Declared: model.Declared{ShardCount: 3},
		Files: []model.FileComponent{
			{Role: "primary"}, {Role: "shard"}, {Role: "shard"},
		},
	}
	if !hasIn(driftIDs(short), DriftShardCount) {
		t.Error("a shard set short of the index should be reported")
	}

	complete := &model.Artifact{
		Declared: model.Declared{ShardCount: 2},
		Files: []model.FileComponent{
			{Role: "primary"}, {Role: "shard"}, {Role: "shard"},
		},
	}
	if hasIn(driftIDs(complete), DriftShardCount) {
		t.Error("a complete shard set should not be reported")
	}
}

func TestDriftMixedFormats(t *testing.T) {
	// The peer file arrives as a directory observation from the parse layer,
	// not as a component. That distinction is load-bearing: a stray pickle is
	// not part of this model, so it is never added to the component set — and
	// an earlier version of this check looked at the component set, which meant
	// it could never fire on the case it describes.
	mixed := &model.Artifact{
		Format: model.FormatSafetensors,
		Raw:    map[string]string{"peer.executable_weights": "pytorch_model.bin"},
	}
	if !hasIn(driftIDs(mixed), DriftMixedFormats) {
		t.Error("a pickle beside safetensors should be reported")
	}

	// GGUF is also a format that does not execute, so the same concern applies.
	gguf := &model.Artifact{
		Format: model.FormatGGUF,
		Raw:    map[string]string{"peer.executable_weights": "model.ckpt"},
	}
	if !hasIn(driftIDs(gguf), DriftMixedFormats) {
		t.Error("a checkpoint beside a GGUF should be reported")
	}

	// Beside a pickle, another pickle is not news — only worth saying when the
	// model itself is in a format that does not execute.
	onnx := &model.Artifact{
		Format: model.FormatONNX,
		Raw:    map[string]string{"peer.executable_weights": "pytorch_model.bin"},
	}
	if hasIn(driftIDs(onnx), DriftMixedFormats) {
		t.Error("ONNX is not one of the safe-weights formats this finding is about")
	}

	clean := &model.Artifact{
		Format: model.FormatSafetensors,
		Files:  []model.FileComponent{{Path: "model.safetensors", Role: "primary"}},
	}
	if hasIn(driftIDs(clean), DriftMixedFormats) {
		t.Error("safetensors alone should not be reported")
	}
}

func TestParseCount(t *testing.T) {
	cases := map[string]int64{
		"8B": 8e9, "1.5b": 1_500_000_000, "70M": 70e6, "125m": 125e6,
		"7504924672": 7504924672, "1,000,000": 1e6, "1_500_000": 1_500_000,
		// Anything unparsed yields 0, which suppresses the check. A label we
		// cannot read is not evidence of a mismatch.
		"": 0, "large": 0, "-3B": 0, "0": 0,
	}
	for in, want := range cases {
		if got := parseCount(in); got != want {
			t.Errorf("parseCount(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestDriftParameterCount(t *testing.T) {
	cases := []struct {
		name        string
		declared    string
		measured    int64
		wantFinding bool
	}{
		// Tied embeddings and rounding move the real figure around; the band is
		// deliberately wide so ordinary models stay quiet.
		{"exact", "8B", 8_000_000_000, false},
		{"rounded label", "8B", 8_030_261_248, false},
		{"tied embeddings counted once", "8B", 7_504_924_672, false},
		{"slightly over", "7B", 7_800_000_000, false},
		// A model an order of magnitude off is not a rounding artefact.
		{"an order of magnitude short", "8B", 525_336_576, true},
		{"wildly over", "1B", 70_000_000_000, true},
		// Nothing to compare against on either side.
		{"no declaration", "", 8_000_000_000, false},
		{"nothing measured", "8B", 0, false},
		{"unparseable label", "large", 8_000_000_000, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := &model.Artifact{
				Declared: model.Declared{Source: "config.json", ParameterCount: c.declared},
				Params:   model.Parameters{MeasuredParameters: c.measured},
			}
			got := hasIn(driftIDs(a), DriftParameterCount)
			if got != c.wantFinding {
				t.Errorf("declared=%q measured=%d: finding=%v, want %v",
					c.declared, c.measured, got, c.wantFinding)
			}
		})
	}
}
