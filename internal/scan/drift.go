package scan

import (
	"fmt"
	"strings"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// Drift compares what a model declares about itself against what its bytes
// actually contain.
//
// Tools in this space read both sides and do not compare them. syft is the
// clearest example: its safetensors cataloger parses the tensor header and
// reads config.json in the same pass, and asks nothing about whether the two
// agree. That gap is worth occupying, because a declaration nobody checks is
// exactly where a wrong or dishonest claim survives: a card advertising
// bfloat16 over 8-bit weights, a config naming one architecture while the
// tensors implement another, a shard set that is quietly short a file.
//
// That was true of every comparable tool surveyed on 2026-08-19. It is the kind
// of claim that ages, so it is written as an observation with a date rather
// than as a permanent boast.
//
// None of these findings prove malice, and they are not written as though they
// do. A stale config is far more common than a forged one. What a drift finding
// establishes is narrower and still useful: a specific claim in the bill of
// materials is not supported by the artifact it describes, which is worth
// knowing before anything relies on that claim.

// Drift finding identifiers.
const (
	DriftArchitecture = "TESS-DRIFT-001"
	DriftDType        = "TESS-DRIFT-002"
	DriftQuantization = "TESS-DRIFT-003"
	DriftShardCount   = "TESS-DRIFT-004"
	DriftUncheckable  = "TESS-DRIFT-005"
	DriftMixedFormats = "TESS-DRIFT-006"
)

// analyzeDrift produces the declared-versus-measured findings.
func analyzeDrift(a *model.Artifact) []model.Finding {
	var out []model.Finding
	out = append(out, driftArchitecture(a)...)
	out = append(out, driftDType(a)...)
	out = append(out, driftQuantization(a)...)
	out = append(out, driftShardCount(a)...)
	out = append(out, driftMixedFormats(a)...)
	return out
}

func driftArchitecture(a *model.Artifact) []model.Finding {
	declared, measured := a.Declared.Architecture, a.Params.Architecture
	if declared == "" {
		return nil
	}
	if measured == "" {
		// A claim with nothing to check it against is not a mismatch. Saying so
		// is still better than silence, because a reader would otherwise assume
		// the architecture in the bill of materials was verified.
		return []model.Finding{{
			ID: DriftUncheckable, Title: "Declared architecture could not be checked",
			Severity: "Low", Category: "drift", Location: a.Declared.Source,
			Description: fmt.Sprintf("%s declares the architecture %q, but the model binary does not "+
				"record one, so the claim is carried into the bill of materials unverified.",
				a.Declared.Source, declared),
		}}
	}
	if architectureAgrees(declared, measured) {
		return nil
	}
	return []model.Finding{{
		ID: DriftArchitecture, Title: "Declared architecture does not match the model binary",
		Severity: "High", Category: "drift", Location: a.Declared.Source,
		Description: fmt.Sprintf("%s declares %q while the model binary reports %q. Anything relying "+
			"on the declared architecture — a compatibility gate, a policy rule, an inventory entry — "+
			"is relying on a claim the artifact does not support.",
			a.Declared.Source, declared, measured),
	}}
}

// architectureAgrees allows for the two naming conventions in use: config.json
// gives a class name such as LlamaForCausalLM, while GGUF gives a family such
// as llama. Matching either way round as a substring avoids flagging the entire
// Hugging Face hub as drifted.
func architectureAgrees(declared, measured string) bool {
	d := strings.ToLower(strings.TrimSpace(declared))
	m := strings.ToLower(strings.TrimSpace(measured))
	if d == "" || m == "" {
		return true
	}
	return strings.Contains(d, m) || strings.Contains(m, d)
}

func driftDType(a *model.Artifact) []model.Finding {
	declared, measured := a.Declared.DType, a.Params.DType
	if declared == "" || measured == "" || dtypeAgrees(declared, measured) {
		return nil
	}
	return []model.Finding{{
		ID: DriftDType, Title: "Declared precision does not match the tensors",
		Severity: "High", Category: "drift", Location: a.Declared.Source,
		Description: fmt.Sprintf("%s declares %q while the tensor headers report %q holds the most "+
			"parameters. Precision drives memory, throughput and accuracy, so a quantized model "+
			"presented as full precision misrepresents all three.",
			a.Declared.Source, declared, measured),
	}}
}

// dtypeAgrees normalises the two vocabularies: torch spells it bfloat16,
// safetensors spells the same thing BF16.
func dtypeAgrees(declared, measured string) bool {
	norm := map[string]string{
		"bfloat16": "BF16", "float16": "F16", "half": "F16",
		"float32": "F32", "float": "F32", "float64": "F64",
		"int8": "I8", "uint8": "U8", "int32": "I32", "int64": "I64",
		"float8_e4m3fn": "F8_E4M3", "float8_e5m2": "F8_E5M2",
	}
	d := strings.ToLower(strings.TrimSpace(declared))
	if mapped, ok := norm[d]; ok {
		return strings.EqualFold(mapped, measured)
	}
	return strings.EqualFold(d, measured)
}

func driftQuantization(a *model.Artifact) []model.Finding {
	declared, measured := a.Declared.Quantization, a.Params.Quantization
	if declared == "" || measured == "" {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(declared), strings.TrimSpace(measured)) {
		return nil
	}
	return []model.Finding{{
		ID: DriftQuantization, Title: "Declared quantization differs from the file",
		Severity: "Medium", Category: "drift", Location: a.Declared.Source,
		Description: fmt.Sprintf("%s declares %q; the file itself reports %q.",
			a.Declared.Source, declared, measured),
	}}
}

func driftShardCount(a *model.Artifact) []model.Finding {
	if a.Declared.ShardCount == 0 {
		return nil
	}
	present := 0
	for _, f := range a.Files {
		if f.Role == "shard" {
			present++
		}
	}
	if present == a.Declared.ShardCount {
		return nil
	}
	return []model.Finding{{
		ID: DriftShardCount, Title: "Shard set does not match the index",
		Severity: "High", Category: "drift", Location: "model.safetensors.index.json",
		Description: fmt.Sprintf("the index names %d shard(s) but %d were collected. A model that is "+
			"short a shard cannot load as described, and a bill of materials over an incomplete set "+
			"describes something other than what was shipped.",
			a.Declared.ShardCount, present),
	}}
}

// driftMixedFormats reports weight files in a code-executing format sitting
// beside a safe one.
//
// This is a bill-of-materials concern more than a security one: a directory
// holding both safetensors and a pickle will load whichever the loader prefers,
// so a document listing only the safe format describes a model that is not
// necessarily the one that runs.
func driftMixedFormats(a *model.Artifact) []model.Finding {
	var executable []string
	for _, f := range a.Files {
		switch strings.ToLower(extOf(f.Path)) {
		case ".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle":
			executable = append(executable, f.Path)
		}
	}
	if len(executable) == 0 || a.Format != model.FormatSafetensors {
		return nil
	}
	return []model.Finding{{
		ID: DriftMixedFormats, Title: "Executable weight format beside a safe one",
		Severity: "Medium", Category: "drift", Location: executable[0],
		Description: fmt.Sprintf("the model ships safetensors alongside %d file(s) in a format that "+
			"executes code on load (%s). Which one a loader picks depends on the loader, so this "+
			"bill of materials may describe a different model than the one that runs.",
			len(executable), strings.Join(executable, ", ")),
	}}
}

func extOf(p string) string {
	if i := strings.LastIndex(p, "."); i >= 0 {
		return p[i:]
	}
	return ""
}
