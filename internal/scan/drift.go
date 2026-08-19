package scan

import (
	"cmp"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// Drift compares what a model declares about itself against what its bytes
// actually contain.
//
// The comparison is the point. Plenty of tools read both sides — syft, for one,
// parses the tensor header and reads config.json in the same cataloger — and do
// not ask whether the two agree. A declaration nobody checks is exactly where a
// wrong or dishonest claim survives: a card advertising bfloat16 over 8-bit
// weights, a config naming one architecture while the tensors implement another,
// a shard set that is quietly short a file.
//
// Tools that do compare generally do it against a hub API. Doing it from local
// bytes is why this lives in the parser rather than in a hub client: the case
// that matters is the artifact already sitting on disk, with no repository
// behind it to ask.
//
// None of these findings prove malice, and they are not written as though they
// do. A stale config is far more common than a forged one. What a drift finding
// establishes is narrower and still useful: a specific claim in the bill of
// materials is not supported by the artifact it describes, which is worth
// knowing before anything relies on that claim.

// Drift finding identifiers.
const (
	DriftArchitecture   = "TESS-DRIFT-001"
	DriftDType          = "TESS-DRIFT-002"
	DriftQuantization   = "TESS-DRIFT-003"
	DriftShardCount     = "TESS-DRIFT-004"
	DriftUncheckable    = "TESS-DRIFT-005"
	DriftMixedFormats   = "TESS-DRIFT-006"
	DriftParameterCount = "TESS-DRIFT-007"
)

// analyzeDrift produces the declared-versus-measured findings.
func analyzeDrift(a *model.Artifact) []model.Finding {
	var out []model.Finding
	out = append(out, driftArchitecture(a)...)
	out = append(out, driftDType(a)...)
	out = append(out, driftQuantization(a)...)
	out = append(out, driftShardCount(a)...)
	out = append(out, driftMixedFormats(a)...)
	out = append(out, driftParameterCount(a)...)
	return out
}

func driftArchitecture(a *model.Artifact) []model.Finding {
	declared, measured := a.Declared.Architecture, a.Params.Architecture
	if declared == "" {
		return nil
	}
	if measured == "" {
		// Only worth saying when the format could have recorded an architecture
		// and did not. safetensors and ONNX never record one, so on those the
		// claim is unverifiable by construction — reporting it says something
		// about the file format rather than about this artifact.
		//
		// Measured against a corpus of twenty-five real Hugging Face models this
		// fired on 84% of them, every safetensors and every ONNX. A finding that
		// fires on five models in six carries no information and teaches people
		// to skip the list, which costs more than the finding is worth. The same
		// reasoning keeps TESS-PICKLE-003 at Low elsewhere.
		if a.Format != model.FormatGGUF {
			return nil
		}
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
// beside the model.
//
// This is a bill-of-materials concern more than a security one: a directory
// holding both safetensors and a pickle will load whichever the loader prefers,
// so a document listing only the safe format describes a model that is not
// necessarily the one that runs.
//
// The peer files come from the parse layer's directory observation rather than
// from the component list, and that distinction is the whole reason this works.
// A stray pickle is not part of this model, so it is deliberately never added
// to the component set — hashing it in would describe an artifact nobody
// shipped. An earlier version of this check read the component list instead,
// which meant it could never fire on the exact case it describes.
func driftMixedFormats(a *model.Artifact) []model.Finding {
	peers := a.Raw["peer.executable_weights"]
	if peers == "" {
		return nil
	}
	// Only worth saying when the model itself is in a format that does not
	// execute. Beside a pickle, another pickle is not a surprise.
	if a.Format != model.FormatSafetensors && a.Format != model.FormatGGUF {
		return nil
	}
	names := strings.Split(peers, ", ")
	return []model.Finding{{
		ID: DriftMixedFormats, Title: "Executable weight format beside a safe one",
		Severity: "Medium", Category: "drift", Location: names[0],
		Description: fmt.Sprintf("the model is %s, and %d file(s) in a format that executes code on "+
			"load sit in the same directory (%s). Which one a loader picks depends on the loader, so "+
			"this bill of materials may describe a different model than the one that runs. Those files "+
			"are not components of this model and were not read.",
			a.Format, len(names), peers),
	}}
}

// driftParameterCount compares a declared parameter count against the sum of
// every tensor shape in the file.
//
// This is the check the declared-versus-measured idea is really for. A size
// label is a marketing string on the front of the box; the tensor shapes are
// what is in it. A model advertised as 8B whose weights sum to 3B is a
// substantive misrepresentation, and it is arithmetic — no judgement, no
// heuristic, no false-positive class to tune.
//
// EU AI Act Annex XI 1(d) requires providers to document "the architecture and
// number of parameters". This is the only way to check that requirement was met
// honestly rather than merely answered.
func driftParameterCount(a *model.Artifact) []model.Finding {
	measured := a.Params.MeasuredParameters
	if measured <= 0 {
		return nil
	}
	declared, label := declaredParameterCount(a)
	if declared <= 0 {
		return nil
	}

	// A generous band. Published counts legitimately differ from a tensor sum:
	// embeddings may be tied or counted twice, a size label is rounded to one
	// significant figure, and "8B" is a family name as much as a measurement.
	// Only a difference too large to explain that way is worth reporting.
	ratio := float64(measured) / float64(declared)
	if ratio > 0.80 && ratio < 1.25 {
		return nil
	}
	return []model.Finding{{
		ID: DriftParameterCount, Title: "Declared parameter count does not match the tensors",
		Severity: "High", Category: "drift", Location: cmp.Or(a.Declared.Source, a.PrimaryFile().Path),
		Description: fmt.Sprintf("the model is described as %q (about %s parameters) but its tensor shapes "+
			"sum to %s — a factor of %.1f. Parameter count drives memory, cost and capability, so a figure "+
			"this far from the artifact misdescribes all three. Counts differing by a little are normal "+
			"(tied embeddings, rounding); this is not.",
			label, humanCount(declared), humanCount(measured), maxRatio(ratio)),
	}}
}

// declaredParameterCount reads a declared count, accepting both an exact number
// and the "8B" / "1.5b" shorthand a size label uses.
func declaredParameterCount(a *model.Artifact) (int64, string) {
	for _, raw := range []string{a.Declared.ParameterCount, a.Params.ParameterCount} {
		if raw == "" {
			continue
		}
		if n := parseCount(raw); n > 0 {
			return n, raw
		}
	}
	return 0, ""
}

// parseCount turns "8B", "1.5b", "70M" or a plain integer into a number.
// Anything it does not understand yields 0, which suppresses the check — an
// unparsed label is not evidence of a mismatch.
func parseCount(s string) int64 {
	t := strings.TrimSpace(strings.ToLower(s))
	t = strings.ReplaceAll(t, ",", "")
	t = strings.ReplaceAll(t, "_", "")
	mult := float64(1)
	switch {
	case strings.HasSuffix(t, "b"):
		mult, t = 1e9, strings.TrimSuffix(t, "b")
	case strings.HasSuffix(t, "m"):
		mult, t = 1e6, strings.TrimSuffix(t, "m")
	case strings.HasSuffix(t, "k"):
		mult, t = 1e3, strings.TrimSuffix(t, "k")
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
	if err != nil || f <= 0 {
		return 0
	}
	n := f * mult
	if n > math.MaxInt64 {
		return 0
	}
	return int64(n)
}

// humanCount renders a count the way a model card would.
func humanCount(n int64) string {
	switch {
	case n >= 1e9:
		return strconv.FormatFloat(float64(n)/1e9, 'f', 1, 64) + "B"
	case n >= 1e6:
		return strconv.FormatFloat(float64(n)/1e6, 'f', 1, 64) + "M"
	case n >= 1e3:
		return strconv.FormatFloat(float64(n)/1e3, 'f', 1, 64) + "K"
	}
	return strconv.FormatInt(n, 10)
}

// maxRatio reports the discrepancy as a factor greater than one, whichever
// direction it went, so the message reads the same for over- and under-claims.
func maxRatio(r float64) float64 {
	if r < 1 {
		return 1 / r
	}
	return r
}
