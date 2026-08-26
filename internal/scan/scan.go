// Package scan turns parsed model metadata into security findings. It reads
// only the assembled Artifact — never the file again — so the checks are
// exactly the things you can conclude from what the format disclosed. That is
// the point of parsing the bytes instead of the repo card: the risk signals
// live in fields a hash-and-move scanner throws away.
//
// Findings here are supply-chain / load-time observations. They are not a
// behavioural evaluation of the model (poisoning, backdoor triggers, jailbreak
// robustness) — those need training data and runtime behaviour a static parse
// cannot see, and claiming them would be dishonest.
package scan

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// Analyze produces findings from a parsed artifact.
func Analyze(a *model.Artifact) []model.Finding {
	var out []model.Finding

	switch a.Format {
	case model.FormatGGUF:
		out = append(out, scanGGUF(a)...)
	case model.FormatONNX:
		out = append(out, scanONNX(a)...)
	case model.FormatSafetensors:
		out = append(out, scanSafetensors(a)...)
	}

	// Declared-versus-measured comparison. This runs for every format, because
	// the sidecars that carry declarations are format-independent.
	out = append(out, analyzeDrift(a)...)

	// Cross-format compliance observation: a model with no resolvable license
	// cannot satisfy the SBOM-for-AI license element. Low severity — it is a
	// completeness gap, not a threat.
	if !hasResolvedLicense(a) {
		out = append(out, model.Finding{
			ID: "TESS-LIC-001", Title: "No license disclosed", Severity: "Low", Category: "license",
			Location: a.PrimaryFile().Path,
			Description: "the model file discloses no license; the SBOM cannot populate the license " +
				"element that CISA/G7 SBOM-for-AI minimum elements ask for. Supply it from a sidecar or the source repo.",
		})
	}

	return out
}

func scanGGUF(a *model.Artifact) []model.Finding {
	var out []model.Finding

	// The chat template is a metadata string rendered through Jinja2 by some
	// loaders without a sandbox (CVE-2024-34359, "Llama Drama"): attacker-
	// controlled metadata alone becomes code execution. Flag a template that
	// contains Jinja control constructs, which a plain formatting template does
	// not need.
	if tmpl := a.Raw["tokenizer.chat_template"]; tmpl != "" {
		if looksLikeActiveJinja(tmpl) {
			out = append(out, model.Finding{
				ID: "TESS-GGUF-010", Title: "Executable chat template", Severity: "High", Category: "model",
				Location: a.PrimaryFile().Path,
				Description: "the GGUF chat_template metadata contains Jinja control logic. Loaders that " +
					"render it without a sandbox execute it (CVE-2024-34359 class); the template ships inside " +
					"the model file, so this is attacker-controllable metadata, not model behaviour.",
			})
		}
	}

	// An implausibly large general.alignment drives an integer-overflow seek in
	// vulnerable GGUF readers. The spec default is 32; powers of two up to a few
	// thousand are seen. Anything huge is a red flag.
	if al := a.Raw["general.alignment"]; al != "" {
		if n, err := strconv.ParseUint(al, 10, 64); err == nil {
			if n == 0 || n > (1<<20) || (n&(n-1)) != 0 {
				out = append(out, model.Finding{
					ID: "TESS-GGUF-011", Title: "Suspicious tensor alignment", Severity: "Medium", Category: "model",
					Location: a.PrimaryFile().Path,
					Description: fmt.Sprintf("general.alignment is %d (expected a small power of two, default 32). "+
						"Unbounded alignment is a known GGUF integer-overflow / arbitrary-seek vector.", n),
				})
			}
		}
	}
	return out
}

func scanONNX(a *model.Artifact) []model.Finding {
	var out []model.Finding

	// A non-standard operator domain resolves to out-of-tree native kernels: the
	// model is the trigger half of a two-artifact code-execution package.
	if len(a.Runtime.CustomDomains) > 0 {
		out = append(out, model.Finding{
			ID: "TESS-ONNX-010", Title: "Custom operator domain", Severity: "High", Category: "model",
			Location: a.PrimaryFile().Path,
			Description: fmt.Sprintf("the graph imports non-standard operator domain(s) [%s]. Custom domains "+
				"resolve to out-of-tree native kernels (a .so/.dll) that execute when the model runs; the "+
				"kernel library is a required, unscanned component.", strings.Join(a.Runtime.CustomDomains, ", ")),
		})
	}

	// External data that walks out of the model directory is the ONNX path-
	// traversal class. The parser refused to open it; the scan raises it.
	if a.Raw["onnx.external_data.traversal"] == "true" {
		out = append(out, model.Finding{
			ID: "TESS-ONNX-011", Title: "External-data path traversal", Severity: "Critical", Category: "model",
			Location: a.PrimaryFile().Path,
			Description: "an initializer's external_data location escapes the model directory (contains '..' " +
				"or an absolute path). On load this reads an arbitrary file (CVE-2022-25882 → 2024-27318 → " +
				"2026-27489). The referenced path was not opened.",
		})
	}
	return out
}

func scanSafetensors(a *model.Artifact) []model.Finding {
	// safetensors is a safe format by design; the header findings it can produce
	// are raised during parsing. There is nothing further to conclude from the
	// metadata alone, and inventing a finding here would be noise.
	return nil
}

// hasResolvedLicense reports whether any license resolved to a usable id.
func hasResolvedLicense(a *model.Artifact) bool {
	for _, l := range a.Licenses {
		if l.SPDXID != "" {
			return true
		}
	}
	return false
}

// looksLikeActiveJinja reports whether a template string contains Jinja control
// logic ({% ... %}) rather than only plain substitutions ({{ ... }}). Control
// constructs are what a sandbox-escape payload needs.
// looksLikeActiveJinja reports whether a chat template reaches for the
// interpreter, as opposed to merely formatting messages.
//
// The distinction is the whole value of the check, and an earlier version got
// it backwards by treating any "{%" as evidence. Every instruction-tuned model
// ships a template that opens with {% for message in messages %} — control flow
// is what a chat template *is*. Flagging it made this a High-severity finding on
// substantially every chat model in existence, which does not make a fleet safe;
// it makes the finding noise, and a reviewer who sees it on all thousand models
// learns to click past it before reaching the one that matters.
//
// What actually distinguishes an attack (CVE-2024-34359, "Llama Drama") is a
// template escaping the sandbox to reach Python: attribute traversal through
// dunders, the known SSTI gadget objects, or pulling in another template. A
// formatting template needs none of those.
func looksLikeActiveJinja(s string) bool { return model.ActiveJinja(s) }
