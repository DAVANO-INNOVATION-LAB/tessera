package parse

import (
	"cmp"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// Sidecar files are the other half of a model's story. The binary says what the
// artifact is; config.json and the shard index say what its author claims it
// is. Reading both is what makes it possible to notice when they disagree,
// which is the comparison this package exists to make.
//
// Nothing read here is trusted. A declaration is recorded as a declaration —
// never merged into the measured fields — so a stale or dishonest config can
// never quietly become a fact in the bill of materials.

// maxSidecarBytes bounds a sidecar read. These are small JSON files; anything
// larger is not a config and is not worth loading to find out.
const maxSidecarBytes = 8 << 20

// readSidecars fills a.Declared from files beside the model.
func readSidecars(a *model.Artifact, dir, primary string) {
	readConfigJSON(a, dir)
	readModelCard(a, dir)
	readShardIndex(a, dir)
	notePeerWeightFiles(a, dir, primary)
}

// readModelCard reads the YAML frontmatter of a model card.
//
// safetensors carries no licence of its own, so without this a model whose card
// plainly says "license: apache-2.0" is reported as disclosing no licence at
// all — a false finding on the majority of the Hugging Face Hub, and one that
// also empties the licence element the CISA/G7 minimum-elements guidance asks a
// bill of materials to populate.
//
// Deliberately a small hand-written parser rather than a YAML dependency. Only
// the scalar and simple-list forms the Hub validates are accepted, and this
// package parses files written by whoever published the model, so the smaller
// the surface the better.
func readModelCard(a *model.Artifact, dir string) {
	raw, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		return
	}
	// The body is read whether or not there is frontmatter. A card with no
	// YAML block still has the prose a reviewer needs, and returning early on
	// missing frontmatter would discard it.
	parseConsiderations(a, frontmatterBody(string(raw)), "README.md")

	fields := parseFrontmatter(string(raw))
	if len(fields) == 0 {
		return
	}

	// A card licence is a claim by the publisher, not something measured, so it
	// is recorded like any other disclosure and resolved to SPDX downstream.
	if lic := fields["license"]; lic != "" {
		a.Licenses = append(a.Licenses, model.License{Raw: lic})
	}
	// base_model may be a list, which on the Hub means a merge. Keeping the
	// whole value preserves that rather than silently reporting one parent.
	if base := fields["base_model"]; base != "" {
		if a.Declared.BaseModel == "" {
			a.Declared.BaseModel = base
		}
		// Lineage is what a bill of materials carries; the declared field is
		// what drift compares. Both are wanted, for different readers.
		for _, name := range splitList(base) {
			if !hasReference(a.Lineage.BaseModels, name) {
				a.Lineage.BaseModels = append(a.Lineage.BaseModels, model.Reference{
					Name: name, URL: hubURL(name),
				})
			}
		}
	}

	// Training datasets. These are the G7 "SBOM for AI" Models-cluster
	// training-properties element and the CycloneDX modelCard datasets field,
	// and they were being read and discarded.
	//
	// A card's dataset list is a claim by the publisher — nothing in the
	// weights confirms it — which is why it lands in Lineage rather than in
	// anything measured.
	for _, name := range splitList(fields["datasets"]) {
		if !hasReference(a.Lineage.Datasets, name) {
			a.Lineage.Datasets = append(a.Lineage.Datasets, model.Reference{
				Name: name, URL: hubDatasetURL(name),
			})
		}
	}

	// The task the model is published for. CycloneDX has a dedicated field,
	// and it is the only place an input/output shape can be inferred from a
	// card without inventing one.
	if a.Declared.Task == "" {
		a.Declared.Task = fields["pipeline_tag"]
	}
	if a.Declared.Library == "" {
		a.Declared.Library = fields["library_name"]
	}
	if a.Declared.Source == "" {
		a.Declared.Source = "README.md"
	} else if !strings.Contains(a.Declared.Source, "README.md") {
		a.Declared.Source += ", README.md"
	}
}

// parseFrontmatter extracts the leading --- delimited YAML block.
//
// Returns scalars as themselves and simple lists joined by commas; anything
// nested is skipped rather than guessed at.
func parseFrontmatter(text string) map[string]string {
	if !strings.HasPrefix(text, "---") {
		return nil
	}
	end := strings.Index(text[3:], "\n---")
	if end < 0 {
		return nil
	}
	block := text[3 : 3+end]

	out := map[string]string{}
	var listKey string
	var items []string

	flush := func() {
		if listKey != "" && len(items) > 0 {
			out[listKey] = strings.Join(items, ",")
		}
		listKey, items = "", nil
	}

	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			if listKey != "" {
				items = append(items, strings.Trim(strings.TrimPrefix(trimmed, "- "), `"' `))
			}
			continue
		}
		flush()
		key, value, found := strings.Cut(trimmed, ":")
		if !found {
			continue
		}
		// Nested keys are indented; only top-level ones are read.
		if line != trimmed && strings.HasPrefix(line, "  ") {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if value == "" {
			listKey = key
			continue
		}
		out[key] = value
	}
	flush()
	return out
}

// hfConfig is the subset of a Hugging Face config.json worth comparing. Field
// names changed across transformers versions, so both spellings of the dtype
// key are accepted.
type hfConfig struct {
	Architectures []string `json:"architectures"`
	ModelType     string   `json:"model_type"`
	TorchDType    string   `json:"torch_dtype"`
	DType         string   `json:"dtype"`
	QuantConfig   *struct {
		QuantMethod string `json:"quant_method"`
		Bits        int    `json:"bits"`
	} `json:"quantization_config"`
	NumParameters any `json:"num_parameters"`
}

func readConfigJSON(a *model.Artifact, dir string) {
	path := filepath.Join(dir, "config.json")
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSidecarBytes {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var cfg hfConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return
	}

	a.Declared.Source = "config.json"
	if len(cfg.Architectures) > 0 {
		a.Declared.Architecture = cfg.Architectures[0]
	} else if cfg.ModelType != "" {
		a.Declared.Architecture = cfg.ModelType
	}
	a.Declared.DType = cmp.Or(cfg.TorchDType, cfg.DType)
	if cfg.QuantConfig != nil && cfg.QuantConfig.QuantMethod != "" {
		a.Declared.Quantization = cfg.QuantConfig.QuantMethod
		if cfg.QuantConfig.Bits > 0 {
			a.Declared.Quantization += fmt.Sprintf("-%dbit", cfg.QuantConfig.Bits)
		}
	}
	switch n := cfg.NumParameters.(type) {
	case float64:
		a.Declared.ParameterCount = fmt.Sprintf("%.0f", n)
	case string:
		a.Declared.ParameterCount = n
	}

	// Keep the raw claims addressable without letting them pass as measured.
	a.SetRaw("declared.architecture", a.Declared.Architecture)
	a.SetRaw("declared.dtype", a.Declared.DType)
	a.SetRaw("declared.quantization", a.Declared.Quantization)
}

// readShardIndex records how many shards the index claims, so a set that is
// short a file can be noticed.
func readShardIndex(a *model.Artifact, dir string) {
	path := filepath.Join(dir, "model.safetensors.index.json")
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSidecarBytes {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var index struct {
		WeightMap map[string]string `json:"weight_map"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return
	}
	shards := map[string]bool{}
	for _, s := range index.WeightMap {
		shards[s] = true
	}
	a.Declared.ShardCount = len(shards)
	if a.Declared.Source == "" {
		a.Declared.Source = "model.safetensors.index.json"
	}
}

// dominantDType reports the dtype holding the most parameters, which is the
// figure a model card means when it advertises a precision. A model is not one
// precision throughout — norms and embeddings routinely differ from the body —
// so the majority holder is the honest single answer.
func dominantDType(tensors []model.Tensor) string {
	if len(tensors) == 0 {
		return ""
	}
	weight := map[string]int64{}
	for _, t := range tensors {
		n := int64(1)
		for _, d := range t.Shape {
			if d > 0 {
				n *= d
			}
		}
		weight[t.DType] += n
	}

	best, bestN := "", int64(-1)
	for dtype, n := range weight {
		// Ties break on name so the answer does not depend on map order.
		if n > bestN || (n == bestN && dtype < best) {
			best, bestN = dtype, n
		}
	}
	return best
}

// executableWeightExts are weight formats that run code when they are loaded.
var executableWeightExts = map[string]bool{
	".bin": true, ".pt": true, ".pth": true, ".ckpt": true,
	".pkl": true, ".pickle": true, ".dill": true, ".joblib": true,
}

// maxSiblingScan bounds the sibling listing so a directory of many thousands of
// files cannot turn a metadata read into a directory walk of unbounded cost.
const maxSiblingScan = 4096

// notePeerWeightFiles records weight files in a code-executing format sitting
// beside the model.
//
// These are deliberately NOT added to the component set. They are not part of
// this model, and hashing them into its file list would describe an artifact
// that was never shipped. But their presence is worth reporting, because a
// directory holding both a safe format and a pickle loads whichever the loader
// prefers — so a bill of materials naming only the safe one may describe a
// different model than the one that runs.
//
// The observation is passed to the scan through Raw, the same way the ONNX
// traversal signal is: parsing states what it saw, and the scan decides what it
// means.
func notePeerWeightFiles(a *model.Artifact, dir, primary string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	primaryBase := filepath.Base(primary)

	var peers []string
	for i, e := range entries {
		if i >= maxSiblingScan {
			break
		}
		if e.IsDir() || e.Name() == primaryBase {
			continue
		}
		if executableWeightExts[strings.ToLower(filepath.Ext(e.Name()))] {
			peers = append(peers, e.Name())
		}
	}
	if len(peers) > 0 {
		sort.Strings(peers)
		a.SetRaw("peer.executable_weights", strings.Join(peers, ", "))
	}
}

// splitList expands the comma-joined form parseFrontmatter produces.
func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func hasReference(refs []model.Reference, name string) bool {
	for _, r := range refs {
		if r.Name == name {
			return true
		}
	}
	return false
}

// hubURL turns an owner/name reference into a resolvable location.
//
// Only applied to values that look like a Hub id. A local filesystem path is a
// perfectly legal base_model value, and turning one into a URL would invent a
// provenance link that does not exist.
func hubURL(name string) string {
	if strings.Count(name, "/") != 1 || strings.ContainsAny(name, " \\:") {
		return ""
	}
	return "https://huggingface.co/" + name
}

func hubDatasetURL(name string) string {
	if strings.Count(name, "/") != 1 || strings.ContainsAny(name, " \\:") {
		return ""
	}
	return "https://huggingface.co/datasets/" + name
}

// frontmatterBody returns the markdown after a leading YAML frontmatter block,
// or the whole document when there is none.
func frontmatterBody(raw string) string {
	t := strings.TrimLeft(raw, "\ufeff \t\r\n")
	if !strings.HasPrefix(t, "---") {
		return raw
	}
	rest := t[3:]
	if i := strings.Index(rest, "\n---"); i >= 0 {
		after := rest[i+4:]
		if j := strings.Index(after, "\n"); j >= 0 {
			return after[j+1:]
		}
		return ""
	}
	return raw
}
