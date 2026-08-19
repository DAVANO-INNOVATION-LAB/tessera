package parse

import (
	"cmp"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// Sidecar files are the other half of a model's story. The binary says what the
// artifact is; config.json and the shard index say what its author claims it
// is. Reading both is what makes it possible to notice when they disagree,
// which is the one question no other tool in this space asks.
//
// Nothing read here is trusted. A declaration is recorded as a declaration —
// never merged into the measured fields — so a stale or dishonest config can
// never quietly become a fact in the bill of materials.

// maxSidecarBytes bounds a sidecar read. These are small JSON files; anything
// larger is not a config and is not worth loading to find out.
const maxSidecarBytes = 8 << 20

// readSidecars fills a.Declared from files beside the model.
func readSidecars(a *model.Artifact, dir string) {
	readConfigJSON(a, dir)
	readShardIndex(a, dir)
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
