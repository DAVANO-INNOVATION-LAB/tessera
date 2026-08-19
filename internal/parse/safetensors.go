package parse

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// safetensors is the sparsest of the three formats: an 8-byte little-endian
// header length, a JSON header mapping tensor names to dtype/shape/offsets, and
// a raw tensor buffer. It carries almost no self-description — only a free-form
// __metadata__ string map that, by convention, usually holds just the framework
// name. So the parser harvests what little is there (framework, tensor shapes,
// any provenance a producer chose to write) and the orchestrator is responsible
// for pulling the rest from sidecar files. Nothing here reads the tensor buffer;
// the header is the whole attack surface of a format that cannot execute code.

const stMaxHeader = 100 << 20 // the reference parser's header cap

// ParseSafetensors reads a single safetensors file's header.
func ParseSafetensors(path string) (*model.Artifact, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	a := &model.Artifact{Format: model.FormatSafetensors}
	a.Runtime.Framework = "safetensors"

	var headerLen uint64
	if err := binary.Read(f, binary.LittleEndian, &headerLen); err != nil {
		a.AddFinding(model.Finding{
			ID: "TESS-ST-001", Title: "Truncated safetensors header", Severity: "Medium", Category: "model",
			Location: path, Description: "file is too short to contain the 8-byte header length prefix",
		})
		return a, nil
	}
	if headerLen == 0 || headerLen > uint64(info.Size()) || headerLen > stMaxHeader {
		a.AddFinding(model.Finding{
			ID: "TESS-ST-002", Title: "Invalid safetensors header length", Severity: "High", Category: "model",
			Location: path,
			Description: fmt.Sprintf("declared header length %d is not consistent with the %d-byte file "+
				"(or exceeds the %d cap); a lying length prefix can drive a loader to over-read",
				headerLen, info.Size(), stMaxHeader),
		})
		return a, nil
	}

	buf := make([]byte, headerLen)
	if _, err := io.ReadFull(f, buf); err != nil {
		a.AddFinding(model.Finding{
			ID: "TESS-ST-001", Title: "Truncated safetensors header", Severity: "Medium", Category: "model",
			Location: path, Description: "header is shorter than its declared length",
		})
		return a, nil
	}

	// The header is an object of tensor entries plus an optional __metadata__.
	// Decode into RawMessage first so a tensor entry and the metadata map, which
	// have different shapes, can be told apart.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf, &raw); err != nil {
		a.AddFinding(model.Finding{
			ID: "TESS-ST-003", Title: "Unparseable safetensors header", Severity: "Medium", Category: "model",
			Location: path, Description: "header is not valid JSON",
		})
		return a, nil
	}

	if md, ok := raw["__metadata__"]; ok {
		var meta map[string]string
		if err := json.Unmarshal(md, &meta); err == nil {
			applySafetensorsMetadata(a, meta)
		}
		delete(raw, "__metadata__")
	}

	// Remaining keys are tensors. Sort for deterministic output.
	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	sort.Strings(names)

	a.TensorCount = len(names)
	for _, name := range names {
		var t struct {
			DType string  `json:"dtype"`
			Shape []int64 `json:"shape"`
		}
		if err := json.Unmarshal(raw[name], &t); err != nil {
			continue
		}
		if len(a.Tensors) < ggMaterializeTensors {
			a.Tensors = append(a.Tensors, model.Tensor{Name: name, DType: t.DType, Shape: t.Shape})
		}
	}
	return a, nil
}

// applySafetensorsMetadata lifts the free-form __metadata__ map into the IR.
// Only a small set of keys has any conventional meaning; everything else is
// preserved in Raw so nothing a producer wrote is lost.
func applySafetensorsMetadata(a *model.Artifact, meta map[string]string) {
	for k, v := range meta {
		a.SetRaw("__metadata__."+k, v)
	}
	if f := meta["format"]; f != "" {
		a.Runtime.Framework = "safetensors (" + f + ")"
	}
	// Opportunistic: some quant/training tools write these, none are guaranteed.
	a.Identity.Name = firstNonEmpty(meta["name"], meta["model_name"], meta["general.name"])
	if lic := firstNonEmpty(meta["license"], meta["general.license"]); lic != "" {
		a.Licenses = append(a.Licenses, model.License{Raw: lic})
	}
	if base := firstNonEmpty(meta["base_model"], meta["general.base_model"]); base != "" {
		a.Lineage.BaseModels = append(a.Lineage.BaseModels, model.Reference{Name: base})
	}
	if arch := firstNonEmpty(meta["architecture"], meta["model_type"]); arch != "" {
		a.Params.Architecture = arch
		a.Params.ArchitectureFamily = arch
	}
}
