package parse

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// GGUF is a single-file container: header, a typed key/value metadata store,
// a tensor-info table, then aligned tensor data. The KV store is the richest
// self-description of any model format Tessera reads — name, license, author,
// base-model lineage, datasets, and quantization all live there — so the GGUF
// parser is where most of the bill of materials actually comes from.
//
// Every count and length is read against a bound. The GGUF parser CVE history
// (heap overflows from unchecked kv/tensor counts, an unbounded general.alignment
// driving an integer-overflow seek, exabyte string allocations) is a catalogue
// of what happens when these fields are trusted, so Tessera treats an
// implausible value as a finding and refuses to allocate on the file's say-so.

// GGUF metadata value types.
const (
	ggUint8 = iota
	ggInt8
	ggUint16
	ggInt16
	ggUint32
	ggInt32
	ggFloat32
	ggBool
	ggString
	ggArray
	ggUint64
	ggInt64
	ggFloat64
)

const (
	// ggMaxKV caps the number of metadata entries read. Real models sit in the
	// low hundreds; a header claiming millions is either corrupt or an attack.
	ggMaxKV = 1 << 20
	// ggMaxTensors caps the tensor-info table.
	ggMaxTensors = 1 << 20
	// ggMaxString caps a single string read. The spec permits ~1 GiB; anything
	// approaching that is flagged rather than allocated.
	ggMaxString = 64 << 20
	// ggMaxArray caps materialized string-array elements.
	ggMaxArray = 1 << 20
	// ggMaterializeTensors caps how many tensor entries land in the inventory.
	ggMaterializeTensors = 64
	// ggMaterializeArrayStrings caps how many strings of a small string array we
	// keep (for tags/languages/datasets); larger arrays are summarized.
	ggMaterializeArrayStrings = 64
)

type ggufReader struct {
	r   *bufio.Reader
	err error
}

func (g *ggufReader) u32() uint32 {
	if g.err != nil {
		return 0
	}
	var b [4]byte
	if _, err := io.ReadFull(g.r, b[:]); err != nil {
		g.err = err
		return 0
	}
	return binary.LittleEndian.Uint32(b[:])
}

func (g *ggufReader) u64() uint64 {
	if g.err != nil {
		return 0
	}
	var b [8]byte
	if _, err := io.ReadFull(g.r, b[:]); err != nil {
		g.err = err
		return 0
	}
	return binary.LittleEndian.Uint64(b[:])
}

func (g *ggufReader) i8() int8  { var b [1]byte; g.readFull(b[:]); return int8(b[0]) }
func (g *ggufReader) u8() uint8 { var b [1]byte; g.readFull(b[:]); return b[0] }
func (g *ggufReader) u16() uint16 {
	var b [2]byte
	g.readFull(b[:])
	return binary.LittleEndian.Uint16(b[:])
}
func (g *ggufReader) f32() float32 { return math.Float32frombits(g.u32()) }
func (g *ggufReader) f64() float64 { return math.Float64frombits(g.u64()) }

func (g *ggufReader) readFull(b []byte) {
	if g.err != nil {
		return
	}
	if _, err := io.ReadFull(g.r, b); err != nil {
		g.err = err
	}
}

// str reads a GGUF string: a uint64 length followed by that many bytes. An
// over-long length is refused rather than allocated, and reported by the caller.
func (g *ggufReader) str() (string, bool) {
	n := g.u64()
	if g.err != nil {
		return "", false
	}
	if n > ggMaxString {
		g.err = fmt.Errorf("string length %d exceeds cap", n)
		return "", true // true = the cap was the reason, not EOF
	}
	buf := make([]byte, n)
	g.readFull(buf)
	if g.err != nil {
		return "", false
	}
	return string(buf), false
}

// ParseGGUF reads the header, metadata, and tensor-info table of a GGUF file
// and fills an Artifact. It never reads the tensor data region.
func ParseGGUF(path string) (*model.Artifact, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	g := &ggufReader{r: bufio.NewReaderSize(f, 1<<20)}
	a := &model.Artifact{Format: model.FormatGGUF}

	var magic [4]byte
	g.readFull(magic[:])
	if g.err != nil {
		return nil, fmt.Errorf("read magic: %w", g.err)
	}
	if magic != [4]byte{'G', 'G', 'U', 'F'} {
		a.AddFinding(model.Finding{
			ID: "TESS-GGUF-001", Title: "Bad GGUF magic", Severity: "High", Category: "model",
			Location: path,
			Description: fmt.Sprintf("file does not begin with the GGUF magic (%q); it may be corrupt "+
				"or a different format wearing a .gguf extension", string(magic[:])),
		})
		return a, nil
	}

	version := g.u32()
	tensorCount := g.u64()
	kvCount := g.u64()
	if g.err != nil {
		return nil, fmt.Errorf("read header: %w", g.err)
	}
	a.SetRaw("gguf.version", strconv.FormatUint(uint64(version), 10))

	if kvCount > ggMaxKV {
		a.AddFinding(model.Finding{
			ID: "TESS-GGUF-002", Title: "Implausible metadata count", Severity: "High", Category: "model",
			Location: path,
			Description: fmt.Sprintf("header declares %d metadata entries, above the %d cap; "+
				"unchecked counts are the GGUF heap-overflow class, so the metadata was not read", kvCount, ggMaxKV),
		})
		return a, nil
	}
	if tensorCount > ggMaxTensors {
		a.AddFinding(model.Finding{
			ID: "TESS-GGUF-005", Title: "Implausible tensor count", Severity: "High", Category: "model",
			Location:    path,
			Description: fmt.Sprintf("header declares %d tensors, above the %d cap", tensorCount, ggMaxTensors),
		})
		return a, nil
	}

	kv := map[string]string{}
	kvList := map[string][]string{} // string arrays, materialized when small
	for i := uint64(0); i < kvCount; i++ {
		key, capped := g.str()
		if g.err != nil {
			if capped {
				a.AddFinding(model.Finding{
					ID: "TESS-GGUF-003", Title: "Over-long metadata string", Severity: "High", Category: "model",
					Location: path,
					Description: "a metadata key or value declared a length past the safety cap; " +
						"exabyte-scale string lengths are a known GGUF denial-of-service vector",
				})
			}
			break
		}
		valType := g.u32()
		disp, list := g.readValue(valType, a, path)
		if g.err != nil {
			break
		}
		kv[key] = disp
		if list != nil {
			kvList[key] = list
		}
		a.SetRaw(key, disp)
	}

	applyGGUFMetadata(a, kv, kvList)

	// Tensor-info table follows the metadata. Read names/dims/type/offset for a
	// bounded inventory; never touch the tensor data itself.
	a.TensorCount = int(tensorCount)
	for i := uint64(0); i < tensorCount && g.err == nil; i++ {
		name, _ := g.str()
		nDims := g.u32()
		if nDims > 8 {
			// Malformed dimensionality; stop reading the table rather than
			// spin on a bad count.
			a.AddFinding(model.Finding{
				ID: "TESS-GGUF-004", Title: "Malformed tensor dimensions", Severity: "Medium", Category: "model",
				Location:    path,
				Description: fmt.Sprintf("tensor %q declares %d dimensions (max 8); tensor-info table truncated", name, nDims),
			})
			break
		}
		dims := make([]int64, 0, nDims)
		for d := uint32(0); d < nDims; d++ {
			dims = append(dims, int64(g.u64()))
		}
		ggmlType := g.u32()
		_ = g.u64() // offset, not needed for the BOM
		if g.err != nil {
			break
		}
		if len(a.Tensors) < ggMaterializeTensors {
			a.Tensors = append(a.Tensors, model.Tensor{
				Name:  name,
				DType: ggmlTypeName(ggmlType),
				Shape: dims,
			})
		}
	}

	return a, nil
}

// readValue reads one metadata value and returns a display string plus, for a
// string array, the materialized elements (nil otherwise). Numeric arrays and
// oversized arrays are summarized rather than stored.
func (g *ggufReader) readValue(valType uint32, a *model.Artifact, path string) (string, []string) {
	switch valType {
	case ggUint8:
		return strconv.FormatUint(uint64(g.u8()), 10), nil
	case ggInt8:
		return strconv.FormatInt(int64(g.i8()), 10), nil
	case ggUint16:
		return strconv.FormatUint(uint64(g.u16()), 10), nil
	case ggInt16:
		return strconv.FormatInt(int64(int16(g.u16())), 10), nil
	case ggUint32:
		return strconv.FormatUint(uint64(g.u32()), 10), nil
	case ggInt32:
		return strconv.FormatInt(int64(int32(g.u32())), 10), nil
	case ggFloat32:
		return strconv.FormatFloat(float64(g.f32()), 'g', -1, 32), nil
	case ggBool:
		if g.u8() != 0 {
			return "true", nil
		}
		return "false", nil
	case ggString:
		s, _ := g.str()
		return s, nil
	case ggUint64:
		return strconv.FormatUint(g.u64(), 10), nil
	case ggInt64:
		return strconv.FormatInt(int64(g.u64()), 10), nil
	case ggFloat64:
		return strconv.FormatFloat(g.f64(), 'g', -1, 64), nil
	case ggArray:
		return g.readArray(a, path)
	default:
		g.err = fmt.Errorf("unknown gguf value type %d", valType)
		return "", nil
	}
}

// readArray consumes a GGUF array value. Small string arrays are materialized
// (these carry tags, languages, datasets); everything else is summarized to
// keep memory bounded on tokenizer arrays with hundreds of thousands of entries.
//
// An array of arrays is refused rather than descended. GGUF has no legitimate
// nested arrays, and descending one is not merely wasteful: readValue and
// readArray are mutually recursive, each nesting level costs only twelve bytes
// on disk, and Go answers a deep enough recursion with `fatal error: stack
// overflow` — which recover cannot catch. A ~23 MB file would therefore kill
// whatever process embedded this library, which for a library whose whole
// premise is being safe to embed is the worst failure available. Refusing the
// construct outright removes the recursion instead of bounding it.
func (g *ggufReader) readArray(a *model.Artifact, path string) (string, []string) {
	elemType := g.u32()
	count := g.u64()
	if g.err != nil {
		return "", nil
	}
	if elemType == ggArray {
		g.err = fmt.Errorf("nested gguf array is not a valid construct")
		a.AddFinding(model.Finding{
			ID: "TESS-GGUF-006", Title: "Nested metadata array", Severity: "High", Category: "model",
			Location: path,
			Description: "a metadata array declares elements that are themselves arrays. GGUF has no " +
				"nested arrays, and deep nesting is a known way to exhaust a parser's stack, so the " +
				"metadata was not read past this point.",
		})
		return "", nil
	}
	if count > ggMaxArray {
		// Consume nothing further and signal a stop: an unbounded array count
		// is the same class of DoS as an unbounded string length.
		g.err = fmt.Errorf("array count %d exceeds cap", count)
		a.AddFinding(model.Finding{
			ID: "TESS-GGUF-007", Title: "Over-long metadata array", Severity: "High", Category: "model",
			Location:    path,
			Description: fmt.Sprintf("a metadata array declared %d elements, above the %d cap", count, ggMaxArray),
		})
		return "", nil
	}

	if elemType == ggString {
		var kept []string
		for i := uint64(0); i < count && g.err == nil; i++ {
			s, _ := g.str()
			if uint64(len(kept)) < ggMaterializeArrayStrings {
				kept = append(kept, s)
			}
		}
		if uint64(len(kept)) < count {
			return fmt.Sprintf("[array<string> × %d]", count), kept
		}
		return "[" + strings.Join(kept, ", ") + "]", kept
	}

	// Numeric array: consume the elements without materializing them.
	for i := uint64(0); i < count && g.err == nil; i++ {
		g.readValue(elemType, a, path)
	}
	return fmt.Sprintf("[array<type %d> × %d]", elemType, count), nil
}

// applyGGUFMetadata lifts the standardized general.* keys out of the raw KV map
// into the typed IR slots.
func applyGGUFMetadata(a *model.Artifact, kv map[string]string, kvList map[string][]string) {
	a.Identity.Name = kv["general.name"]
	a.Identity.Version = kv["general.version"]
	a.Identity.Author = kv["general.author"]
	a.Identity.Organization = kv["general.organization"]
	a.Identity.Description = kv["general.description"]
	a.Identity.UUID = kv["general.uuid"]
	a.Identity.URL = firstNonEmpty(kv["general.url"], kv["general.repo_url"])
	a.Identity.RepoURL = kv["general.repo_url"]
	a.Identity.DOI = kv["general.doi"]

	// License: prefer the explicit name, fall back to the id-bearing key.
	if lic := firstNonEmpty(kv["general.license"], kv["general.license.name"]); lic != "" {
		a.Licenses = append(a.Licenses, model.License{
			Raw: lic,
			URL: kv["general.license.link"],
		})
	}

	a.Params.Architecture = kv["general.architecture"]
	a.Params.ArchitectureFamily = kv["general.architecture"]
	a.Params.ParameterCount = kv["general.size_label"]
	if ft := kv["general.file_type"]; ft != "" {
		a.Params.Quantization = ggufFileType(ft)
	}

	// Architecture-namespaced hyperparameters (<arch>.context_length, etc.).
	if arch := kv["general.architecture"]; arch != "" {
		hp := map[string]string{}
		prefix := arch + "."
		for k, v := range kv {
			if strings.HasPrefix(k, prefix) && !strings.HasPrefix(k, arch+".vocab") {
				hp[strings.TrimPrefix(k, prefix)] = v
			}
		}
		if q := kv["general.quantization_version"]; q != "" {
			hp["quantization_version"] = q
		}
		if len(hp) > 0 {
			a.Params.Hyperparameters = hp
		}
	}

	a.Runtime.Framework = "gguf/ggml"
	if qb := kv["general.quantized_by"]; qb != "" {
		a.Runtime.Producer = qb
	}

	// Lineage: base models and sources use indexed keys
	// (general.base_model.0.name, general.base_model.0.repo_url, ...).
	a.Lineage.BaseModels = collectIndexed(kv, "general.base_model")
	a.Lineage.Sources = collectIndexed(kv, "general.source")
	for _, ds := range kvList["general.datasets"] {
		a.Lineage.Datasets = append(a.Lineage.Datasets, model.Reference{Name: ds})
	}
}

// collectIndexed gathers general.<group>.<n>.<field> keys into References.
func collectIndexed(kv map[string]string, group string) []model.Reference {
	byIndex := map[string]*model.Reference{}
	var order []string
	prefix := group + "."
	for k, v := range kv {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		rest := strings.TrimPrefix(k, prefix)
		idx, field, ok := strings.Cut(rest, ".")
		if !ok {
			// general.base_model.count and similar scalars — skip.
			continue
		}
		ref := byIndex[idx]
		if ref == nil {
			ref = &model.Reference{}
			byIndex[idx] = ref
			order = append(order, idx)
		}
		switch field {
		case "name":
			ref.Name = v
		case "repo_url", "url":
			ref.URL = v
		case "doi":
			ref.DOI = v
		case "organization":
			if ref.Name == "" {
				ref.Name = v
			}
		}
	}
	// Stable order by numeric index.
	sortIndexKeys(order)
	var out []model.Reference
	for _, idx := range order {
		r := byIndex[idx]
		if r.Name != "" || r.URL != "" || r.DOI != "" {
			out = append(out, *r)
		}
	}
	return out
}

// ggufFileType maps a general.file_type enum value to a quantization name.
func ggufFileType(raw string) string {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return raw
	}
	if name, ok := ggufFileTypes[n]; ok {
		return name
	}
	return "file_type=" + raw
}

var ggufFileTypes = map[int]string{
	0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1",
	7: "Q8_0", 8: "Q5_0", 9: "Q5_1",
	10: "Q2_K", 11: "Q3_K_S", 12: "Q3_K_M", 13: "Q3_K_L",
	14: "Q4_K_S", 15: "Q4_K_M", 16: "Q5_K_S", 17: "Q5_K_M",
	18: "Q6_K", 19: "IQ2_XXS", 20: "IQ2_XS", 21: "Q2_K_S",
	22: "IQ3_XS", 23: "IQ3_XXS", 24: "IQ1_S", 25: "IQ4_NL",
	26: "IQ3_S", 27: "IQ3_M", 28: "IQ2_S", 29: "IQ2_M",
	30: "IQ4_XS", 31: "IQ1_M", 32: "BF16",
}

var ggmlTypes = map[uint32]string{
	0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 6: "Q5_0", 7: "Q5_1",
	8: "Q8_0", 9: "Q8_1", 10: "Q2_K", 11: "Q3_K", 12: "Q4_K",
	13: "Q5_K", 14: "Q6_K", 15: "Q8_K", 30: "BF16",
}

func ggmlTypeName(t uint32) string {
	if n, ok := ggmlTypes[t]; ok {
		return n
	}
	return "ggml_type=" + strconv.FormatUint(uint64(t), 10)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// sortIndexKeys orders the numeric index keys of a general.<group>.<n>.<field>
// family so lineage entries come out in the order the file declared them.
func sortIndexKeys(s []string) {
	sort.Slice(s, func(i, j int) bool { return lessIndex(s[i], s[j]) })
}

// lessIndex compares two index keys numerically when both are numbers, and
// lexically otherwise.
func lessIndex(a, b string) bool {
	ai, aerr := strconv.Atoi(a)
	bi, berr := strconv.Atoi(b)
	if aerr == nil && berr == nil {
		return ai < bi
	}
	return a < b
}
