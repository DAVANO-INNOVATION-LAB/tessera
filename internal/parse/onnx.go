package parse

import (
	"cmp"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// ONNX is a serialized protobuf ModelProto. Tessera reads it with the hand-
// rolled wire reader rather than the onnx library so the parse stays inert: it
// never resolves a custom operator kernel and never fetches external tensor
// data. What it extracts is the producer/opset/graph metadata that populates a
// bill of materials, and the two structural facts that matter for security —
// which operator domains are non-standard (custom native code) and whether any
// initializer points at external data via a traversal path.

// ModelProto field numbers (onnx.proto).
const (
	mpIRVersion       = 1
	mpProducerName    = 2
	mpProducerVersion = 3
	mpDomain          = 4
	mpModelVersion    = 5
	mpDocString       = 6
	mpGraph           = 7
	mpOpsetImport     = 8
	mpMetadataProps   = 14
)

// OperatorSetIdProto / StringStringEntryProto / GraphProto / NodeProto /
// TensorProto / ValueInfoProto field numbers.
const (
	opsetDomain  = 1
	opsetVersion = 2

	sseKey   = 1
	sseValue = 2

	graphNode              = 1
	graphInitializer       = 5
	graphInput             = 11
	graphOutput            = 12
	graphSparseInitializer = 15

	// ValueInfoProto / TypeProto / TensorShapeProto, for graph I/O signatures.
	valueInfoName  = 1
	valueInfoType  = 2
	typeTensorType = 1
	tensorElemType = 1
	tensorShape    = 2
	shapeDim       = 1
	dimValue       = 1
	dimParam       = 2

	nodeAttribute = 5
	nodeOpType    = 4
	nodeDomain    = 7

	// AttributeProto: g/graphs hold control-flow bodies, t/tensors hold
	// tensors that may carry external-data references.
	attrTensor  = 5
	attrGraph   = 6
	attrTensors = 9
	attrGraphs  = 10

	tensorDims         = 1
	tensorName         = 8
	tensorExternalData = 13

	// ModelProto.functions holds locally-defined operator bodies, which are
	// executed like any other graph.
	mpFunctions = 25
	funcNode    = 4
)

// Caps on how much attacker-declared structure is retained. Without them a file
// of repeated two-byte fields turns a few megabytes on disk into hundreds of
// megabytes of live objects, and then into a bill of materials just as large.
const (
	maxONNXOpsets       = 4096
	maxONNXCustomDomain = 4096
	maxONNXExternalRefs = 4096
	maxONNXMetadata     = 4096
	maxONNXOpTypes      = 65536
	// A model's signature is a handful of tensors; anything beyond this is a
	// crafted file rather than a description worth carrying.
	maxONNXIOSpecs = 256
	maxONNXDims    = 16
)

// standardONNXDomains are the operator domains that ship with ONNX / ONNX
// Runtime. Anything else resolves to out-of-tree code and is worth surfacing.
var standardONNXDomains = map[string]bool{
	"":                         true, // the default ai.onnx domain
	"ai.onnx":                  true,
	"ai.onnx.ml":               true,
	"ai.onnx.training":         true,
	"ai.onnx.preview.training": true,
}

// ParseONNX reads an ONNX file's ModelProto metadata and graph structure.
func ParseONNX(path string) (*model.Artifact, error) {
	return parseONNXBounded(path, DefaultMaxFileSize)
}

// parseONNXBounded is ParseONNX with an explicit ceiling on bytes held in
// memory. ONNX is protobuf, so the message has to be walked in memory; a model
// past the ceiling is reported rather than loaded, which keeps a hostile or
// merely enormous file from deciding the process's memory footprint.
func parseONNXBounded(path string, maxSize int64) (*model.Artifact, error) {
	if maxSize <= 0 {
		maxSize = DefaultMaxFileSize
	}
	if info, err := os.Stat(path); err == nil && info.Size() > maxSize {
		a := &model.Artifact{Format: model.FormatONNX}
		a.Runtime.Framework = "onnx"
		a.AddFinding(model.Finding{
			ID: "TESS-ONNX-006", Title: "ONNX file exceeds the parse ceiling", Severity: "Medium",
			Category: "model", Location: path,
			Description: fmt.Sprintf("the file is %d bytes, above the %d-byte parse ceiling, so its graph "+
				"was not examined. An unexamined graph has not been cleared; raise the ceiling to scan it.",
				info.Size(), maxSize),
		})
		return a, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	a := &model.Artifact{Format: model.FormatONNX}
	a.Runtime.Framework = "onnx"

	g := defaultGuards()
	meta := map[string]string{}
	opTypes := map[string]bool{}
	domains := map[string]bool{}
	var externalDataRefs []string
	traversal := false
	// Initializers are the model's weights. Their names are needed to tell a
	// real graph input from a weight that older ONNX also lists as one, and
	// their shapes are where the parameter count actually lives.
	initializers := map[string]bool{}
	var measured int64

	err = walk(data, g, 0, func(f pbField) error {
		switch f.num {
		case mpIRVersion:
			if f.wire == wireVarint {
				a.Runtime.IRVersion = strconv.FormatInt(asInt64(f.num64), 10)
			}
		case mpProducerName:
			if f.wire == wireLen {
				a.Runtime.Producer = f.str()
			}
		case mpProducerVersion:
			if f.wire == wireLen {
				a.SetRaw("producer_version", f.str())
			}
		case mpDomain:
			if f.wire == wireLen {
				a.SetRaw("domain", f.str())
			}
		case mpModelVersion:
			if f.wire == wireVarint {
				a.Identity.Version = strconv.FormatInt(asInt64(f.num64), 10)
			}
		case mpDocString:
			if f.wire == wireLen {
				a.Identity.Description = f.str()
			}
		case mpOpsetImport:
			if f.wire == wireLen && len(a.Runtime.OpsetImports) < maxONNXOpsets {
				dom, ver := parseOpset(f.data, g)
				a.Runtime.OpsetImports = append(a.Runtime.OpsetImports, model.Opset{Domain: dom, Version: ver})
			}
		case mpMetadataProps:
			if f.wire == wireLen && len(meta) < maxONNXMetadata {
				k, v := parseStringEntry(f.data, g)
				if k != "" {
					meta[k] = v
				}
			}
		case mpGraph:
			if f.wire == wireLen {
				// The model's own signature comes from the top-level graph only.
				// A subgraph's inputs are branch-local plumbing, not something a
				// caller of the model ever supplies.
				// Walk the graph first so the initializer set is known, then
				// read the signature and drop any "input" that is really a
				// weight. ONNX before IR 4 listed initializers in graph.input,
				// so a naive read reports a nine-input MNIST.
				if err := parseGraph(f.data, g, 1, opTypes, domains, &externalDataRefs, &traversal, initializers, &measured); err != nil {
					return err
				}
				a.Params.Inputs = filterInitializers(parseValueInfos(f.data, g, graphInput), initializers)
				a.Params.Outputs = parseValueInfos(f.data, g, graphOutput)
				return nil
			}
		case mpFunctions:
			if f.wire == wireLen {
				return parseFunction(f.data, g, 1, opTypes, domains, &externalDataRefs, &traversal, initializers, &measured)
			}
		}
		return nil
	})
	if err != nil {
		a.AddFinding(model.Finding{
			ID: "TESS-ONNX-005", Title: "ONNX parse aborted", Severity: "Medium", Category: "model",
			Location: path,
			Description: fmt.Sprintf("the protobuf walk stopped early (%v); the model may be malformed "+
				"or crafted to exhaust a parser. What was read before the stop is reported; the rest was not.", err),
		})
	}

	a.Params.MeasuredParameters = measured

	applyONNXMetadata(a, meta)

	// Assemble the sorted operator inventory and custom-domain list.
	a.SetRaw("onnx.operators", strconv.Itoa(len(opTypes)))
	var customDomains []string
	for d := range domains {
		if !standardONNXDomains[d] {
			customDomains = append(customDomains, d)
		}
	}
	sort.Strings(customDomains)
	a.Runtime.CustomDomains = customDomains

	if len(externalDataRefs) > 0 {
		sort.Strings(externalDataRefs)
		a.SetRaw("onnx.external_data", strings.Join(slices.Compact(externalDataRefs), ", "))
	}
	// Stash the traversal signal for the scan pass to escalate; keep the parse's
	// job to reporting what is structurally present.
	if traversal {
		a.SetRaw("onnx.external_data.traversal", "true")
	}

	return a, nil
}

// parseValueInfos reads a graph's input or output signature.
//
// This is what the EU AI Act Annex XI calls "the modality and format of inputs
// and outputs", and it is one of the few items in that annex a file parse can
// actually produce. ONNX states it precisely; the other two formats do not
// state it at all.
func parseValueInfos(graph []byte, g *pbGuards, field int) []model.IOSpec {
	var out []model.IOSpec
	_ = walk(graph, g, 2, func(f pbField) error {
		if f.num != field || f.wire != wireLen || len(out) >= maxONNXIOSpecs {
			return nil
		}
		var spec model.IOSpec
		_ = walk(f.data, g, 3, func(v pbField) error {
			switch v.num {
			case valueInfoName:
				if v.wire == wireLen {
					spec.Name = v.str()
				}
			case valueInfoType:
				if v.wire == wireLen {
					spec.DType, spec.Shape = parseTypeProto(v.data, g)
				}
			}
			return nil
		})
		if spec.Name != "" || spec.DType != "" {
			spec.Format = "tensor"
			out = append(out, spec)
		}
		return nil
	})
	return out
}

// parseTypeProto pulls the element type and dimensions out of a TypeProto.
// A symbolic dimension (a named batch axis, say) has no numeric value; it is
// recorded as -1 rather than dropped, so a caller can tell a dynamic axis from
// a missing one.
func parseTypeProto(b []byte, g *pbGuards) (string, []int64) {
	var dtype string
	var shape []int64
	_ = walk(b, g, 4, func(t pbField) error {
		if t.num != typeTensorType || t.wire != wireLen {
			return nil
		}
		_ = walk(t.data, g, 5, func(tt pbField) error {
			switch tt.num {
			case tensorElemType:
				if tt.wire == wireVarint {
					dtype = onnxElemTypeName(int32(tt.num64))
				}
			case tensorShape:
				if tt.wire == wireLen {
					_ = walk(tt.data, g, 6, func(sh pbField) error {
						if sh.num != shapeDim || sh.wire != wireLen || len(shape) >= maxONNXDims {
							return nil
						}
						dim := int64(-1)
						_ = walk(sh.data, g, 7, func(d pbField) error {
							switch d.num {
							case dimValue:
								if d.wire == wireVarint {
									dim = asInt64(d.num64)
								}
							case dimParam:
								dim = -1 // symbolic, e.g. a named batch axis
							}
							return nil
						})
						shape = append(shape, dim)
						return nil
					})
				}
			}
			return nil
		})
		return nil
	})
	return dtype, shape
}

// onnxElemTypeName maps TensorProto.DataType to its spec name.
func onnxElemTypeName(t int32) string {
	names := map[int32]string{
		1: "float", 2: "uint8", 3: "int8", 4: "uint16", 5: "int16",
		6: "int32", 7: "int64", 8: "string", 9: "bool", 10: "float16",
		11: "double", 12: "uint32", 13: "uint64", 14: "complex64",
		15: "complex128", 16: "bfloat16",
		17: "float8e4m3fn", 18: "float8e4m3fnuz", 19: "float8e5m2", 20: "float8e5m2fnuz",
		21: "uint4", 22: "int4", 23: "float4e2m1",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return "elem_type=" + strconv.FormatInt(int64(t), 10)
}

func parseOpset(b []byte, g *pbGuards) (string, int64) {
	var domain string
	var version int64
	_ = walk(b, g, 1, func(f pbField) error {
		switch f.num {
		case opsetDomain:
			if f.wire == wireLen {
				domain = f.str()
			}
		case opsetVersion:
			if f.wire == wireVarint {
				version = asInt64(f.num64)
			}
		}
		return nil
	})
	return domain, version
}

func parseStringEntry(b []byte, g *pbGuards) (string, string) {
	var k, v string
	_ = walk(b, g, 1, func(f pbField) error {
		switch f.num {
		case sseKey:
			if f.wire == wireLen {
				k = f.str()
			}
		case sseValue:
			if f.wire == wireLen {
				v = f.str()
			}
		}
		return nil
	})
	return k, v
}

// parseGraph descends one GraphProto, collecting the operator inventory,
// operator domains, and external-data references from initializers. It records
// op types and domains into the shared sets and appends external-data locations.
func parseGraph(b []byte, g *pbGuards, depth int, opTypes, domains map[string]bool, extRefs *[]string, traversal *bool, inits map[string]bool, measured *int64) error {
	return walk(b, g, depth, func(f pbField) error {
		switch f.num {
		case graphNode:
			if f.wire == wireLen {
				return parseNode(f.data, g, depth+1, opTypes, domains, extRefs, traversal, inits, measured)
			}
		case graphInitializer, graphSparseInitializer:
			if f.wire == wireLen {
				return parseTensor(f.data, g, depth+1, extRefs, traversal, inits, measured)
			}
		}
		return nil
	})
}

// parseNode reads one NodeProto, and descends into any subgraph it carries.
//
// Descending is not optional. Control-flow operators (If, Loop, Scan) hold
// their branch bodies in an attribute of type GraphProto, and ONNX Runtime
// executes those bodies exactly like top-level nodes. A scanner that reads only
// the top level reports a clean verdict on a model whose malicious operator or
// external-data reference is one `If` deep — which is a silent pass on the
// artifact it exists to catch. The depth guard in the walker is what makes this
// descent safe to do.
// parseFunction walks a locally-defined operator body. Its nodes execute like
// any other, so the same inventory and checks apply.
func parseFunction(b []byte, g *pbGuards, depth int, opTypes, domains map[string]bool, extRefs *[]string, traversal *bool, inits map[string]bool, measured *int64) error {
	return walk(b, g, depth, func(f pbField) error {
		if f.num == funcNode && f.wire == wireLen {
			return parseNode(f.data, g, depth+1, opTypes, domains, extRefs, traversal, inits, measured)
		}
		return nil
	})
}

func parseNode(b []byte, g *pbGuards, depth int, opTypes, domains map[string]bool, extRefs *[]string, traversal *bool, inits map[string]bool, measured *int64) error {
	return walk(b, g, depth, func(f pbField) error {
		switch f.num {
		case nodeOpType:
			if f.wire == wireLen && len(opTypes) < maxONNXOpTypes {
				opTypes[f.str()] = true
			}
		case nodeDomain:
			if f.wire == wireLen && len(domains) < maxONNXCustomDomain {
				domains[f.str()] = true
			}
		case nodeAttribute:
			if f.wire == wireLen {
				return parseAttribute(f.data, g, depth+1, opTypes, domains, extRefs, traversal, inits, measured)
			}
		}
		return nil
	})
}

// parseAttribute descends an AttributeProto, following the single-graph and
// repeated-graph fields that hold control-flow bodies.
func parseAttribute(b []byte, g *pbGuards, depth int, opTypes, domains map[string]bool, extRefs *[]string, traversal *bool, inits map[string]bool, measured *int64) error {
	return walk(b, g, depth, func(f pbField) error {
		switch f.num {
		case attrGraph, attrGraphs:
			if f.wire == wireLen {
				return parseGraph(f.data, g, depth+1, opTypes, domains, extRefs, traversal, inits, measured)
			}
		case attrTensor, attrTensors:
			// An attribute can carry a tensor directly, and a tensor is where
			// an external-data reference lives.
			if f.wire == wireLen {
				return parseTensor(f.data, g, depth+1, extRefs, traversal, inits, measured)
			}
		}
		return nil
	})
}

// parseTensor inspects one TensorProto initializer for external-data pointers.
// A location that walks out of the model directory is the ONNX path-traversal
// class (CVE-2022-25882 → CVE-2024-27318 → CVE-2026-27489); the traversal flag
// records it for the scan pass to raise to Critical.
func parseTensor(b []byte, g *pbGuards, depth int, extRefs *[]string, traversal *bool, inits map[string]bool, measured *int64) error {
	var dims []int64
	var name string
	err := walk(b, g, depth, func(f pbField) error {
		switch {
		case f.num == tensorDims && f.wire == wireVarint:
			if len(dims) < maxONNXDims {
				dims = append(dims, asInt64(f.num64))
			}
		case f.num == tensorName && f.wire == wireLen:
			name = f.str()
		}
		if f.num == tensorExternalData && f.wire == wireLen {
			k, v := parseStringEntry(f.data, g)
			if k == "location" && v != "" {
				if len(*extRefs) < maxONNXExternalRefs {
					*extRefs = append(*extRefs, v)
				}
				if isTraversal(v) {
					*traversal = true
				}
			}
		}
		return nil
	})
	if name != "" && len(inits) < maxONNXOpTypes {
		inits[name] = true
	}
	*measured += elementCount(dims)
	return err
}

// filterInitializers drops graph inputs that name a weight.
//
// ONNX before IR version 4 required every initializer to also appear in
// graph.input, so the raw list conflates the model's actual signature with its
// parameters. Reporting both as "inputs" would put a nine-input MNIST into a
// compliance document.
func filterInitializers(specs []model.IOSpec, inits map[string]bool) []model.IOSpec {
	out := specs[:0]
	for _, s := range specs {
		if !inits[s.Name] {
			out = append(out, s)
		}
	}
	return out
}

func applyONNXMetadata(a *model.Artifact, meta map[string]string) {
	for k, v := range meta {
		a.SetRaw("metadata_props."+k, v)
	}
	if a.Identity.Name == "" {
		a.Identity.Name = cmp.Or(meta["model_name"], meta["name"])
	}
	if a.Identity.Author == "" {
		a.Identity.Author = cmp.Or(meta["author"], meta["organization"])
	}
	// ONNX has no standard license field; producers who care put it here.
	if lic := cmp.Or(meta["license"], meta["licenses"]); lic != "" {
		a.Licenses = append(a.Licenses, model.License{Raw: lic})
	}
	if a.Identity.Description == "" {
		a.Identity.Description = meta["description"]
	}
}

// isTraversal reports whether a path reference tries to leave the directory it
// is relative to. It is the sole gate on the only Critical finding this package
// raises, so it errs toward reporting.
//
// Windows conventions are handled because Windows binaries are shipped: a
// drive-absolute path like C:\Windows\... contains no ".." and does not start
// with a separator, so a POSIX-only check reports it as perfectly local on the
// one platform where it is not.
func isTraversal(p string) bool {
	if p == "" {
		return false
	}
	cleaned := strings.ReplaceAll(p, "\\", "/")

	// POSIX-absolute, and UNC (\\server\share) once separators are folded.
	if strings.HasPrefix(cleaned, "/") {
		return true
	}
	// Drive-absolute (C:/...) and drive-relative (C:file), both of which resolve
	// against something other than the model directory.
	if len(cleaned) >= 2 && cleaned[1] == ':' && isDriveLetter(cleaned[0]) {
		return true
	}
	for _, part := range strings.Split(cleaned, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func isDriveLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
