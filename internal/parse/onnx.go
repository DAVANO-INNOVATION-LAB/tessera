package parse

import (
	"fmt"
	"os"
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
	graphSparseInitializer = 15

	nodeAttribute = 5
	nodeOpType    = 4
	nodeDomain    = 7

	// AttributeProto: g/graphs hold control-flow bodies, t/tensors hold
	// tensors that may carry external-data references.
	attrTensor  = 5
	attrGraph   = 6
	attrTensors = 9
	attrGraphs  = 10

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
				return parseGraph(f.data, g, 1, opTypes, domains, &externalDataRefs, &traversal)
			}
		case mpFunctions:
			if f.wire == wireLen {
				return parseFunction(f.data, g, 1, opTypes, domains, &externalDataRefs, &traversal)
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
		a.SetRaw("onnx.external_data", strings.Join(dedupe(externalDataRefs), ", "))
	}
	// Stash the traversal signal for the scan pass to escalate; keep the parse's
	// job to reporting what is structurally present.
	if traversal {
		a.SetRaw("onnx.external_data.traversal", "true")
	}

	return a, nil
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
func parseGraph(b []byte, g *pbGuards, depth int, opTypes, domains map[string]bool, extRefs *[]string, traversal *bool) error {
	return walk(b, g, depth, func(f pbField) error {
		switch f.num {
		case graphNode:
			if f.wire == wireLen {
				return parseNode(f.data, g, depth+1, opTypes, domains, extRefs, traversal)
			}
		case graphInitializer, graphSparseInitializer:
			if f.wire == wireLen {
				return parseTensor(f.data, g, depth+1, extRefs, traversal)
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
func parseFunction(b []byte, g *pbGuards, depth int, opTypes, domains map[string]bool, extRefs *[]string, traversal *bool) error {
	return walk(b, g, depth, func(f pbField) error {
		if f.num == funcNode && f.wire == wireLen {
			return parseNode(f.data, g, depth+1, opTypes, domains, extRefs, traversal)
		}
		return nil
	})
}

func parseNode(b []byte, g *pbGuards, depth int, opTypes, domains map[string]bool, extRefs *[]string, traversal *bool) error {
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
				return parseAttribute(f.data, g, depth+1, opTypes, domains, extRefs, traversal)
			}
		}
		return nil
	})
}

// parseAttribute descends an AttributeProto, following the single-graph and
// repeated-graph fields that hold control-flow bodies.
func parseAttribute(b []byte, g *pbGuards, depth int, opTypes, domains map[string]bool, extRefs *[]string, traversal *bool) error {
	return walk(b, g, depth, func(f pbField) error {
		switch f.num {
		case attrGraph, attrGraphs:
			if f.wire == wireLen {
				return parseGraph(f.data, g, depth+1, opTypes, domains, extRefs, traversal)
			}
		case attrTensor, attrTensors:
			// An attribute can carry a tensor directly, and a tensor is where
			// an external-data reference lives.
			if f.wire == wireLen {
				return parseTensor(f.data, g, depth+1, extRefs, traversal)
			}
		}
		return nil
	})
}

// parseTensor inspects one TensorProto initializer for external-data pointers.
// A location that walks out of the model directory is the ONNX path-traversal
// class (CVE-2022-25882 → CVE-2024-27318 → CVE-2026-27489); the traversal flag
// records it for the scan pass to raise to Critical.
func parseTensor(b []byte, g *pbGuards, depth int, extRefs *[]string, traversal *bool) error {
	return walk(b, g, depth, func(f pbField) error {
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
}

func applyONNXMetadata(a *model.Artifact, meta map[string]string) {
	for k, v := range meta {
		a.SetRaw("metadata_props."+k, v)
	}
	if a.Identity.Name == "" {
		a.Identity.Name = firstNonEmpty(meta["model_name"], meta["name"])
	}
	if a.Identity.Author == "" {
		a.Identity.Author = firstNonEmpty(meta["author"], meta["organization"])
	}
	// ONNX has no standard license field; producers who care put it here.
	if lic := firstNonEmpty(meta["license"], meta["licenses"]); lic != "" {
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

func dedupe(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range items {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
