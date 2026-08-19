package parse

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Minimal protobuf wire encoders for building an ONNX ModelProto in tests.
func pbTag(field, wire int) []byte {
	return binary.AppendUvarint(nil, uint64(field)<<3|uint64(wire))
}
func pbVarint(field int, v uint64) []byte {
	return append(pbTag(field, wireVarint), binary.AppendUvarint(nil, v)...)
}
func pbBytes(field int, b []byte) []byte {
	out := pbTag(field, wireLen)
	out = append(out, binary.AppendUvarint(nil, uint64(len(b)))...)
	return append(out, b...)
}
func pbString(field int, s string) []byte {
	return pbBytes(field, []byte(s))
}

func writeONNX(t *testing.T) string {
	t.Helper()

	// StringStringEntryProto{key:"location", value:"../../etc/passwd"}
	extEntry := append(pbString(sseKey, "location"), pbString(sseValue, "../../etc/passwd")...)
	// TensorProto initializer with data_location=EXTERNAL and that external_data.
	initializer := pbBytes(tensorExternalData, extEntry)

	// NodeProto{op_type:"Conv"}
	node1 := pbString(nodeOpType, "Conv")
	// NodeProto{op_type:"MyCustomOp", domain:"com.example.custom"}
	node2 := append(pbString(nodeOpType, "MyCustomOp"), pbString(nodeDomain, "com.example.custom")...)

	// GraphProto
	graph := append([]byte{}, pbBytes(graphNode, node1)...)
	graph = append(graph, pbBytes(graphNode, node2)...)
	graph = append(graph, pbBytes(graphInitializer, initializer)...)

	// OperatorSetIdProto entries.
	opsetStd := append(pbString(opsetDomain, ""), pbVarint(opsetVersion, 17)...)
	opsetCustom := append(pbString(opsetDomain, "com.example.custom"), pbVarint(opsetVersion, 1)...)

	// metadata_props StringStringEntryProto{key:"license", value:"bsd-3-clause"}
	metaLic := append(pbString(sseKey, "license"), pbString(sseValue, "bsd-3-clause")...)

	// ModelProto
	var m []byte
	m = append(m, pbVarint(mpIRVersion, 9)...)
	m = append(m, pbString(mpProducerName, "pytorch")...)
	m = append(m, pbString(mpProducerVersion, "2.3.0")...)
	m = append(m, pbVarint(mpModelVersion, 1)...)
	m = append(m, pbString(mpDocString, "a test model")...)
	m = append(m, pbBytes(mpOpsetImport, opsetStd)...)
	m = append(m, pbBytes(mpOpsetImport, opsetCustom)...)
	m = append(m, pbBytes(mpMetadataProps, metaLic)...)
	m = append(m, pbBytes(mpGraph, graph)...)

	dir := t.TempDir()
	path := filepath.Join(dir, "model.onnx")
	if err := os.WriteFile(path, m, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseONNX(t *testing.T) {
	path := writeONNX(t)
	a, err := ParseONNX(path)
	if err != nil {
		t.Fatalf("ParseONNX: %v", err)
	}
	if a.Runtime.Producer != "pytorch" {
		t.Errorf("producer = %q", a.Runtime.Producer)
	}
	if a.Runtime.IRVersion != "9" {
		t.Errorf("ir_version = %q", a.Runtime.IRVersion)
	}
	if a.Identity.Version != "1" {
		t.Errorf("model_version = %q", a.Identity.Version)
	}
	if a.Identity.Description != "a test model" {
		t.Errorf("doc_string = %q", a.Identity.Description)
	}
	if len(a.Runtime.OpsetImports) != 2 {
		t.Errorf("opsets = %+v", a.Runtime.OpsetImports)
	}
	if len(a.Runtime.CustomDomains) != 1 || a.Runtime.CustomDomains[0] != "com.example.custom" {
		t.Errorf("custom domains = %+v", a.Runtime.CustomDomains)
	}
	if len(a.Licenses) != 1 || a.Licenses[0].Raw != "bsd-3-clause" {
		t.Errorf("licenses = %+v", a.Licenses)
	}
	if a.Raw["onnx.external_data.traversal"] != "true" {
		t.Errorf("traversal not detected: %+v", a.Raw)
	}
}

// TestSubgraphPayloadIsNotHidden covers a detection bypass: the walker read only
// top-level nodes, so an identical malicious payload produced a Critical finding
// at the top level and nothing at all when moved one If-branch deep. ONNX Runtime
// executes those branch bodies like any other node, so a scanner that skips them
// returns a clean verdict on exactly the artifact it exists to catch.
func TestSubgraphPayloadIsNotHidden(t *testing.T) {
	// The payload: a custom-domain operator plus an external-data traversal.
	extEntry := append(pbString(sseKey, "location"), pbString(sseValue, "../../../etc/passwd")...)
	initializer := pbBytes(tensorExternalData, extEntry)
	evilNode := append(pbString(nodeOpType, "EvilOp"), pbString(nodeDomain, "com.attacker.custom")...)

	payloadGraph := append(pbBytes(graphNode, evilNode), pbBytes(graphInitializer, initializer)...)

	// Visible: the payload sits in the top-level graph.
	visible := append(pbVarint(mpIRVersion, 9), pbBytes(mpGraph, payloadGraph)...)

	// Hidden: the same payload is the body of an If node's attribute.
	attr := pbBytes(attrGraph, payloadGraph)
	ifNode := append(pbString(nodeOpType, "If"), pbBytes(nodeAttribute, attr)...)
	outerGraph := pbBytes(graphNode, ifNode)
	hidden := append(pbVarint(mpIRVersion, 9), pbBytes(mpGraph, outerGraph)...)

	analyse := func(t *testing.T, name string, data []byte) (domains []string, traversal bool) {
		t.Helper()
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		a, err := ParseONNX(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return a.Runtime.CustomDomains, a.Raw["onnx.external_data.traversal"] == "true"
	}

	visDomains, visTraversal := analyse(t, "visible.onnx", visible)
	hidDomains, hidTraversal := analyse(t, "hidden.onnx", hidden)

	if len(visDomains) == 0 || !visTraversal {
		t.Fatalf("the control case did not detect its own payload: domains=%v traversal=%v",
			visDomains, visTraversal)
	}
	if len(hidDomains) != len(visDomains) {
		t.Errorf("custom domains hidden in a subgraph: visible=%v hidden=%v", visDomains, hidDomains)
	}
	if hidTraversal != visTraversal {
		t.Errorf("external-data traversal hidden in a subgraph: visible=%v hidden=%v",
			visTraversal, hidTraversal)
	}
}
