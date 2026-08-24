package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// maxDocumentBytes bounds a document read. A bill of materials is a description,
// not a payload; anything larger is not one.
const maxDocumentBytes = 64 << 20

// ReadDocument loads a CycloneDX or SPDX bill of materials and reduces it to the
// claims that can be checked against bytes.
//
// The format is detected from the content rather than the filename, because the
// document being verified arrives from wherever it has been stored and its name
// is not evidence of anything.
func ReadDocument(path string) (*Document, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxDocumentBytes {
		return nil, fmt.Errorf("%s: %d bytes is too large to be a bill of materials", path, info.Size())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("%s: not a JSON bill of materials: %w", path, err)
	}
	switch {
	case probe["bomFormat"] != nil || probe["specVersion"] != nil:
		return readCycloneDX(raw)
	case probe["@graph"] != nil:
		return readSPDX(raw)
	}
	return nil, fmt.Errorf("%s: not a CycloneDX or SPDX document", path)
}

func readCycloneDX(raw []byte) (*Document, error) {
	var doc struct {
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Component cdxComponent `json:"component"`
		} `json:"metadata"`
		Components []cdxComponent `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("unreadable CycloneDX document: %w", err)
	}

	// Which component is the model.
	//
	// Documents that describe a single artifact put it at metadata.component,
	// which is what this assumed. System-level generators do not: a bill of
	// materials for a running inference service puts the *workload* there —
	// "vllm-llama3", type application — and lists the models beneath it in
	// components[]. Comparing an artifact against that top-level entry compares
	// it against a Deployment name and reports a mismatch that means nothing.
	//
	// So the subject is the top-level component when it is a model, and
	// otherwise the first machine-learning-model in the document. This is what
	// lets one verifier check documents produced by tools that describe systems
	// as well as tools that describe files.
	primary := doc.Metadata.Component
	if primary.Type != "machine-learning-model" {
		for _, c := range doc.Components {
			if c.Type == "machine-learning-model" {
				primary = c
				break
			}
		}
	}

	out := &Document{
		Format:     "CycloneDX " + doc.SpecVersion,
		ModelName:  primary.Name,
		Version:    primary.Version,
		Properties: map[string]string{},
	}

	if f := fileFromCDX(primary, primaryPathFrom(primary)); f.Path != "" {
		out.Files = append(out.Files, f)
	}
	for _, c := range doc.Components {
		if c.Type != "file" {
			continue // a library component is a runtime requirement, not a file
		}
		if f := fileFromCDX(c, c.Name); f.Path != "" {
			out.Files = append(out.Files, f)
		}
	}

	for _, p := range primary.Properties {
		if k := normalizeProperty(p.Name); k != "" {
			out.Properties[k] = p.Value
		}
	}
	if mp := primary.ModelCard.ModelParameters; mp != nil {
		if mp.ModelArchitecture != "" {
			out.Properties["architecture"] = mp.ModelArchitecture
		}
	}
	for _, p := range primary.ModelCard.Properties {
		if k := normalizeProperty(p.Name); k != "" {
			out.Properties[k] = p.Value
		}
	}
	return out, nil
}

type cdxComponent struct {
	Type       string    `json:"type"`
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	Hashes     []cdxHash `json:"hashes"`
	Properties []cdxProp `json:"properties"`
	ModelCard  struct {
		ModelParameters *struct {
			ModelArchitecture string `json:"modelArchitecture"`
		} `json:"modelParameters"`
		Properties []cdxProp `json:"properties"`
	} `json:"modelCard"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func fileFromCDX(c cdxComponent, path string) DocumentedFile {
	f := DocumentedFile{Path: path}
	for _, h := range c.Hashes {
		switch strings.ToUpper(h.Alg) {
		case "SHA-256":
			f.SHA256 = h.Content
		case "SHA-384":
			f.SHA384 = h.Content
		}
	}
	return f
}

// primaryPathFrom recovers the primary file's path from the properties, since
// the model component is named for the model rather than the file.
func primaryPathFrom(c cdxComponent) string {
	for _, p := range c.Properties {
		if p.Name == "tessera:primaryFile" {
			return p.Value
		}
	}
	return ""
}

func normalizeProperty(name string) string {
	switch name {
	case "tessera:quantization":
		return "quantization"
	case "tessera:dtype":
		return "dtype"
	case "tessera:measuredParameters":
		return "measuredParameters"
	case "tessera:architecture":
		return "architecture"
	}
	if strings.HasPrefix(name, "hyperparameter:") {
		return ""
	}
	return ""
}

func readSPDX(raw []byte) (*Document, error) {
	var doc struct {
		Graph []map[string]any `json:"@graph"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("unreadable SPDX document: %w", err)
	}
	out := &Document{Format: "SPDX 3.0.1", Properties: map[string]string{}}

	for _, node := range doc.Graph {
		switch node["type"] {
		case "ai_AIPackage":
			// The first AI package is the model; later ones are base models
			// recorded as ancestry, which are not this artifact.
			if out.ModelName != "" {
				continue
			}
			out.ModelName, _ = node["name"].(string)
			out.Version, _ = node["software_packageVersion"].(string)
			if f := fileFromSPDX(node, ""); f.SHA256 != "" || f.SHA384 != "" {
				out.Files = append(out.Files, f)
			}
			readSPDXHyperparameters(node, out.Properties)
			// The primary file rides in as a hyperparameter entry; lift it out
			// so it becomes a checkable component rather than a stray property.
			if p := out.Properties["primaryFile"]; p != "" && len(out.Files) > 0 {
				out.Files[len(out.Files)-1].Path = p
				delete(out.Properties, "primaryFile")
			}
			if t, ok := node["ai_typeOfModel"].([]any); ok && len(t) > 0 {
				if s, ok := t[0].(string); ok {
					out.Properties["architecture"] = s
				}
			}
		case "software_File":
			name, _ := node["name"].(string)
			if f := fileFromSPDX(node, name); f.Path != "" {
				out.Files = append(out.Files, f)
			}
		}
	}
	return out, nil
}

func fileFromSPDX(node map[string]any, path string) DocumentedFile {
	f := DocumentedFile{Path: path}
	hashes, _ := node["verifiedUsing"].([]any)
	for _, h := range hashes {
		hm, ok := h.(map[string]any)
		if !ok {
			continue
		}
		alg, _ := hm["algorithm"].(string)
		val, _ := hm["hashValue"].(string)
		switch strings.ToLower(alg) {
		case "sha256":
			f.SHA256 = val
		case "sha384":
			f.SHA384 = val
		}
	}
	return f
}

func readSPDXHyperparameters(node map[string]any, into map[string]string) {
	entries, _ := node["ai_hyperparameter"].([]any)
	for _, e := range entries {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		k, _ := em["key"].(string)
		v, _ := em["value"].(string)
		switch k {
		case "quantization", "measuredParameters", "primaryFile":
			into[k] = v
		}
	}
}
