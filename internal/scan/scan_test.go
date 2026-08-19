package scan

import (
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

func has(findings []model.Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestGGUFChatTemplate(t *testing.T) {
	a := &model.Artifact{
		Format:   model.FormatGGUF,
		Licenses: []model.License{{SPDXID: "MIT"}},
		Raw:      map[string]string{"tokenizer.chat_template": "{% if x %}{{ x }}{% endif %}"},
	}
	if !has(Analyze(a), "TESS-GGUF-010") {
		t.Errorf("active Jinja template should be flagged")
	}

	// A plain substitution template must NOT be flagged — that would be noise on
	// nearly every instruct model.
	b := &model.Artifact{
		Format:   model.FormatGGUF,
		Licenses: []model.License{{SPDXID: "MIT"}},
		Raw:      map[string]string{"tokenizer.chat_template": "{{ system }} {{ prompt }}"},
	}
	if has(Analyze(b), "TESS-GGUF-010") {
		t.Errorf("plain substitution template should not be flagged")
	}
}

func TestGGUFAlignment(t *testing.T) {
	a := &model.Artifact{
		Format:   model.FormatGGUF,
		Licenses: []model.License{{SPDXID: "MIT"}},
		Raw:      map[string]string{"general.alignment": "999999999"},
	}
	if !has(Analyze(a), "TESS-GGUF-011") {
		t.Errorf("implausible alignment should be flagged")
	}

	ok := &model.Artifact{
		Format:   model.FormatGGUF,
		Licenses: []model.License{{SPDXID: "MIT"}},
		Raw:      map[string]string{"general.alignment": "32"},
	}
	if has(Analyze(ok), "TESS-GGUF-011") {
		t.Errorf("default alignment 32 should not be flagged")
	}
}

func TestONNXFindings(t *testing.T) {
	a := &model.Artifact{
		Format:   model.FormatONNX,
		Licenses: []model.License{{SPDXID: "Apache-2.0"}},
		Runtime:  model.Runtime{CustomDomains: []string{"com.evil.ops"}},
		Raw:      map[string]string{"onnx.external_data.traversal": "true"},
	}
	fs := Analyze(a)
	if !has(fs, "TESS-ONNX-010") {
		t.Errorf("custom domain should be flagged")
	}
	if !has(fs, "TESS-ONNX-011") {
		t.Errorf("external-data traversal should be flagged Critical")
	}
	for _, f := range fs {
		if f.ID == "TESS-ONNX-011" && f.Severity != "Critical" {
			t.Errorf("traversal severity = %q, want Critical", f.Severity)
		}
	}
}

func TestNoLicenseFinding(t *testing.T) {
	a := &model.Artifact{Format: model.FormatSafetensors} // no licenses
	if !has(Analyze(a), "TESS-LIC-001") {
		t.Errorf("missing license should produce the compliance finding")
	}

	withLic := &model.Artifact{
		Format:   model.FormatSafetensors,
		Licenses: []model.License{{SPDXID: "MIT"}},
	}
	if has(Analyze(withLic), "TESS-LIC-001") {
		t.Errorf("a resolved license should suppress the finding")
	}
}
