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

// The line this check has to draw: control flow is what a chat template IS,
// and reaching for the interpreter is what an attack is.
//
// An earlier version flagged any "{%", which meant a High-severity finding on
// substantially every instruction-tuned model — every one of them opens with
// {% for message in messages %}. That does not make a fleet safe. It teaches a
// reviewer to click past this finding on all thousand models before they reach
// the one that matters.
func TestGGUFChatTemplateSeparatesControlFlowFromEscapes(t *testing.T) {
	tmpl := func(s string) *model.Artifact {
		return &model.Artifact{
			Format:   model.FormatGGUF,
			Licenses: []model.License{{SPDXID: "MIT"}},
			Raw:      map[string]string{"tokenizer.chat_template": s},
		}
	}

	// Ordinary templates. Every one of these is what a real instruct model
	// ships, and flagging any of them is a false positive on the whole fleet.
	for _, benign := range []string{
		"{{ system }} {{ prompt }}",
		"{% for m in messages %}{{ m['role'] }}: {{ m['content'] }}\n{% endfor %}",
		"{% if system %}{{ system }}{% endif %}{% for m in messages %}{{ m.content }}{% endfor %}",
		"{% set loop_messages = messages %}{% for message in loop_messages %}{{ message }}{% endfor %}",
		"{%- for message in messages -%}{{ message.content | trim }}{%- endfor -%}",
	} {
		if has(Analyze(tmpl(benign)), "TESS-GGUF-010") {
			t.Errorf("flagged an ordinary chat template:\n  %s", benign)
		}
	}

	// Escapes. Each of these is a published route from a template to the
	// interpreter; missing one is the failure that matters.
	for _, hostile := range []string{
		"{{ self.__init__.__globals__['os'].system('id') }}",
		"{{ ''.__class__.__mro__[1].__subclasses__() }}",
		"{{ lipsum.__globals__.os.popen('id').read() }}",
		"{% for x in cycler.__init__.__globals__ %}{{ x }}{% endfor %}",
		"{% import 'other.jinja' as o %}{{ o.run() }}",
		"{% include 'payload.jinja' %}",
		"{{ namespace(a=1) }}",
		"{{ config.items() }}{{ subprocess }}",
	} {
		if !has(Analyze(tmpl(hostile)), "TESS-GGUF-010") {
			t.Errorf("missed a template that reaches the interpreter:\n  %s", hostile)
		}
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
