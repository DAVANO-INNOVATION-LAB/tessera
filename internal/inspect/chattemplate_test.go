package inspect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A chat template is executable content shipped with the weights, and it
// arrives by two routes: GGUF metadata, and a tokenizer_config.json beside
// safetensors. Only the first was read, so the check covered the minority
// packaging of the risk — nearly every model on a public hub ships the second.
func TestAHostileChatTemplateIsFoundInTheHuggingFaceLayout(t *testing.T) {
	hostile := []string{
		`{% for m in messages %}{{ m['content'].__class__.__mro__[1].__subclasses__() }}{% endfor %}`,
		`{{ cycler.__init__.__globals__.os.popen('id').read() }}`,
		`{% import os %}{{ os.system('id') }}`,
		`{{ lipsum.__globals__["os"].system("id") }}`,
		`{% include 'other.jinja' %}`,
		`{{ self._TemplateReference__context.cycler }}`,
	}

	for _, tmpl := range hostile {
		dir := t.TempDir()
		writeTokenizerConfig(t, dir, map[string]any{"chat_template": tmpl})
		findings, err := inspectJSONConfig(filepath.Join(dir, "tokenizer_config.json"), "tokenizer_config.json")
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) == 0 {
			t.Errorf("scanned clean: %s", tmpl)
			continue
		}
		if findings[0].ID != "TESS-HF-003" || findings[0].Severity != "High" {
			t.Errorf("got %s %s, want TESS-HF-003 High", findings[0].ID, findings[0].Severity)
		}
	}
}

// The counter-check. Instruct models are full of Jinja control flow, and
// flagging that flags the entire category — which teaches a reviewer to ignore
// the finding, and is worse than not reporting it.
func TestOrdinaryChatTemplatesAreNotFlagged(t *testing.T) {
	ordinary := []string{
		`{% for message in messages %}{{ '<|im_start|>' + message['role'] + '\n' + message['content'] + '<|im_end|>\n' }}{% endfor %}{% if add_generation_prompt %}{{ '<|im_start|>assistant\n' }}{% endif %}`,
		`{{ bos_token }}{% for message in messages %}{% if message['role'] == 'user' %}{{ '[INST] ' + message['content'] + ' [/INST]' }}{% else %}{{ message['content'] + eos_token }}{% endif %}{% endfor %}`,
		`{% set loop_messages = messages %}{% for message in loop_messages %}{{ '<|start_header_id|>' + message['role'] + '<|end_header_id|>\n\n' + message['content'] | trim + '<|eot_id|>' }}{% endfor %}`,
		``,
	}

	for _, tmpl := range ordinary {
		dir := t.TempDir()
		writeTokenizerConfig(t, dir, map[string]any{"chat_template": tmpl})
		findings, err := inspectJSONConfig(filepath.Join(dir, "tokenizer_config.json"), "tokenizer_config.json")
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			if f.ID == "TESS-HF-003" {
				t.Errorf("false positive on an ordinary template: %s", tmpl)
			}
		}
	}
}

func writeTokenizerConfig(t *testing.T, dir string, cfg map[string]any) {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tokenizer_config.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}
