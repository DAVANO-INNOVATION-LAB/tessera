package model

import "strings"

// ActiveJinja reports whether a chat template reaches for the interpreter
// rather than merely formatting a conversation.
//
// Chat templates are rendered by a template engine at load time, so a template
// is executable content shipped with the weights. CVE-2024-34359 is that path
// reaching remote code execution in llama-cpp-python, and llama.cpp took its
// own template-parser CVE later.
//
// Nearly every instruct model has a template full of {% %} control flow, so
// flagging control flow alone flags the entire category and teaches a reviewer
// to ignore the finding. What is worth reporting is a template reaching for
// something a conversation formatter never needs.
//
// This lives here, in the package both the inspector and the metadata scanner
// already depend on, because the same template arrives by two routes: as GGUF
// metadata, and as a tokenizer_config.json beside safetensors weights. It was
// checked on one of them.
func ActiveJinja(s string) bool {
	// Dunder traversal is the universal signature: __globals__, __class__,
	// __subclasses__, __init__ are how every published escape gets from a
	// template object to the interpreter.
	if strings.Contains(s, "__") {
		return true
	}
	// Gadget objects Jinja exposes that are only useful as a bridge to Python.
	for _, gadget := range []string{"namespace(", "cycler", "lipsum", "joiner"} {
		if strings.Contains(s, gadget) {
			return true
		}
	}
	// Loading another template moves the logic somewhere this file cannot show
	// a reviewer, which defeats the point of reading the template at all.
	for _, tag := range []string{"{% import", "{%import", "{% from", "{%from",
		"{% extends", "{%extends", "{% include", "{%include"} {
		if strings.Contains(s, tag) {
			return true
		}
	}
	// Direct reaches for process and evaluation primitives.
	for _, call := range []string{"os.", "subprocess", "popen", "system(",
		"eval(", "exec(", "importlib", "builtins"} {
		if strings.Contains(s, call) {
			return true
		}
	}
	return false
}
