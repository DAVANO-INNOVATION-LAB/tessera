package model

import "strings"

// BSI TR-03183-2 component classification.
//
// The guideline requires three boolean-ish properties on every component, and
// they are not metadata a model file carries — they are determinations about
// what the file *is*. §3.2.6 defines an executable file as "any file which
// comprises code that is executed by a computer, either directly or by a
// runtime system", and §5.2.2 requires the structured property to say whether
// "metadata of the contents is still present".
//
// Making the determination here rather than in an emitter keeps one answer:
// the coverage report and the document it describes cannot disagree about
// whether a model is executable.

// BSI property values, spelled as the guideline spells them.
const (
	BSIExecutable    = "executable"
	BSINonExecutable = "non-executable"
	BSIArchive       = "archive"
	BSINoArchive     = "no archive"
	BSIStructured    = "structured"
	BSIUnstructured  = "unstructured"
)

// File roles, as recorded on FileComponent.Role.
const (
	RolePrimary      = "primary"
	RoleShard        = "shard"
	RoleExternalData = "external-data"
)

// ExecutableProperty reports whether the model's primary file comprises code
// that runs when a runtime system loads it.
//
// This is where the formats genuinely differ, and the answer is the reason
// safetensors exists:
//
//   - GGUF carries tokenizer.chat_template, which loaders render through a
//     template engine. That is code executed by a runtime system.
//   - ONNX resolves custom operator domains to native kernel libraries, and a
//     graph naming one cannot run without executing out-of-tree code.
//   - safetensors is a length-prefixed header and a tensor blob. There is no
//     path by which loading one executes anything, which is precisely why it
//     was designed.
//
// A GGUF with no template and an ONNX with no custom domain are reported as
// non-executable, because the property describes the file in front of you and
// not the worst file its format permits.
func (a *Artifact) ExecutableProperty() string {
	switch a.Format {
	case FormatGGUF:
		if a.Raw["tokenizer.chat_template"] != "" {
			return BSIExecutable
		}
	case FormatONNX:
		if len(a.Runtime.CustomDomains) > 0 {
			return BSIExecutable
		}
	}
	return BSINonExecutable
}

// ArchiveProperty reports whether the component is an archive.
//
// None of the three formats is one. They are single files with a header and a
// tensor region; a sharded model is several such files, not one containing the
// others. Saying so explicitly is the point — the guideline requires the
// property to be present, and "not applicable" is not one of its values.
func (a *Artifact) ArchiveProperty() string { return BSINoArchive }

// StructuredProperty reports whether metadata of the contents is still present.
//
// It always is: every format this tool parses is parsed precisely because its
// tensor names, shapes and dtypes are readable without loading a framework. A
// file for which this were false is one the analysis could not have described.
func (a *Artifact) StructuredProperty() string { return BSIStructured }

// FileExecutableProperty classifies one physical file of a multi-file model.
//
// Shards and external tensor data are inert on their own: they hold weights,
// and nothing loads them except through the primary file. Reporting them as
// executable because the model they belong to is would misstate what the
// component is.
func (a *Artifact) FileExecutableProperty(f FileComponent) string {
	if f.Role == RolePrimary {
		return a.ExecutableProperty()
	}
	return BSINonExecutable
}

// FileStructuredProperty classifies one physical file.
//
// A safetensors shard carries its own header, so its contents are described. A
// GGUF split shard past the first and an ONNX external-data blob are raw tensor
// bytes with no metadata of their own — unstructured, and the guideline's own
// distinction is exactly this one.
func (a *Artifact) FileStructuredProperty(f FileComponent) string {
	if f.Role == RolePrimary {
		return BSIStructured
	}
	if f.Role == RoleShard && a.Format == FormatSafetensors {
		return BSIStructured
	}
	if strings.HasSuffix(strings.ToLower(f.Path), ".safetensors") {
		return BSIStructured
	}
	return BSIUnstructured
}
