package coverage

import (
	"strings"
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// BSI TR-03183-2 requires the hash "as SHA-512" — by algorithm, not by
// strength. A document carrying SHA-384 is stronger under CNSA 2.0 and still
// not conformant here, so the element must not be satisfied by the other
// digests.
func TestBSIHashElementNeedsSHA512Specifically(t *testing.T) {
	a := &model.Artifact{
		Format:   model.FormatSafetensors,
		Identity: model.Identity{Name: "m", Version: "1"},
		Files: []model.FileComponent{{
			Path: "model.safetensors", Role: model.RolePrimary,
			SHA256: "aa", SHA384: "bb",
		}},
	}
	r, err := Assess(BSI, a)
	if err != nil {
		t.Fatal(err)
	}
	el := elementNamed(t, r, "Hash value of the deployable component (SHA-512)")
	if el.Status != Absent {
		t.Fatalf("with no SHA-512 the element must be absent, got %s", el.Status)
	}

	a.Files[0].SHA512 = "cc"
	r, _ = Assess(BSI, a)
	if elementNamed(t, r, "Hash value of the deployable component (SHA-512)").Status != Populated {
		t.Fatal("with a SHA-512 present the element must be populated")
	}
}

// The element a model artifact structurally cannot supply. Marking it
// populated would say a model bill of materials alone satisfies the CRA's
// dependency requirement, which it does not.
func TestBSIDependenciesAreOutOfScopeWithTheReasonGiven(t *testing.T) {
	r, err := Assess(BSI, bsiArtifact())
	if err != nil {
		t.Fatal(err)
	}
	el := elementNamed(t, r, "Dependencies on other components")
	if el.Status != OutOfScope {
		t.Fatalf("status %s: recursive resolution to the delivery scope is a build-time fact", el.Status)
	}
	if !strings.Contains(el.Note, "delivery item") {
		t.Errorf("the note should say what to merge with, got %q", el.Note)
	}
	// The artifact's own set is still described, or the row is useless.
	if !strings.Contains(el.Note, "complete") {
		t.Errorf("the note should state whether the artifact's own set is complete, got %q", el.Note)
	}
}

// §5.2.2 asks for a contact, not a name. An organization string identifies the
// publisher perfectly well and is not an email address or a URL.
func TestBSICreatorNeedsAContactNotAName(t *testing.T) {
	a := bsiArtifact()
	a.Identity.Organization = "example-org"
	a.Identity.Author = ""
	a.Identity.RepoURL = ""
	a.Identity.URL = ""

	r, _ := Assess(BSI, a)
	if el := elementNamed(t, r, "Component creator"); el.Status != Absent {
		t.Fatalf("a bare organization name is not a contact; got %s (%q)", el.Status, el.Value)
	}

	a.Identity.Author = "maintainers@example.org"
	r, _ = Assess(BSI, a)
	if el := elementNamed(t, r, "Component creator"); el.Status != Populated {
		t.Fatal("an email address populates the element")
	}
}

// The three properties BSI requires are determinations, not disclosures, and
// they must match what the emitted document says. A coverage report claiming
// an element the document does not carry is a claim with nothing behind it.
func TestBSIComponentPropertiesAreAlwaysDetermined(t *testing.T) {
	r, err := Assess(BSI, bsiArtifact())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Executable property", "Archive property", "Structured property"} {
		el := elementNamed(t, r, name)
		if el.Status != Populated || el.Value == "" {
			t.Errorf("%s must always be determined, got %s %q", name, el.Status, el.Value)
		}
	}
}

// safetensors has no load-time code path, which is the reason it exists. GGUF
// carrying a chat template does, because a loader renders it through a
// template engine.
func TestExecutablePropertyDistinguishesTheFormats(t *testing.T) {
	safe := bsiArtifact()
	if got := safe.ExecutableProperty(); got != model.BSINonExecutable {
		t.Errorf("safetensors has no load-time code path, got %q", got)
	}

	gguf := &model.Artifact{
		Format: model.FormatGGUF,
		Raw:    map[string]string{"tokenizer.chat_template": "{% if x %}"},
		Files:  []model.FileComponent{{Path: "m.gguf", Role: model.RolePrimary}},
	}
	if got := gguf.ExecutableProperty(); got != model.BSIExecutable {
		t.Errorf("a GGUF carrying a chat template is executable by §3.2.6, got %q", got)
	}

	onnx := &model.Artifact{
		Format:  model.FormatONNX,
		Runtime: model.Runtime{CustomDomains: []string{"com.example.ops"}},
		Files:   []model.FileComponent{{Path: "m.onnx", Role: model.RolePrimary}},
	}
	if got := onnx.ExecutableProperty(); got != model.BSIExecutable {
		t.Errorf("an ONNX graph naming a custom domain resolves native kernels, got %q", got)
	}

	// A GGUF with no template is not executable. The property describes the
	// file in front of you, not the worst file its format permits.
	plain := &model.Artifact{Format: model.FormatGGUF,
		Files: []model.FileComponent{{Path: "m.gguf", Role: model.RolePrimary}}}
	if got := plain.ExecutableProperty(); got != model.BSINonExecutable {
		t.Errorf("a GGUF with no chat template is not executable, got %q", got)
	}
}

// Shards and external tensor data carry no metadata of their own. The
// guideline's structured/unstructured distinction is exactly this one.
func TestShardsAreUnstructuredExceptSafetensors(t *testing.T) {
	gguf := &model.Artifact{Format: model.FormatGGUF}
	shard := model.FileComponent{Path: "m-00002-of-00002.gguf", Role: model.RoleShard}
	if got := gguf.FileStructuredProperty(shard); got != model.BSIUnstructured {
		t.Errorf("a GGUF split shard is raw tensor bytes, got %q", got)
	}

	st := &model.Artifact{Format: model.FormatSafetensors}
	stShard := model.FileComponent{Path: "model-00002-of-00002.safetensors", Role: model.RoleShard}
	if got := st.FileStructuredProperty(stShard); got != model.BSIStructured {
		t.Errorf("a safetensors shard carries its own header, got %q", got)
	}
}

func bsiArtifact() *model.Artifact {
	return &model.Artifact{
		Format: model.FormatSafetensors,
		Identity: model.Identity{
			Name: "golden", Version: "1.0", Author: "maintainers@example.org",
			RepoURL: "https://huggingface.co/example-org/golden",
		},
		Licenses: []model.License{{Raw: "apache-2.0", SPDXID: "Apache-2.0"}},
		Files: []model.FileComponent{{
			Path: "model.safetensors", Role: model.RolePrimary,
			SHA256: "aa", SHA384: "bb", SHA512: "cc",
		}},
	}
}

func elementNamed(t *testing.T, r *Report, name string) Element {
	t.Helper()
	for _, el := range r.Elements {
		if el.Name == name {
			return el
		}
	}
	t.Fatalf("no element named %q", name)
	return Element{}
}
