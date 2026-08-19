package parse

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// A model card is the only place a safetensors model discloses its licence.
// Without reading it, TESS-LIC-001 fires on most of the Hugging Face Hub and
// the bill of materials ships with an empty licence element.
func TestModelCardLicenseIsRead(t *testing.T) {
	dir := t.TempDir()
	card := "---\nlanguage: en\ntags:\n- exbert\nlicense: apache-2.0\ndatasets:\n- wikipedia\n---\n\n# Model\n"
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(card), 0o644); err != nil {
		t.Fatal(err)
	}

	var a model.Artifact
	readModelCard(&a, dir)

	if len(a.Licenses) != 1 || a.Licenses[0].Raw != "apache-2.0" {
		t.Fatalf("the card licence should be recorded, got %+v", a.Licenses)
	}
}

func TestModelCardBaseModelIsRead(t *testing.T) {
	dir := t.TempDir()
	card := "---\nbase_model: meta-llama/Llama-3-8B\nlicense: mit\n---\n"
	os.WriteFile(filepath.Join(dir, "README.md"), []byte(card), 0o644)

	var a model.Artifact
	readModelCard(&a, dir)

	if a.Declared.BaseModel != "meta-llama/Llama-3-8B" {
		t.Fatalf("declared parent should survive, got %q", a.Declared.BaseModel)
	}
}

// A measurement must never be displaced by a claim; the card is read last for
// exactly that reason.
func TestModelCardDoesNotOverwriteConfig(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "README.md"),
		[]byte("---\nbase_model: from-card\n---\n"), 0o644)

	a := model.Artifact{}
	a.Declared.BaseModel = "from-config"
	readModelCard(&a, dir)

	if a.Declared.BaseModel != "from-config" {
		t.Fatal("a card claim must not overwrite one already read from config")
	}
}

func TestFrontmatterHandlesListsAndNesting(t *testing.T) {
	got := parseFrontmatter("---\nlicense: mit\ntags:\n- a\n- b\nmodel-index:\n  name: x\n  results: y\npipeline_tag: text-generation\n---\n")

	if got["license"] != "mit" {
		t.Errorf("scalar not read: %q", got["license"])
	}
	if got["tags"] != "a,b" {
		t.Errorf("list should join: %q", got["tags"])
	}
	if got["pipeline_tag"] != "text-generation" {
		t.Errorf("a key after a nested block was lost: %q", got["pipeline_tag"])
	}
	// Nested keys are skipped rather than promoted to the top level, or
	// "name" from model-index would masquerade as a model-level field.
	if _, ok := got["name"]; ok {
		t.Error("a nested key must not be lifted to the top level")
	}
}

func TestNoFrontmatterIsNotAnError(t *testing.T) {
	if got := parseFrontmatter("# Just a heading\n\nSome prose.\n"); len(got) != 0 {
		t.Fatalf("a card with no frontmatter yields nothing, got %v", got)
	}
	if got := parseFrontmatter("---\nunterminated: true\n"); len(got) != 0 {
		t.Fatal("an unterminated block must not be parsed")
	}
}
