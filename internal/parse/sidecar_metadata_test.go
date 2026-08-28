package parse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// An archive rolled up on macOS carries an AppleDouble stub for every file, and
// the "._" prefix sorts before every ordinary name. A scan that takes the first
// match therefore describes a couple of hundred bytes of resource fork: wrong
// name in the bill of materials, wrong bytes pinned, model never examined.
func TestFilesystemBookkeepingIsRecognised(t *testing.T) {
	for _, name := range []string{
		"._model.safetensors", "._config.json", ".DS_Store", "Thumbs.db",
		"desktop.ini", "/staged/models/m/._model.gguf",
	} {
		if !FilesystemBookkeeping(name) {
			t.Errorf("%q is filesystem metadata and was not recognised", name)
		}
	}
}

// Content must never be mistaken for bookkeeping.
func TestContentIsNotMistakenForBookkeeping(t *testing.T) {
	for _, name := range []string{
		"model.safetensors", "config.json", "model.gguf", ".gitattributes",
		"_model.safetensors", ".hidden-but-real.onnx", "tokenizer.model",
	} {
		if FilesystemBookkeeping(name) {
			t.Errorf("%q is content and was skipped as metadata", name)
		}
	}
}

func TestArchiverDirectoriesAreRecognised(t *testing.T) {
	if !InBookkeepingDir("__MACOSX/model.safetensors") {
		t.Error("__MACOSX was not recognised")
	}
	if InBookkeepingDir("models/__MACOSX_backup/model.safetensors") {
		t.Error("a directory merely containing the substring was treated as bookkeeping")
	}
}

// A single tokenizer.pkl beside safetensors weights must read as one pickle,
// not two. The AppleDouble stub carries the same extension, so counting it
// overstates what is in the directory — in a finding whose whole job is to say
// how many executable files sit next to the weights.
func TestAPeerCountIgnoresResourceForks(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"model.safetensors", "tokenizer.pkl", "._tokenizer.pkl", "._model.safetensors"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	a := &model.Artifact{}
	notePeerWeightFiles(a, dir, filepath.Join(dir, "model.safetensors"))

	peers := a.Raw["peer.executable_weights"]
	if strings.Contains(peers, "._") {
		t.Errorf("a resource fork was counted as an executable weight file: %q", peers)
	}
	if peers != "tokenizer.pkl" {
		t.Errorf("peers = %q, want just the one real pickle", peers)
	}
}
