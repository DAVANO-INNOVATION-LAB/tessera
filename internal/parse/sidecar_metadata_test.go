package parse

import "testing"

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
