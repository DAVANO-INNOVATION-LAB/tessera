package parse

import (
	"path/filepath"
	"strings"
)

// FilesystemBookkeeping reports whether a name is metadata a filesystem wrote
// beside the content, rather than content.
//
// These arrive constantly and invisibly. Any archive rolled up on macOS carries
// an AppleDouble stub for every file — a couple of hundred bytes holding a
// resource fork — named with a "._" prefix. That prefix sorts before every
// ordinary name, so a directory staged from such an archive offers
// "._model.safetensors" ahead of "model.safetensors", and a scan that takes the
// first match describes the stub: wrong name in the bill of materials, wrong
// bytes pinned, and a model nobody actually looked at.
//
// Skipping them is not a heuristic. The prefix is a reserved convention, and a
// resource fork cannot be a model.
func FilesystemBookkeeping(name string) bool {
	base := filepath.Base(name)
	switch base {
	case ".DS_Store", "Thumbs.db", "desktop.ini":
		return true
	}
	// AppleDouble: "._" plus the name of the file it shadows.
	return strings.HasPrefix(base, "._")
}

// InBookkeepingDir reports whether a path sits inside a directory a filesystem
// or archiver created for its own purposes.
func InBookkeepingDir(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == "__MACOSX" {
			return true
		}
	}
	return false
}
