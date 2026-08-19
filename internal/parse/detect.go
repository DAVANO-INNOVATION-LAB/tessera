package parse

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// ggufMagic is "GGUF" as it sits on disk.
var ggufMagic = []byte{'G', 'G', 'U', 'F'}

// Detect identifies the model format of a file by content first, extension
// second. Content wins because an attacker renames files, and because ONNX has
// no magic bytes and can only be reached by extension in the first place.
//
// Detection is deliberately conservative: it returns ("", false) rather than
// guessing, so an unrecognized file is skipped, never mis-parsed.
func Detect(path string) (model.Format, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	head := make([]byte, 8)
	n, _ := f.Read(head)
	head = head[:n]

	switch {
	case bytes.HasPrefix(head, ggufMagic):
		return model.FormatGGUF, true
	case looksLikeSafetensors(head):
		// The safetensors "magic" is only an 8-byte little-endian header length,
		// which is ambiguous, so confirm with the extension.
		if hasExt(path, ".safetensors") {
			return model.FormatSafetensors, true
		}
	}

	// ONNX is protobuf with no magic. Fall back to extension.
	switch {
	case hasExt(path, ".onnx"):
		return model.FormatONNX, true
	case hasExt(path, ".safetensors"):
		return model.FormatSafetensors, true
	case hasExt(path, ".gguf"), hasExt(path, ".ggml"):
		// Extension says GGUF but the magic did not match — parse it anyway so
		// the GGUF parser can report the malformed magic as a finding rather
		// than the file being silently skipped.
		return model.FormatGGUF, true
	}
	return "", false
}

// looksLikeSafetensors is a weak signal: the first 8 bytes are a header length
// that must be positive and smaller than a sane cap.
func looksLikeSafetensors(head []byte) bool {
	if len(head) < 8 {
		return false
	}
	var n uint64
	for i := 0; i < 8; i++ {
		n |= uint64(head[i]) << (8 * i)
	}
	return n > 0 && n < (100<<20)
}

func hasExt(path, ext string) bool {
	return strings.EqualFold(filepath.Ext(path), ext)
}
