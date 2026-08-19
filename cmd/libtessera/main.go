// Command libtessera builds Tessera as a C shared library, so runtimes that
// cannot import a Go package can still embed the analyser in-process rather
// than shelling out to a binary or standing up a sidecar.
//
// Build:
//
//	go build -buildmode=c-shared -o libtessera.so  ./cmd/libtessera   # Linux
//	go build -buildmode=c-shared -o libtessera.dylib ./cmd/libtessera # macOS
//	go build -buildmode=c-shared -o tessera.dll    ./cmd/libtessera   # Windows
//
// which also writes libtessera.h next to the library. The surface is three
// functions and one rule:
//
//	char *tessera_analyze(const char *path, const char *format);
//	char *tessera_version(void);
//	void  tessera_free(char *s);
//
// Every char* returned by this library is allocated by C and owned by the
// caller, who must release it with tessera_free. Nothing else is shared across
// the boundary, so there is no handle to track and no lifetime to reason about
// beyond that one rule.
//
// format selects the representation: "json" for the full analysis (the default
// when NULL or empty), "cyclonedx" for a CycloneDX 1.6 ML-BOM, "spdx" for an
// SPDX 3.0.1 document.
//
// Errors are returned in-band as a JSON object with an "error" key rather than
// through a status code, because a single owned string is the simplest contract
// to bind against from Python, Rust, Java, C# or Node. Callers should check for
// that key. The library never writes to stdout or stderr and never exits the
// host process.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"time"
	"unsafe"

	tessera "github.com/DAVANO-INNOVATION-LAB/tessera"
)

// version is stamped by the linker: -ldflags "-X main.version=v0.1.0".
var version = "dev"

// The library version is published once, at load time. Assigning it per call
// would be a data race between concurrent callers, which is the normal way a
// shared library gets used.
func init() { tessera.Version = version }

//export tessera_analyze
func tessera_analyze(cPath, cFormat *C.char) (out *C.char) {
	// A Go panic that crosses the C boundary aborts the host process with no
	// usable diagnostic, which from Python or Java is an unattributable crash.
	// Convert it into the same owned error string every other failure returns.
	defer func() {
		if r := recover(); r != nil {
			out = errorJSON("internal parser fault")
		}
	}()

	path := C.GoString(cPath)
	format := C.GoString(cFormat)
	if format == "" {
		format = "json"
	}

	art, err := tessera.Analyze(context.Background(), path)
	if err != nil {
		return errorJSON(err.Error())
	}

	// The clock is read here rather than taken from the caller because the C
	// boundary has no good timestamp type. A caller that needs reproducible
	// output should use the Go API or the CLI's --reproducible flag.
	now := time.Now()

	var doc []byte
	switch format {
	case "json":
		doc, err = json.Marshal(art)
	case "cyclonedx", "cdx":
		doc, err = tessera.CycloneDX(art, now)
	case "spdx":
		doc, err = tessera.SPDX(art, now)
	default:
		return errorJSON("unknown format " + format + " (want json, cyclonedx or spdx)")
	}
	if err != nil {
		return errorJSON(err.Error())
	}
	return C.CString(string(doc))
}

//export tessera_version
func tessera_version() *C.char {
	return C.CString(version)
}

//export tessera_free
func tessera_free(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

// errorJSON renders a failure as the same kind of owned string as a success,
// so a binding has exactly one return path and one free to perform.
func errorJSON(msg string) *C.char {
	b, err := json.Marshal(map[string]string{"error": msg})
	if err != nil {
		return C.CString(`{"error":"internal error"}`)
	}
	return C.CString(string(b))
}

func main() {}
