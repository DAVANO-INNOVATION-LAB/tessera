package fetch_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	fetch "github.com/DAVANO-INNOVATION-LAB/tessera/fetch"
)

// An external test package, importing the module the way a consumer would. The
// implementation is internal/, so this is the only thing that proves the public
// surface is reachable from outside.
func TestPublicSurfaceIsUsableFromOutside(t *testing.T) {
	// A PVC URI names a claim the orchestrator has mounted, so the test builds
	// that shape: mountRoot/<claim>/<path>.
	mount := t.TempDir()
	src := filepath.Join(mount, "model-store", "fraud", "v1")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "model.safetensors"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &fetch.Registry{}
	r.Register(&fetch.PVCResolver{MountRoot: mount})

	dest := t.TempDir()
	art, err := r.Resolve(context.Background(), "pvc://model-store/fraud/v1", dest)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if art.LocalPath == "" {
		t.Error("a staged artifact has no local path")
	}
	if art.Coverage != nil {
		t.Error("a whole-artifact fetch reported partial coverage")
	}
}

// A URI with no scheme has to be an error. Guessing a default would silently
// send a local path to a network resolver, or the reverse.
func TestSchemelessURIIsRejected(t *testing.T) {
	for _, uri := range []string{"", "/models/llama", "model.gguf", "./relative"} {
		if _, err := fetch.SchemeOf(uri); err == nil {
			t.Errorf("SchemeOf(%q) succeeded; a missing scheme must not be guessed", uri)
		}
	}
}

// An unregistered scheme must fail rather than fall through to some default.
// A registry built without the network resolvers is how an air-gapped
// deployment proves it cannot reach out, and that only holds if an unknown
// scheme is refused.
func TestUnregisteredSchemeIsRefused(t *testing.T) {
	r := &fetch.Registry{}
	r.Register(&fetch.PVCResolver{})
	if _, err := r.Resolve(context.Background(), "https://example.com/model", t.TempDir()); err == nil {
		t.Error("a registry without the HTTP resolver still fetched an https URI")
	}
}

func TestExecutableFormatsAreDistinguished(t *testing.T) {
	for _, name := range []string{"model.pkl", "weights.pt", "model.pth", "net.h5"} {
		if !fetch.CanExecuteCode(name) {
			t.Errorf("%s should be flagged as able to execute on load", name)
		}
	}
	for _, name := range []string{"model.safetensors", "model.gguf"} {
		if fetch.CanExecuteCode(name) {
			t.Errorf("%s cannot carry code; flagging it inflates the risk of every scan", name)
		}
	}
}
