package sigstore_test

import (
	"os"
	"path/filepath"
	"testing"

	sigstore "github.com/DAVANO-INNOVATION-LAB/tessera/sigstore"
)

// An external test package, importing the module the way a consumer would. The
// implementation is internal/, so this is the only thing proving the public
// surface is reachable at all.
func TestPublicSurfaceIsUsableFromOutside(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "model.pkl"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	inv, err := sigstore.Discover(ws)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if inv == nil {
		t.Fatal("Discover returned no inventory")
	}

	if got := sigstore.ExecutableFormat("model.pkl"); got == "" {
		t.Error("a pickle is an executable format; an unsigned one is a different risk from an unsigned safetensors")
	}
	if got := sigstore.ExecutableFormat("model.safetensors"); got != "" {
		t.Errorf("safetensors reported as executable (%q); it cannot carry code", got)
	}
}

// A policy that cannot be made usable must fail loudly. A verifier that quietly
// reports every artifact as unsigned looks identical to a working one examining
// unsigned artifacts, and those mean opposite things.
func TestUnusablePolicyIsAnErrorNotASilentPass(t *testing.T) {
	_, err := sigstore.NewVerifier(sigstore.Policy{
		TrustRootPath: filepath.Join(t.TempDir(), "does-not-exist.json"),
		Publishers:    []sigstore.Publisher{{}},
	})
	if err == nil {
		t.Error("a policy naming a missing trust root produced a working verifier")
	}
}
