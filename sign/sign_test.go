package sign_test

import (
	"testing"
	"time"

	sign "github.com/DAVANO-INNOVATION-LAB/tessera/sign"
)

// An external test package, importing the module the way a consumer would.
// The implementation is internal/, so this is the only thing that proves the
// public surface is actually usable from outside — the same check tessera runs
// on its own root package.
func TestPublicSurfaceIsUsableFromOutside(t *testing.T) {
	kp, err := sign.Generate(sign.SuiteHybridMLDSA87)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	doc := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)

	b, err := sign.Sign(kp, doc, time.Unix(1_760_000_000, 0).UTC())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub, err := sign.MarshalPublic(kp)
	if err != nil {
		t.Fatal(err)
	}
	pq, ec, err := sign.ParsePublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := sign.Verify(b, doc, pq, ec); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// A changed document must fail. This is the property everything else rests
	// on, so it is asserted here rather than assumed from the internal tests.
	if err := sign.Verify(b, append(doc, ' '), pq, ec); err == nil {
		t.Error("a modified document verified")
	}
}
