package tessera

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The caller's limits must actually reach the walk. An earlier adapter accepted
// a Limits value and passed none of it through, so every caller silently got
// the defaults — the failure mode that looks identical to working.
func TestInspectLimitedHonoursTheFileCap(t *testing.T) {
	dir := t.TempDir()
	for i := range 40 {
		name := filepath.Join(dir, string(rune('a'+i%26))+string(rune('a'+i/26))+".bin")
		if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	limits := InspectLimits()
	limits.MaxFiles = 5
	tight, err := InspectLimited(context.Background(), dir, limits)
	if err != nil {
		t.Fatal(err)
	}
	loose, err := Inspect(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	if tight.FilesScanned > 5 {
		t.Errorf("scanned %d files under a cap of 5; the limit was ignored", tight.FilesScanned)
	}
	if tight.FilesScanned >= loose.FilesScanned {
		t.Errorf("capped walk scanned %d, uncapped scanned %d; the cap had no effect",
			tight.FilesScanned, loose.FilesScanned)
	}
	if !tight.Truncated {
		t.Error("a walk stopped by its file cap must report Truncated; " +
			"otherwise a partial result reads as a clean one")
	}
}
