package tessera_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tessera "github.com/DAVANO-INNOVATION-LAB/tessera"
)

// These tests are written from outside the package, as an importer sees it.
// If the public surface stops being usable from the outside, they stop
// compiling — which is the point.

func writeSafetensors(t *testing.T, dir string, meta map[string]string) string {
	t.Helper()
	header := map[string]any{
		"__metadata__": meta,
		"w":            map[string]any{"dtype": "F16", "shape": []int{2, 2}, "data_offsets": []int{0, 8}},
	}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(len(hb)))
	out := append(buf, hb...)
	out = append(out, make([]byte, 8)...)

	p := filepath.Join(dir, "model.safetensors")
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAnalyzeAndEmitFromOutside(t *testing.T) {
	path := writeSafetensors(t, t.TempDir(), map[string]string{"format": "pt", "license": "mit"})

	art, err := tessera.Analyze(context.Background(), path)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if art.Format != tessera.FormatSafetensors {
		t.Errorf("format = %q", art.Format)
	}
	if len(art.Files) != 1 || art.Files[0].SHA256 == "" {
		t.Fatalf("expected one hashed file, got %+v", art.Files)
	}
	if art.Files[0].Role != tessera.RolePrimary {
		t.Errorf("role = %q", art.Files[0].Role)
	}
	// The licence should have resolved through to an SPDX identifier.
	if len(art.Licenses) != 1 || art.Licenses[0].SPDXID != "MIT" {
		t.Errorf("licenses = %+v", art.Licenses)
	}

	at := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	cdx, err := tessera.CycloneDX(art, at)
	if err != nil {
		t.Fatalf("CycloneDX: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(cdx, &doc); err != nil {
		t.Fatalf("CycloneDX output invalid: %v", err)
	}
	if doc["specVersion"] != "1.6" {
		t.Errorf("specVersion = %v", doc["specVersion"])
	}

	spdx, err := tessera.SPDX(art, at)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	if err := json.Unmarshal(spdx, &doc); err != nil {
		t.Fatalf("SPDX output invalid: %v", err)
	}
}

func TestOptionsSkipHashing(t *testing.T) {
	path := writeSafetensors(t, t.TempDir(), map[string]string{"format": "pt"})

	art, err := tessera.Analyze(context.Background(), path, tessera.WithoutHashing())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if art.Files[0].SHA256 != "" {
		t.Errorf("WithoutHashing still hashed the file")
	}
	if art.Files[0].Size == 0 {
		t.Errorf("size should still be recorded without hashing")
	}
}

func TestContextCancellationIsHonoured(t *testing.T) {
	path := writeSafetensors(t, t.TempDir(), map[string]string{"format": "pt"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tessera.Analyze(ctx, path); err == nil {
		t.Fatalf("expected a cancelled context to stop the analysis")
	}
}

func TestUnrecognizedFormatIsAnError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "notes.txt")
	os.WriteFile(p, []byte("hello"), 0o644)
	if _, err := tessera.Analyze(context.Background(), p); err == nil {
		t.Errorf("expected an error for a non-model file")
	}
}

func TestWorstAndSeverity(t *testing.T) {
	f := []tessera.Finding{
		{Severity: tessera.SeverityLow},
		{Severity: tessera.SeverityCritical},
		{Severity: tessera.SeverityMedium},
	}
	if got := tessera.Worst(f); got != tessera.SeverityCritical {
		t.Errorf("Worst = %q", got)
	}
	if tessera.Worst(nil) != "" {
		t.Errorf("Worst of nothing should be empty")
	}
	if tessera.Severity(tessera.SeverityCritical) >= tessera.Severity(tessera.SeverityHigh) {
		t.Errorf("severity ordering is wrong")
	}
}

// --- the embedding guarantees ---
//
// An importer inherits this package's dependencies, its network reach, and its
// output behaviour. Each of those is promised in the package doc, so each gets
// a test that fails when the promise breaks.

func TestNoThirdPartyDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.HasPrefix(dep, "github.com/DAVANO-INNOVATION-LAB/tessera") {
			continue
		}
		// A standard-library import path has no dot in its first segment.
		first, _, _ := strings.Cut(dep, "/")
		if strings.Contains(first, ".") {
			t.Errorf("third-party dependency introduced: %s\n"+
				"this package is imported by other services; its dependency tree must stay empty", dep)
		}
	}
}

func TestNoNetworkInDependencyTree(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if dep == "net" || dep == "net/http" || strings.HasPrefix(dep, "net/http/") {
			t.Errorf("%s entered the dependency tree; analysis must not be able to reach the network", dep)
		}
	}
}

func TestAnalysisWritesNothingToStdoutOrStderr(t *testing.T) {
	path := writeSafetensors(t, t.TempDir(), map[string]string{"format": "pt"})

	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW

	_, err := tessera.Analyze(context.Background(), path)

	os.Stdout, os.Stderr = origOut, origErr
	outW.Close()
	errW.Close()
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	var buf [1]byte
	if n, _ := outR.Read(buf[:]); n > 0 {
		t.Errorf("Analyze wrote to stdout; the caller owns all output")
	}
	if n, _ := errR.Read(buf[:]); n > 0 {
		t.Errorf("Analyze wrote to stderr; the caller owns all output")
	}
}
