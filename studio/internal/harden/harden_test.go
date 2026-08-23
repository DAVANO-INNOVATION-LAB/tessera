package harden

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/tessera"
)

func art(fs ...tessera.Finding) *tessera.Artifact {
	return &tessera.Artifact{Findings: fs}
}

// The most important behaviour in the package: it will not unpickle to convert,
// and it says why rather than quietly omitting the option.
func TestPickleConversionIsRefusedWithAReason(t *testing.T) {
	p := PlanFor("/m", art(tessera.Finding{ID: "TESS-PICKLE-003", Location: "w.pkl"}))
	if len(p.Refusals) != 1 {
		t.Fatalf("expected a refusal, got %d", len(p.Refusals))
	}
	if !contains(p.Refusals[0].Why, "unpickling") {
		t.Errorf("the refusal does not explain the danger: %q", p.Refusals[0].Why)
	}
	for _, a := range p.Actions {
		if a.Kind != KindRefused && a.Path == "w.pkl" {
			t.Error("a pickle conversion was proposed as an applicable action")
		}
	}
}

// Editing a description to match the bytes would hide a disagreement rather
// than resolve it, and the disagreement is the finding.
func TestDriftIsRefusedRatherThanPapredOver(t *testing.T) {
	p := PlanFor("/m", art(tessera.Finding{ID: "TESS-DRIFT-002", Location: "config.json"}))
	if len(p.Refusals) != 1 || len(p.Actions) != 0 {
		t.Errorf("drift produced %d actions and %d refusals; want 0 and 1", len(p.Actions), len(p.Refusals))
	}
}

// The original must survive. A security tool that damages what it was pointed
// at does not get pointed at anything twice.
func TestOriginalIsNeverModified(t *testing.T) {
	src := t.TempDir()
	write(t, src, "model.gguf", "weights")
	write(t, src, "evil.pkl", "payload")

	dest := filepath.Join(t.TempDir(), "hardened")
	plan := PlanFor(src, art(tessera.Finding{ID: "TESS-PICKLE-001", Location: "evil.pkl"}))
	if _, err := Apply(src, dest, plan, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(src, "evil.pkl")); err != nil {
		t.Error("the original pickle was removed; hardening must write a copy")
	}
	if _, err := os.Stat(filepath.Join(dest, "evil.pkl")); !os.IsNotExist(err) {
		t.Error("the copy still has the pickle")
	}
	if _, err := os.Stat(filepath.Join(dest, "model.gguf")); err != nil {
		t.Error("the copy is missing the weights")
	}
}

func TestApplyRefusesDangerousDestinations(t *testing.T) {
	src := t.TempDir()
	write(t, src, "a", "x")

	if _, err := Apply(src, src, Plan{}, nil); err == nil {
		t.Error("hardening in place was allowed")
	}
	if _, err := Apply(src, filepath.Join(src, "inner"), Plan{}, nil); err == nil {
		t.Error("a destination inside the source was allowed")
	}
	occupied := t.TempDir()
	write(t, occupied, "existing", "data")
	if _, err := Apply(src, occupied, Plan{}, nil); err == nil {
		t.Error("writing over a non-empty tree was allowed")
	}
}

// trust_remote_code is set false rather than deleted: a loader that finds the
// key missing may apply its own default, which is not necessarily the safe one.
func TestTrustRemoteCodeIsSetFalseNotRemoved(t *testing.T) {
	src := t.TempDir()
	write(t, src, "config.json", `{"trust_remote_code": true, "auto_map": {"a":"b"}, "keep": 1}`)

	dest := filepath.Join(t.TempDir(), "out")
	plan := PlanFor(src, art(
		tessera.Finding{ID: "TESS-HF-001", Location: "config.json"},
		tessera.Finding{ID: "TESS-HF-002", Location: "config.json"},
	))
	if _, err := Apply(src, dest, plan, nil); err != nil {
		t.Fatal(err)
	}

	var cfg map[string]any
	data, err := os.ReadFile(filepath.Join(dest, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if v, ok := cfg["trust_remote_code"]; !ok {
		t.Error("trust_remote_code was removed; a loader may then apply its own default")
	} else if v != false {
		t.Errorf("trust_remote_code = %v, want false", v)
	}
	if _, ok := cfg["auto_map"]; ok {
		t.Error("auto_map was not removed")
	}
	if cfg["keep"] == nil {
		t.Error("an unrelated config key was lost")
	}
}

// Finding locations come from parsed files — attacker-influenced text that has
// no business escaping the destination.
func TestActionPathsCannotEscape(t *testing.T) {
	src := t.TempDir()
	write(t, src, "model.gguf", "w")
	outside := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(outside, []byte("do not touch"), 0o644)

	dest := filepath.Join(t.TempDir(), "out")
	plan := Plan{Actions: []Action{{
		Kind: KindRemoveFile, Path: "../../../" + filepath.Base(outside), Selected: true}}}

	if _, err := Apply(src, dest, plan, nil); err == nil {
		t.Error("an escaping action path was applied")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Error("a file outside the destination was removed")
	}
}

// A symlink faithfully reproduced would carry the problem across, and leaving
// it behind is the point.
func TestSymlinksAreNotCarriedIntoTheCopy(t *testing.T) {
	src := t.TempDir()
	write(t, src, "model.gguf", "w")
	if err := os.Symlink("/etc/passwd", filepath.Join(src, "sneaky")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	if _, err := Apply(src, dest, Plan{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "sneaky")); !os.IsNotExist(err) {
		t.Error("a symlink was copied into the hardened tree")
	}
}

func TestExecutableBitIsDroppedOnCopy(t *testing.T) {
	src := t.TempDir()
	p := filepath.Join(src, "run.sh")
	os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755)

	dest := filepath.Join(t.TempDir(), "out")
	if _, err := Apply(src, dest, Plan{}, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dest, "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 != 0 {
		t.Errorf("mode %04o carried the executable bit across", info.Mode().Perm())
	}
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (len(sub) == 0 || indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
