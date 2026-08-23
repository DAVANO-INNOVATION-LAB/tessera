// Package harden proposes and applies safe remediation to a model artifact.
//
// The obvious feature here is dangerous, and refusing it is the most important
// thing this package does.
//
// "Convert the pickle to safetensors" is the single highest-value hardening
// anyone could offer, and it is unimplementable safely: converting a pickle
// means unpickling it, and unpickling is exactly the code execution the finding
// warns about. A button that did it would run the attacker's payload on the
// machine of the person trying to defend against it. So this package will not,
// and says so where a user can read it rather than silently omitting the option.
//
// What it does instead is everything that needs no interpreter, no framework
// and no model load:
//
//   - remove executable files sitting beside the weights
//   - turn off trust_remote_code and strip auto_map from a JSON config
//   - remove symlinks that leave the artifact directory
//
// Three rules govern all of it.
//
// **The original is never modified.** Hardening writes a copy. An operator who
// disagrees with a change, or discovers the model no longer loads, still has the
// artifact they started with — and a security tool that damages the thing it was
// pointed at will not be pointed at anything twice.
//
// **Nothing is applied without being shown first.** Plan and Apply are separate
// calls, and the plan says precisely which files are affected.
//
// **The result is re-scanned, not assumed.** Applying a plan proves nothing; the
// findings on the copy are what proves it, and those are returned.
package harden

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DAVANO-INNOVATION-LAB/tessera"
)

// Kind names what an action does.
type Kind string

const (
	// KindRemoveFile deletes a file from the copy.
	KindRemoveFile Kind = "remove-file"
	// KindConfigFlag rewrites a boolean in a JSON config.
	KindConfigFlag Kind = "config-flag"
	// KindConfigKey removes a key from a JSON config.
	KindConfigKey Kind = "config-key"
	// KindRemoveLink removes a symlink.
	KindRemoveLink Kind = "remove-link"
	// KindRefused is an action this package will not perform, carried in the
	// plan so the reason is visible rather than the option merely missing.
	KindRefused Kind = "refused"
)

// Action is one proposed change.
type Action struct {
	Kind Kind `json:"kind"`
	// Path is relative to the artifact directory.
	Path string `json:"path"`
	// Key names the config field, for the config kinds.
	Key string `json:"key,omitempty"`
	// Finding is the identifier this action answers.
	Finding string `json:"finding,omitempty"`
	// Why explains the change in a sentence somebody can act on.
	Why string `json:"why"`
	// Consequence states what may break. Hardening is not free, and a plan
	// that omitted the cost would be talking somebody into a change they did
	// not understand.
	Consequence string `json:"consequence,omitempty"`
	// Selected marks whether the action will be applied. Everything defaults
	// to selected except refusals, which cannot be.
	Selected bool `json:"selected"`
}

// Plan is what would be done.
type Plan struct {
	Source  string   `json:"source"`
	Actions []Action `json:"actions"`
	// Refusals are carried separately as well, so an interface can show them
	// without a user having to notice a kind field.
	Refusals []Action `json:"refusals,omitempty"`
}

// Result is what was done, and what the copy scans as afterwards.
type Result struct {
	Destination string   `json:"destination"`
	Applied     []Action `json:"applied"`
	// Before and After are finding counts, so the interface can state the
	// change rather than implying it.
	Before int `json:"before"`
	After  int `json:"after"`
	// Remaining are the findings the hardened copy still has. Returned rather
	// than summarised, because "it worked" is a claim and these are evidence.
	Remaining []tessera.Finding `json:"remaining"`
	Verdict   string            `json:"verdict,omitempty"`
	// Provenance is the record written into the copy, returned so an interface
	// can show the derivation without reading the file back.
	Provenance *Provenance `json:"provenance,omitempty"`
}

// PlanFor proposes actions for an analysed artifact.
//
// Every action traces to a finding. Hardening that is not answering a specific
// finding is somebody's taste being applied to another person's model.
func PlanFor(dir string, art *tessera.Artifact) Plan {
	p := Plan{Source: dir}
	seen := map[string]bool{}

	add := func(a Action) {
		key := string(a.Kind) + "\x00" + a.Path + "\x00" + a.Key
		if seen[key] {
			return
		}
		seen[key] = true
		if a.Kind == KindRefused {
			p.Refusals = append(p.Refusals, a)
			return
		}
		p.Actions = append(p.Actions, a)
	}

	for _, f := range art.Findings {
		switch f.ID {
		// ── Files that execute, sitting beside the weights ───────────────
		case "TESS-PICKLE-001", "TESS-PICKLE-002", "TESS-NPY-001":
			add(Action{
				Kind: KindRemoveFile, Path: f.Location, Finding: f.ID, Selected: true,
				Why: "executes code when loaded",
				Consequence: "the model will not load if a loader expects this file; " +
					"re-export the weights as safetensors instead",
			})
		case "TESS-PY-001", "TESS-PY-002", "TESS-PY-003", "TESS-PY-004", "TESS-PY-005", "TESS-PY-006":
			add(Action{
				Kind: KindRemoveFile, Path: f.Location, Finding: f.ID, Selected: true,
				Why:         "Python shipped with the model, which runs if the loader imports it",
				Consequence: "custom preprocessing in this file will be gone",
			})
		case "TESS-BIN-001", "TESS-BIN-002", "TESS-BIN-003", "TESS-NATIVE-001",
			"TESS-SHELL-001", "TESS-SHELL-002", "TESS-EXEC-001":
			add(Action{
				Kind: KindRemoveFile, Path: f.Location, Finding: f.ID, Selected: true,
				Why:         "an executable has no business inside a model artifact",
				Consequence: "none expected; weights do not need a binary beside them",
			})
		case "TESS-LINK-001", "TESS-FILE-003":
			add(Action{
				Kind: KindRemoveLink, Path: f.Location, Finding: f.ID, Selected: true,
				Why:         "a symlink pointing outside the artifact directory",
				Consequence: "whatever it referenced will not be reachable from the copy",
			})

		// ── Config that causes code to be fetched and run ────────────────
		case "TESS-HF-001":
			add(Action{
				Kind: KindConfigFlag, Path: configPath(f.Location), Key: "trust_remote_code",
				Finding: f.ID, Selected: true,
				Why:         "trust_remote_code runs code shipped with the weights",
				Consequence: "a model that genuinely needs custom code will stop loading — which is the point",
			})
		case "TESS-HF-002":
			add(Action{
				Kind: KindConfigKey, Path: configPath(f.Location), Key: "auto_map",
				Finding: f.ID, Selected: true,
				Why:         "auto_map resolves classes to code shipped with the model",
				Consequence: "the loader will fall back to a built-in architecture, or fail",
			})

		// ── What this package will not do, and why ───────────────────────
		case "TESS-PICKLE-003", "TESS-PICKLE-004":
			add(Action{
				Kind: KindRefused, Path: f.Location, Finding: f.ID,
				Why: "converting a pickle to safetensors requires unpickling it, which is " +
					"exactly the code execution this finding warns about. Re-export from " +
					"the training environment instead, where the weights are already in memory.",
			})
		case "TESS-GGUF-010":
			add(Action{
				Kind: KindRefused, Path: f.Location, Finding: f.ID,
				Why: "the chat template lives inside the GGUF's metadata block. Rewriting it " +
					"means rewriting the model file, and a corrupted GGUF is a worse outcome " +
					"than a template you render in a sandbox. Re-export with a plain template.",
			})
		case "TESS-DRIFT-001", "TESS-DRIFT-002", "TESS-DRIFT-003", "TESS-DRIFT-007":
			add(Action{
				Kind: KindRefused, Path: f.Location, Finding: f.ID,
				Why: "drift means the artifact's description disagrees with its bytes. " +
					"Editing the description to match would hide the disagreement rather " +
					"than resolve it, and the disagreement is the finding.",
			})
		}
	}

	sort.SliceStable(p.Actions, func(i, j int) bool { return p.Actions[i].Path < p.Actions[j].Path })
	return p
}

// configPath resolves which config file a finding refers to, defaulting to the
// conventional name when the finding did not say.
func configPath(loc string) string {
	if loc == "" {
		return "config.json"
	}
	return loc
}

// Apply copies the artifact to dest and performs the selected actions.
//
// The copy happens first and completely. Applying changes while copying would
// leave a partially hardened tree if anything failed, and a partially hardened
// artifact is one nobody can reason about.
func Apply(src, dest string, plan Plan, prov *Provenance) (*Result, error) {
	if dest == "" {
		return nil, fmt.Errorf("hardening needs a destination; the original is never modified")
	}
	abssrc, err := filepath.Abs(src)
	if err != nil {
		return nil, err
	}
	absdest, err := filepath.Abs(dest)
	if err != nil {
		return nil, err
	}
	if abssrc == absdest {
		return nil, fmt.Errorf("destination is the source: hardening writes a copy so the original survives")
	}
	if strings.HasPrefix(absdest, abssrc+string(os.PathSeparator)) {
		return nil, fmt.Errorf("destination is inside the source, which would harden a copy of itself")
	}
	if entries, err := os.ReadDir(absdest); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("destination is not empty; refusing to write over an existing tree")
	}

	if err := copyTree(abssrc, absdest); err != nil {
		return nil, fmt.Errorf("copying the artifact: %w", err)
	}

	res := &Result{Destination: absdest}
	for _, a := range plan.Actions {
		if !a.Selected || a.Kind == KindRefused {
			continue
		}
		if err := apply(absdest, a); err != nil {
			return nil, fmt.Errorf("applying %s to %s: %w", a.Kind, a.Path, err)
		}
		res.Applied = append(res.Applied, a)
	}

	// The derivation is recorded inside the copy, so it stays answerable when
	// the copy is moved somewhere this server cannot see. Written after the
	// actions, and describing the ones that actually succeeded rather than the
	// ones that were proposed.
	if prov != nil {
		prov.Applied = res.Applied
		prov.Refused = plan.Refusals
		if err := WriteProvenance(absdest, *prov); err != nil {
			return nil, fmt.Errorf("recording provenance: %w", err)
		}
		res.Provenance = prov
	}
	return res, nil
}

func apply(root string, a Action) error {
	target, err := safeJoin(root, a.Path)
	if err != nil {
		return err
	}
	switch a.Kind {
	case KindRemoveFile, KindRemoveLink:
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil

	case KindConfigFlag, KindConfigKey:
		data, err := os.ReadFile(target)
		if err != nil {
			if os.IsNotExist(err) {
				return nil // nothing to change
			}
			return err
		}
		var cfg map[string]any
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("config is not valid JSON, so it was left alone: %w", err)
		}
		if a.Kind == KindConfigKey {
			delete(cfg, a.Key)
		} else {
			// Set to false rather than removed: a loader that reads the key and
			// finds it missing may apply its own default, which is not
			// necessarily the safe one.
			cfg[a.Key] = false
		}
		out, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(target, append(out, '\n'), 0o644)
	}
	return fmt.Errorf("unknown action %q", a.Kind)
}

// safeJoin refuses a path that leaves the destination. The plan is built from
// finding locations, which come from parsed files — attacker-influenced text
// that has no business escaping.
func safeJoin(root, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("empty path")
	}
	clean := filepath.Join(root, filepath.FromSlash(rel))
	if clean != root && !strings.HasPrefix(clean, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q escapes the destination", rel)
	}
	return clean, nil
}

// copyTree copies regular files only.
//
// Symlinks are deliberately not recreated. A hardened copy that faithfully
// reproduced a link pointing outside the artifact would carry the problem
// across, and the whole point is to leave it behind.
func copyTree(src, dest string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		switch {
		case info.IsDir():
			return os.MkdirAll(target, 0o755)
		case !info.Mode().IsRegular():
			return nil // symlinks, devices and sockets are not carried over
		case rel == ProvenanceFile:
			// The source's own hardening record is not carried across. It
			// describes the source, and a copy inheriting it would claim to be
			// derived from its own grandparent. A fresh record is written after
			// the actions; the chain is kept through its hardenedFrom field.
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		// The executable bit is dropped on the way across. Nothing in a model
		// artifact needs to be executable, and carrying the bit over would
		// preserve one of the things being hardened away.
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}
