package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera"
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/strutil"
)

// scan is the whole tool in one command.
//
// The separate subcommands each answer one question, which is right when you
// know which question you have. The common case is not that: somebody has a
// model directory and needs to know whether it is safe to ship, with the
// documents to prove what was checked. That used to require a cluster, because
// the parts that answered it lived in an operator. It now requires this binary
// and nothing else — no daemon, no account, no network.
func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	out := fs.String("out", "", "write documents to this directory (default: none, report only)")
	format := fs.String("format", "cyclonedx,spdx,sarif", "documents to write: cyclonedx,spdx,sarif")
	cdxVersion := fs.String("cyclonedx-version", tessera.CycloneDX16, "CycloneDX spec version: 1.6 or 1.7")
	policyPath := fs.String("policy", "", "policy rules as JSON; omitted means the built-in defaults")
	shallow := fs.Bool("no-deep", false, "skip the walk for executable formats beside the model")
	jsonOut := fs.Bool("json", false, "emit the whole result as JSON")
	reproducible := fs.Bool("reproducible", false, "timestamp from the model file mtime")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: tessera scan <path> [--out DIR] [--policy rules.json] [--json]")
		fs.PrintDefaults()
	}
	path, err := parseWithPositional(fs, args)
	if err != nil {
		fs.Usage()
		return exitUsage
	}

	formats, err := parseFormats(*format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera scan: %v\n", err)
		return exitUsage
	}

	rules, err := loadRules(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera scan: %v\n", err)
		return exitUsage
	}

	ctx := context.Background()
	artifact, err := tessera.Analyze(ctx, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera scan: %v\n", err)
		return exitError
	}

	// The deep walk is on by default here, unlike `inspect`. This command is
	// the one that produces a verdict, and a verdict that never looked at the
	// pickle beside the weights is not one worth acting on.
	truncated := false
	parsed := append([]tessera.Finding(nil), artifact.Findings...)
	var walked []tessera.Finding
	if !*shallow {
		report, err := tessera.Inspect(ctx, inspectRoot(path))
		if err != nil {
			fmt.Fprintf(os.Stderr, "tessera scan: %v\n", err)
			return exitError
		}
		merged := mergeFindings(artifact.Findings, report.Findings)
		// Only what the merge actually accepted counts as the walk's
		// contribution. Taking report.Findings wholesale would re-count the
		// safetensors defects the parser already reported, inflating the risk
		// score for an artifact with one problem described twice.
		walked = merged[len(artifact.Findings):]
		artifact.Findings = merged
		truncated = report.Truncated
	}

	generatedAt := time.Now()
	if *reproducible {
		if info, err := os.Stat(path); err == nil {
			generatedAt = info.ModTime()
		}
	}

	var written []string
	if *out != "" && *out != "-" {
		if err := os.MkdirAll(*out, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "tessera scan: %v\n", err)
			return exitError
		}
		slug := strutil.Slug(artifact.Identity.Name, "model")
		for _, name := range formats {
			data, err := render(name, artifact, generatedAt, *cdxVersion)
			if err != nil {
				fmt.Fprintf(os.Stderr, "tessera scan: %v\n", err)
				return exitError
			}
			dst := filepath.Join(*out, slug+extFor(name))
			if err := os.WriteFile(dst, data, 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "tessera scan: %v\n", err)
				return exitError
			}
			written = append(written, dst)
		}
	}

	// The gate reads scanner results, so this scan presents itself as two:
	// what the parse established about the model, and what the walk found
	// around it. Naming them separately keeps the model findings gateable on
	// their own terms rather than averaged into one number.
	results := []tessera.ScannerResult{{
		Scanner:    "tessera",
		Status:     tessera.ScannerStatusFor(len(parsed)),
		Findings:   int32(len(parsed)),
		Severities: tally(parsed, false),
		Drift:      tally(parsed, true),
		Produced:   boolPtr(true),
	}}
	if !*shallow {
		results = append(results, tessera.ScannerResult{
			Scanner:    "model-inspector",
			Status:     tessera.ScannerStatusFor(len(walked)),
			Findings:   int32(len(walked)),
			Severities: tally(walked, false),
		})
	}

	verdict := tessera.Gate(results, tessera.GateArtifact{
		URI:    path,
		Digest: artifact.PrimaryFile().SHA256,
		Format: string(artifact.Format),
	}, rules, nil, time.Now())

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{
			"artifact":  artifact,
			"verdict":   verdict,
			"documents": written,
			"truncated": truncated,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "tessera scan: %v\n", err)
			return exitError
		}
		return scanExit(verdict.Verdict)
	}

	reportFindings(artifact)
	for _, w := range written {
		fmt.Fprintf(os.Stderr, "wrote %s\n", w)
	}
	if truncated {
		fmt.Fprintln(os.Stderr,
			"warning: the artifact walk was truncated, so part of it was never examined")
	}
	fmt.Fprintf(os.Stderr, "\nverdict: %s (risk %d)\n", verdict.Verdict, verdict.RiskScore)
	for _, v := range verdict.Violations {
		fmt.Fprintf(os.Stderr, "  violation [%s] %s\n", v.Rule, v.Message)
	}
	for _, w := range verdict.Waived {
		fmt.Fprintf(os.Stderr, "  waived    [%s] %s\n", w.Rule, w.Message)
	}
	return scanExit(verdict.Verdict)
}

// loadRules reads policy rules from JSON.
//
// JSON rather than YAML because the zero-dependency guarantee is worth more
// than the convenience: the standard library parses one of them.
func loadRules(path string) (*tessera.GateRules, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy: %w", err)
	}
	var rules tessera.GateRules
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parsing policy %s: %w", path, err)
	}
	return &rules, nil
}

// tally counts findings by severity. Drift is counted separately because the
// gate treats it separately: a config that disagrees with its tensors is
// usually a stale re-upload, occasionally the only sign of a swap, and gating
// on it by default would bury the second case in false alarms.
func tally(findings []tessera.Finding, driftOnly bool) tessera.SeverityCounts {
	var c tessera.SeverityCounts
	for _, f := range findings {
		if (f.Category == "drift") != driftOnly {
			continue
		}
		switch f.Severity {
		case tessera.SeverityCritical:
			c.Critical++
		case tessera.SeverityHigh:
			c.High++
		case tessera.SeverityMedium:
			c.Medium++
		case tessera.SeverityLow:
			c.Low++
		default:
			c.Unknown++
		}
	}
	return c
}

func boolPtr(b bool) *bool { return &b }

// scanExit maps a verdict onto the documented exit codes: quarantined is the
// Critical code, review-required is the findings code, approved is clean.
func scanExit(verdict string) int {
	switch verdict {
	case tessera.VerdictQuarantined:
		return exitCritical
	case tessera.VerdictReviewRequired:
		return exitFindings
	}
	return exitClean
}
