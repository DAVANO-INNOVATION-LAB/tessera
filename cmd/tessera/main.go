// Command tessera reads a local model file — GGUF, safetensors, or ONNX — and
// emits a normalized AI bill of materials in CycloneDX (1.6 or 1.7) and SPDX 3.0.1
// a single parse, with security findings attached. It reads only headers and
// metadata: it never loads a framework, never resolves an ONNX operator, never
// fetches external data, and never touches the network. That makes it safe to
// run inside an air-gapped enclave against an untrusted artifact.
//
//	tessera scan <path> [--out DIR] [--fail-on SEVERITY]
//	tessera bom <path> [--format cyclonedx,spdx] [--out DIR] [--reproducible]
//	tessera inspect <path>
//	tessera version
//
// Exit codes are made for CI gates: 0 clean, 2 findings up to High, 3 a Critical
// finding, 1 the parse itself failed.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tessera "github.com/DAVANO-INNOVATION-LAB/tessera"
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/strutil"
)

// version is stamped by the linker: -ldflags "-X main.version=v0.1.0".
var version = "dev"

// Exit codes. These are a contract with CI gates, so usage problems get their
// own code rather than sharing one with a scan result: a pipeline that treats 2
// as "findings, warn and continue" would otherwise pass silently on a typo'd
// flag, having never scanned the artifact at all.
const (
	exitClean    = 0  // scanned, nothing above Low
	exitError    = 1  // the scan itself failed
	exitFindings = 2  // scanned, findings up to High
	exitCritical = 3  // scanned, at least one Critical
	exitUsage    = 64 // the command line was wrong; nothing was scanned
)

func main() {
	tessera.Version = version

	if len(os.Args) < 2 {
		usage()
		os.Exit(exitUsage)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "bom":
		os.Exit(runBOM(os.Args[2:]))
	case "inspect":
		os.Exit(runInspect(os.Args[2:]))
	case "verify":
		os.Exit(runVerify(os.Args[2:]))
	case "coverage":
		os.Exit(runCoverage(os.Args[2:]))
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(exitUsage)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `tessera - offline AIBOM generator for model files

Usage:
  tessera scan     <path> [--out DIR] [--fail-on SEVERITY]
  tessera bom      <path> [--format cyclonedx,spdx,sarif] [--cyclonedx-version 1.6|1.7]
                   [--out DIR] [--reproducible]
  tessera inspect  <path> [--json]
  tessera verify   <bom.json> <path> [--json]
  tessera coverage <path> [--standard g7|cert-in|bsi|cisa-2026] [--json]
  tessera version

tessera reads a GGUF, safetensors, or ONNX file (or a directory containing one)
and emits an AI bill of materials in CycloneDX (1.6 or 1.7) and SPDX 3.0.1, plus the
security findings the metadata discloses. It reads only headers and metadata and
never touches the network, so it is safe against an untrusted artifact offline.

  scan      parse, inspect, document and judge in one pass
  bom       write the bill of materials
  inspect   read the metadata and findings without writing a document
  verify    check an existing document against the bytes it claims to describe
  coverage  report which elements of a published minimum-elements standard the
            artifact can actually supply, and which it cannot

bom flags:
  --cyclonedx-version  1.6 (default) or 1.7; the document is identical either
             way, only the declared specVersion differs
  --fail-on  exit non-zero only at or above this severity (critical, high,
             medium, low, never). Unset keeps the exit codes below as they are.
  --format   comma list of cyclonedx,spdx,sarif (default cyclonedx,spdx; a
             single format may go
             to stdout, both require --out)
  --out DIR  write <name>.cdx.json and <name>.spdx.json into DIR; "-" means stdout
  --reproducible  timestamp the BOM from the model file's mtime, so identical
                  input yields byte-identical output

Exit codes: 0 clean, 2 findings up to High, 3 a Critical finding,
            1 scan error, 64 bad command line (nothing was scanned).
`)
}

func runBOM(args []string) int {
	fs := flag.NewFlagSet("bom", flag.ContinueOnError)
	format := fs.String("format", "cyclonedx,spdx", "comma list: cyclonedx,spdx,sarif")
	cdxVersion := fs.String("cyclonedx-version", tessera.CycloneDX16, "CycloneDX spec version: 1.6 or 1.7")
	out := fs.String("out", "", "output directory (\"-\" or empty = stdout)")
	reproducible := fs.Bool("reproducible", false, "timestamp from the model file mtime for byte-identical output")
	failOn := fs.String("fail-on", "", "exit non-zero only at or above this severity: critical, high, medium, low, never")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: tessera bom <path> [--format cyclonedx,spdx,sarif] [--cyclonedx-version 1.6|1.7] [--out DIR] [--reproducible] [--fail-on SEVERITY]")
		fs.PrintDefaults()
	}
	path, err := parseWithPositional(fs, args)
	if err != nil {
		fs.Usage()
		return exitUsage
	}

	formats, err := parseFormats(*format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera bom: %v\n", err)
		return exitUsage
	}

	artifact, err := tessera.Analyze(context.Background(), path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera bom: %v\n", err)
		return exitError
	}

	generatedAt := time.Now()
	if *reproducible {
		if info, err := os.Stat(path); err == nil {
			generatedAt = info.ModTime()
		}
	}

	toStdout := *out == "" || *out == "-"
	if toStdout && len(formats) > 1 {
		fmt.Fprintln(os.Stderr, "tessera bom: multiple formats need --out DIR; pick one format for stdout")
		return exitUsage
	}

	slug := strutil.Slug(artifact.Identity.Name, "model")
	for _, fmtName := range formats {
		data, err := render(fmtName, artifact, generatedAt, *cdxVersion)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tessera bom: %v\n", err)
			return exitError
		}
		if toStdout {
			os.Stdout.Write(data)
			continue
		}
		if err := os.MkdirAll(*out, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "tessera bom: %v\n", err)
			return exitError
		}
		name := slug + extFor(fmtName)
		dst := filepath.Join(*out, name)
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "tessera bom: %v\n", err)
			return exitError
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", dst)
	}

	// Report findings to stderr so stdout stays a clean BOM.
	reportFindings(artifact)

	gated, err := gateExit(artifact, *failOn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera bom: %v\n", err)
		return exitUsage
	}
	return gated
}

// gateExit applies a --fail-on threshold to the exit code.
//
// The bare exit code cannot express this on its own: High and Medium share
// code 2, so a caller that gates on the number alone cannot ask to fail on High
// without also failing on Medium. The severity is known here, so the decision
// is made here rather than approximated by whoever reads the code.
//
// An unset threshold keeps the historical behaviour exactly. When one is set,
// a result below it exits clean, and a result at or above it keeps the
// informative code (2 or 3) rather than collapsing to a generic failure.
func gateExit(a *tessera.Artifact, failOn string) (int, error) {
	code := exitCode(a)
	if failOn == "" {
		return code, nil
	}

	var threshold int
	switch strings.ToLower(failOn) {
	case "critical":
		threshold = tessera.Severity(tessera.SeverityCritical)
	case "high":
		threshold = tessera.Severity(tessera.SeverityHigh)
	case "medium":
		threshold = tessera.Severity(tessera.SeverityMedium)
	case "low":
		threshold = tessera.Severity(tessera.SeverityLow)
	case "never":
		return exitClean, nil
	default:
		return 0, fmt.Errorf(
			"unknown --fail-on %q (want critical, high, medium, low or never)", failOn)
	}

	// Severity ranks ascend as severity falls, so "at or above the threshold"
	// is a <= comparison on the rank.
	if tessera.Severity(tessera.Worst(a.Findings)) <= threshold {
		return code, nil
	}
	return exitClean, nil
}

// parseWithPositional parses flags that may appear before or after the single
// positional path argument. The stdlib flag package stops at the first non-flag
// token, so a two-phase parse is needed to accept "bom <path> --flag" as well
// as "bom --flag <path>".
func parseWithPositional(fs *flag.FlagSet, args []string) (string, error) {
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return "", fmt.Errorf("missing path argument")
	}
	path := rest[0]
	if err := fs.Parse(rest[1:]); err != nil {
		return "", err
	}
	if fs.NArg() != 0 {
		return "", fmt.Errorf("unexpected extra arguments: %v", fs.Args())
	}
	return path, nil
}

func render(name string, a *tessera.Artifact, at time.Time, cdxVersion string) ([]byte, error) {
	switch name {
	case "cyclonedx":
		return tessera.CycloneDXVersion(a, at, cdxVersion)
	case "spdx":
		return tessera.SPDX(a, at)
	case "sarif":
		return tessera.SARIF(a, at)
	}
	return nil, fmt.Errorf("unknown format %q", name)
}

func extFor(name string) string {
	switch name {
	case "spdx":
		return ".spdx.json"
	case "sarif":
		return ".sarif.json"
	}
	return ".cdx.json"
}

func parseFormats(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(strings.ToLower(f))
		if f == "" {
			continue
		}
		if f != "cyclonedx" && f != "spdx" && f != "sarif" {
			return nil, fmt.Errorf("unknown format %q (want cyclonedx, spdx or sarif)", f)
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no formats selected")
	}
	return out, nil
}

// runInspect prints a human summary of the parsed metadata and findings — the
// quick read before generating a BOM.
func runInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit the parsed artifact as JSON")
	deep := fs.Bool("deep", false, "also walk the directory for executable formats (pickle, Keras, SavedModel, archives)")
	path, err := parseWithPositional(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Usage: tessera inspect <path> [--json] [--deep]")
		return exitUsage
	}
	artifact, err := tessera.Analyze(context.Background(), path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera inspect: %v\n", err)
		return exitError
	}

	// The deep walk answers a different question from the parse. GGUF,
	// safetensors and ONNX are the formats that cannot carry code; the attack
	// lands in the pickle or the Keras Lambda sitting beside them, which a scan
	// that only opened the model would report as clean.
	if *deep {
		report, err := tessera.Inspect(context.Background(), inspectRoot(path))
		if err != nil {
			fmt.Fprintf(os.Stderr, "tessera inspect: %v\n", err)
			return exitError
		}
		artifact.Findings = mergeFindings(artifact.Findings, report.Findings)
		if report.Truncated {
			artifact.Findings = append(artifact.Findings, tessera.Finding{
				ID: "TESS-COVERAGE-001", Title: "Artifact walk was truncated", Severity: "Medium",
				Category: "model", Location: path,
				Description: "the file cap was reached, so part of the artifact was never examined; " +
					"a clean result over a partial walk is not a clean artifact",
			})
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(artifact); err != nil {
			fmt.Fprintf(os.Stderr, "tessera inspect: %v\n", err)
			return exitError
		}
		return exitCode(artifact)
	}

	printHuman(artifact)
	return exitCode(artifact)
}

func printHuman(a *tessera.Artifact) {
	fmt.Printf("tessera %s\n\n", version)
	fmt.Printf("  format        %s\n", a.Format)
	fmt.Printf("  name          %s\n", orNone(a.Identity.Name))
	if a.Identity.Version != "" {
		fmt.Printf("  version       %s\n", a.Identity.Version)
	}
	if sup := cmp.Or(a.Identity.Organization, a.Identity.Author); sup != "" {
		fmt.Printf("  supplier      %s\n", sup)
	}
	if len(a.Licenses) > 0 {
		var lics []string
		for _, l := range a.Licenses {
			if l.SPDXID != "" {
				lics = append(lics, fmt.Sprintf("%s (%s)", l.SPDXID, l.Confidence))
			} else {
				lics = append(lics, l.Raw)
			}
		}
		fmt.Printf("  license       %s\n", strings.Join(lics, ", "))
	}
	if a.Params.Architecture != "" {
		fmt.Printf("  architecture  %s\n", a.Params.Architecture)
	}
	if a.Params.Quantization != "" {
		fmt.Printf("  quantization  %s\n", a.Params.Quantization)
	}
	if a.TensorCount > 0 {
		fmt.Printf("  tensors       %d\n", a.TensorCount)
	}
	if len(a.Runtime.OpsetImports) > 0 {
		var ops []string
		for _, o := range a.Runtime.OpsetImports {
			d := o.Domain
			if d == "" {
				d = "ai.onnx"
			}
			ops = append(ops, fmt.Sprintf("%s v%d", d, o.Version))
		}
		fmt.Printf("  opsets        %s\n", strings.Join(ops, ", "))
	}
	if len(a.Runtime.CustomDomains) > 0 {
		fmt.Printf("  custom ops    %s\n", strings.Join(a.Runtime.CustomDomains, ", "))
	}
	if len(a.Lineage.BaseModels) > 0 {
		var bm []string
		for _, b := range a.Lineage.BaseModels {
			bm = append(bm, b.Name)
		}
		fmt.Printf("  base models   %s\n", strings.Join(bm, ", "))
	}

	fmt.Printf("\n  files (%d):\n", len(a.Files))
	for _, f := range a.Files {
		fmt.Printf("    %-13s %s  %s\n", f.Role, shortHash(f.SHA256), f.Path)
	}

	if len(a.Findings) == 0 {
		fmt.Printf("\n  no findings\n")
	} else {
		findings := append([]tessera.Finding(nil), a.Findings...)
		sort.SliceStable(findings, func(i, j int) bool {
			return tessera.Severity(findings[i].Severity) < tessera.Severity(findings[j].Severity)
		})
		fmt.Printf("\n  findings (%d):\n", len(findings))
		for _, f := range findings {
			fmt.Printf("    [%-8s] %s  %s\n", f.Severity, f.ID, f.Title)
			fmt.Printf("               %s\n", f.Description)
		}
	}
}

func reportFindings(a *tessera.Artifact) {
	findings := append([]tessera.Finding(nil), a.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		return tessera.Severity(findings[i].Severity) < tessera.Severity(findings[j].Severity)
	})
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "finding [%s] %s: %s\n", f.Severity, f.ID, f.Title)
	}

	// A closing summary, always printed, in a shape a script can read.
	//
	// The exit code stopped being sufficient for this once --fail-on existed: a
	// gated run exits clean while still having found something, so a caller
	// reading only the code cannot tell "nothing was found" from "something was
	// found and you asked me not to fail on it". This line always states what
	// was actually found, independent of what the gate decided to do about it.
	fmt.Fprintf(os.Stderr, "worst severity: %s (findings: %d)\n",
		severityOrNone(tessera.Worst(a.Findings)), len(a.Findings))
}

// severityOrNone renders the absent severity as a word rather than an empty string, so
// the summary line always has a value in the same position.
func severityOrNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// inspectRoot resolves the directory to walk. Pointing --deep at a single model
// file should still examine what sits beside it, since that is where an
// executable payload would be.
func inspectRoot(path string) string {
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return filepath.Dir(path)
	}
	return path
}

// mergeFindings appends the walk's findings to the parser's, dropping any that
// the parser already reported for the same place.
//
// The two subsystems overlap deliberately on safetensors: the parser reads the
// header as part of describing the model, and the walker reads it again because
// it cannot assume the parser ran. Reporting the same defect twice would inflate
// the count and make one artifact look worse than another for no reason, so the
// parser's finding wins — it is the one that had the whole file open.
func mergeFindings(parsed, walked []tessera.Finding) []tessera.Finding {
	seen := make(map[string]bool, len(parsed))
	for _, f := range parsed {
		seen[f.ID+"\x00"+f.Location] = true
	}
	for _, f := range walked {
		key := f.ID + "\x00" + f.Location
		if seen[key] {
			continue
		}
		seen[key] = true
		parsed = append(parsed, f)
	}
	return parsed
}

func exitCode(a *tessera.Artifact) int {
	switch worst := tessera.Worst(a.Findings); worst {
	case tessera.SeverityCritical:
		return exitCritical
	case tessera.SeverityHigh, tessera.SeverityMedium:
		return exitFindings
	default:
		return exitClean
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none disclosed)"
	}
	return s
}

func shortHash(sha string) string {
	if len(sha) >= 12 {
		return sha[:12]
	}
	return "-"
}

// runVerify checks a bill of materials against an artifact.
func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit the full result as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: tessera verify <bom.json> <path> [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	rest := fs.Args()
	if len(rest) != 2 {
		fs.Usage()
		return exitUsage
	}

	res, err := tessera.Verify(context.Background(), rest[0], rest[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera verify: %v\n", err)
		return exitError
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(os.Stderr, "tessera verify: %v\n", err)
			return exitError
		}
	} else {
		printVerify(res, rest[0], rest[1])
	}

	if res.Verified {
		return exitClean
	}
	// A document that does not describe the artifact is a failed gate, not a
	// scan finding: nothing here is a judgement about the model's contents.
	return exitCritical
}

func printVerify(r *tessera.VerifyResult, docPath, artifactPath string) {
	fmt.Printf("tessera %s — verifying\n", version)
	fmt.Printf("  document  %s (%s)\n", docPath, r.DocumentFormat)
	fmt.Printf("  artifact  %s\n\n", artifactPath)

	symbol := map[tessera.VerifyOutcome]string{
		tessera.VerifyPass:        "ok  ",
		tessera.VerifyFail:        "FAIL",
		tessera.VerifyUncheckable: "?   ",
		tessera.VerifyExtra:       "EXTRA",
	}
	for _, c := range r.Checks {
		fmt.Printf("  [%-5s] %s\n", symbol[c.Outcome], c.Subject)
		if c.Claim != "" || c.Measured != "" {
			fmt.Printf("            document: %s\n            artifact: %s\n",
				orNone(c.Claim), orNone(c.Measured))
		}
		if c.Detail != "" {
			fmt.Printf("            %s\n", c.Detail)
		}
	}

	fmt.Printf("\n  %d passed, %d failed, %d uncheckable, %d undocumented\n",
		r.Summary.Passed, r.Summary.Failed, r.Summary.Uncheckable, r.Summary.NotInDocument)
	if r.Verified {
		fmt.Println("\nverified: the artifact matches the document")
	} else {
		fmt.Println("\nNOT VERIFIED: the artifact does not match the document")
	}
}

// runCoverage reports how far an artifact goes toward a published
// minimum-elements standard.
func runCoverage(args []string) int {
	fs := flag.NewFlagSet("coverage", flag.ContinueOnError)
	standard := fs.String("standard", "g7", "minimum-elements standard: "+
		strings.Join(tessera.CoverageStandards(), ", "))
	jsonOut := fs.Bool("json", false, "emit the report as JSON")
	path, err := parseWithPositional(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Usage: tessera coverage <path> [--standard g7|cert-in|bsi|cisa-2026] [--json]")
		return exitUsage
	}

	rep, err := tessera.Coverage(context.Background(), *standard, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera coverage: %v\n", err)
		return exitError
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(os.Stderr, "tessera coverage: %v\n", err)
			return exitError
		}
		return exitClean
	}

	printCoverage(rep, path)
	return exitClean
}

func printCoverage(r *tessera.CoverageReport, path string) {
	fmt.Printf("tessera %s — %s\n  artifact %s\n\n", version, r.Title, path)

	mark := map[tessera.CoverageStatus]string{
		tessera.CoveragePopulated:  "yes",
		tessera.CoverageAbsent:     "-  ",
		tessera.CoverageOutOfScope: "n/a",
	}
	cluster := ""
	for _, e := range r.Elements {
		if e.Cluster != cluster {
			cluster = e.Cluster
			fmt.Printf("  %s\n", cluster)
		}
		fmt.Printf("    [%s] %s\n", mark[e.Status], e.Name)
		if e.Value != "" {
			fmt.Printf("          %s\n", truncate(e.Value, 88))
		}
		if e.Note != "" {
			fmt.Printf("          %s\n", e.Note)
		}
	}

	total := r.Populated + r.Absent + r.OutOfScope
	fmt.Printf("\n  %d of %d elements populated; %d absent from this artifact, "+
		"%d not derivable from any model file.\n",
		r.Populated, total, r.Absent, r.OutOfScope)
	// Each n/a element already carries the specific reason it cannot be
	// derived, and those reasons differ by standard — training data and
	// evaluation results for the AI lists, signing and organizational process
	// for the CISA one. Pointing at the per-element notes beats restating one
	// standard's rationale over all of them.
	if r.OutOfScope > 0 {
		fmt.Println("  Elements marked n/a carry the reason they cannot be derived from a")
		fmt.Println("  model file; a static parse is the wrong instrument for them.")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
