// Command tessera reads a local model file — GGUF, safetensors, or ONNX — and
// emits a normalized AI bill of materials in CycloneDX 1.6 and SPDX 3.0.1 from
// a single parse, with security findings attached. It reads only headers and
// metadata: it never loads a framework, never resolves an ONNX operator, never
// fetches external data, and never touches the network. That makes it safe to
// run inside an air-gapped enclave against an untrusted artifact.
//
//	tessera bom <path> [--format cyclonedx,spdx] [--out DIR] [--reproducible]
//	tessera inspect <path>
//	tessera version
//
// Exit codes are made for CI gates: 0 clean, 2 findings up to High, 3 a Critical
// finding, 1 the parse itself failed.
package main

import (
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
	case "bom":
		os.Exit(runBOM(os.Args[2:]))
	case "inspect":
		os.Exit(runInspect(os.Args[2:]))
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
  tessera bom <path> [--format cyclonedx,spdx] [--out DIR] [--reproducible]
  tessera inspect <path>
  tessera version

tessera reads a GGUF, safetensors, or ONNX file (or a directory containing one)
and emits an AI bill of materials in CycloneDX 1.6 and SPDX 3.0.1, plus the
security findings the metadata discloses. It reads only headers and metadata and
never touches the network, so it is safe against an untrusted artifact offline.

bom flags:
  --format   comma list of cyclonedx,spdx (default both; a single format may go
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
	format := fs.String("format", "cyclonedx,spdx", "comma list: cyclonedx,spdx")
	out := fs.String("out", "", "output directory (\"-\" or empty = stdout)")
	reproducible := fs.Bool("reproducible", false, "timestamp from the model file mtime for byte-identical output")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: tessera bom <path> [--format cyclonedx,spdx] [--out DIR] [--reproducible]")
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

	slug := sanitizeFile(artifact.Identity.Name)
	for _, fmtName := range formats {
		data, err := render(fmtName, artifact, generatedAt)
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
	return exitCode(artifact)
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

func render(name string, a *tessera.Artifact, at time.Time) ([]byte, error) {
	switch name {
	case "cyclonedx":
		return tessera.CycloneDX(a, at)
	case "spdx":
		return tessera.SPDX(a, at)
	}
	return nil, fmt.Errorf("unknown format %q", name)
}

func extFor(name string) string {
	if name == "spdx" {
		return ".spdx.json"
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
		if f != "cyclonedx" && f != "spdx" {
			return nil, fmt.Errorf("unknown format %q (want cyclonedx or spdx)", f)
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
	path, err := parseWithPositional(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Usage: tessera inspect <path> [--json]")
		return exitUsage
	}
	artifact, err := tessera.Analyze(context.Background(), path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera inspect: %v\n", err)
		return exitError
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
	if sup := firstNonEmpty(a.Identity.Organization, a.Identity.Author); sup != "" {
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
	if len(a.Findings) == 0 {
		return
	}
	findings := append([]tessera.Finding(nil), a.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		return tessera.Severity(findings[i].Severity) < tessera.Severity(findings[j].Severity)
	})
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "finding [%s] %s: %s\n", f.Severity, f.ID, f.Title)
	}
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
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

func sanitizeFile(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "model"
	}
	return out
}
