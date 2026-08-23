// Command tessera-bench measures Tessera against a labeled corpus.
//
// Exists because "we are accurate" is an assertion and a number with an n
// behind it is not. In any evaluation, measured-with-receipts beats asserted,
// and a tool that cannot state its own precision is asking to be taken on
// faith.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/bench/internal/corpus"
	"github.com/DAVANO-INNOVATION-LAB/tessera/bench/internal/eval"
)

const (
	exitOK         = 0
	exitUsage      = 64
	exitError      = 1
	exitRegression = 3
)

//go:generate echo "corpus lives in corpus/cases.json"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return exitUsage
	}
	switch args[0] {
	case "run":
		return runBench(args[1:])
	case "generate":
		return runGenerate(args[1:])
	default:
		usage()
		return exitUsage
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `tessera-bench - measure Tessera against a labeled corpus

Usage:
  tessera-bench run [--corpus FILE] [--baseline FILE] [--json] [--write-baseline FILE]
  tessera-bench generate --out DIR [--corpus FILE]

run scans a generated corpus and reports precision and recall over labels.
With --baseline it exits `+fmt.Sprint(exitRegression)+` when something that used to be
correct no longer is.`)
}

func loadCases(path string) ([]corpus.Case, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cases []corpus.Case
	if err := json.Unmarshal(data, &cases); err != nil {
		return nil, fmt.Errorf("corpus: %w", err)
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("corpus is empty")
	}
	return cases, nil
}

func runGenerate(args []string) int {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	out := fs.String("out", "", "directory to write the corpus into")
	src := fs.String("corpus", defaultCorpus(), "corpus definition")
	if err := fs.Parse(args); err != nil || *out == "" {
		usage()
		return exitUsage
	}
	cases, err := loadCases(*src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bench: %v\n", err)
		return exitError
	}
	for _, c := range cases {
		if _, err := c.Write(*out); err != nil {
			fmt.Fprintf(os.Stderr, "tessera-bench: %v\n", err)
			return exitError
		}
	}
	fmt.Fprintf(os.Stderr, "wrote %d cases to %s\n", len(cases), *out)
	return exitOK
}

func runBench(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	src := fs.String("corpus", defaultCorpus(), "corpus definition")
	baseline := fs.String("baseline", "", "compare against this report and fail on regression")
	writeBaseline := fs.String("write-baseline", "", "write the report here")
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	keep := fs.String("keep", "", "keep the generated corpus in this directory")
	if err := fs.Parse(args); err != nil {
		usage()
		return exitUsage
	}
	cases, err := loadCases(*src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bench: %v\n", err)
		return exitError
	}

	dir := *keep
	if dir == "" {
		dir, err = os.MkdirTemp("", "tessera-bench-*")
		if err != nil {
			fmt.Fprintf(os.Stderr, "tessera-bench: %v\n", err)
			return exitError
		}
		defer os.RemoveAll(dir)
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bench: %v\n", err)
		return exitError
	}

	rep, err := eval.Run(context.Background(), cases, dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bench: %v\n", err)
		return exitError
	}
	rep.Stamp(time.Now())

	if *writeBaseline != "" {
		enc, err := rep.Marshal()
		if err == nil {
			err = os.WriteFile(*writeBaseline, enc, 0o644)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "tessera-bench: %v\n", err)
			return exitError
		}
	}

	if *asJSON {
		enc, _ := rep.Marshal()
		os.Stdout.Write(enc)
	} else {
		printReport(rep)
	}

	if *baseline == "" {
		if rep.FalseNegatives > 0 || rep.FalsePositives > 0 {
			return exitRegression
		}
		return exitOK
	}

	data, err := os.ReadFile(*baseline)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bench: %v\n", err)
		return exitError
	}
	var base eval.Report
	if err := json.Unmarshal(data, &base); err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bench: baseline: %v\n", err)
		return exitError
	}
	regs := rep.Regressions(&base)
	if len(regs) == 0 {
		fmt.Fprintln(os.Stderr, "\nno regressions against the baseline")
		return exitOK
	}
	fmt.Fprintf(os.Stderr, "\n%d regression(s) against the baseline:\n", len(regs))
	for _, r := range regs {
		fmt.Fprintln(os.Stderr, "  "+r)
	}
	return exitRegression
}

func printReport(r *eval.Report) {
	for _, res := range r.Results {
		mark := "pass"
		if !res.OK() {
			mark = "FAIL"
		}
		fmt.Printf("%-4s %s\n", mark, res.Case)
		for _, m := range res.Missed {
			fmt.Printf("       missed %s\n", m)
		}
		for _, f := range res.Fired {
			fmt.Printf("       false positive %s\n", f)
		}
		if res.Error != "" {
			fmt.Printf("       error %s\n", res.Error)
		}
	}
	fmt.Printf("\n%d cases, %d labels\n", r.Cases, r.Labels)
	fmt.Printf("precision %.1f%%  recall %.1f%%\n", r.Precision()*100, r.Recall()*100)
	fmt.Printf("  %d found, %d missed, %d false positives, %d correctly absent\n",
		r.TruePositives, r.FalseNegatives, r.FalsePositives, r.TrueNegatives)
}

// defaultCorpus finds the shipped corpus relative to the binary or the working
// directory, so the command works from a checkout without a flag.
func defaultCorpus() string {
	for _, p := range []string{
		"corpus/cases.json",
		filepath.Join("bench", "corpus", "cases.json"),
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "corpus/cases.json"
}
