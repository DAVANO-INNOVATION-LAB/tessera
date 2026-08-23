package eval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera"
	"github.com/DAVANO-INNOVATION-LAB/tessera/bench/internal/corpus"
)

// Grading, and what the numbers are allowed to mean.
//
// Precision and recall here are over *labels*, not cases. A case with three
// expected findings contributes three chances to be right, which is the honest
// unit: a tool that finds two of three has not "passed" the case.
//
// A finding the corpus neither expects nor forbids is not counted either way.
// The corpus does not claim to be exhaustive about every artifact, and scoring
// unlabelled output as wrong would punish a tool for reporting something true
// that nobody thought to label. Forbidden labels are how a false positive gets
// counted, which is why the traps matter more than the positives.

// Result is one case's outcome.
type Result struct {
	Case string `json:"case"`
	Why  string `json:"why"`
	// Found are the finding IDs the scan reported.
	Found []string `json:"found"`
	// Missed are expected findings that did not appear: false negatives.
	Missed []string `json:"missed,omitempty"`
	// Fired are forbidden findings that did appear: false positives, and the
	// expensive kind — a trap firing means the tool cannot be trusted on
	// artifacts that are fine.
	Fired []string `json:"fired,omitempty"`
	Error string   `json:"error,omitempty"`
}

// OK reports whether the case was fully correct.
func (r Result) OK() bool { return r.Error == "" && len(r.Missed) == 0 && len(r.Fired) == 0 }

// Report is the whole run.
type Report struct {
	RunAt   string   `json:"runAt"`
	Cases   int      `json:"cases"`
	Labels  int      `json:"labels"`
	Results []Result `json:"results"`

	TruePositives  int `json:"truePositives"`
	FalseNegatives int `json:"falseNegatives"`
	FalsePositives int `json:"falsePositives"`
	TrueNegatives  int `json:"trueNegatives"`
}

// Precision is correct positives over all positives claimed against a label.
func (r Report) Precision() float64 {
	d := r.TruePositives + r.FalsePositives
	if d == 0 {
		return 1
	}
	return float64(r.TruePositives) / float64(d)
}

// Recall is correct positives over everything that should have been found.
func (r Report) Recall() float64 {
	d := r.TruePositives + r.FalseNegatives
	if d == 0 {
		return 1
	}
	return float64(r.TruePositives) / float64(d)
}

// Run generates the corpus, scans it, and grades the output.
func Run(ctx context.Context, cases []corpus.Case, dir string) (*Report, error) {
	rep := &Report{Cases: len(cases)}
	for _, c := range cases {
		rep.Labels += len(c.Expect) + len(c.Forbid)
		root, err := c.Write(dir)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.Name, err)
		}
		res := grade(ctx, c, root)
		rep.TruePositives += len(c.Expect) - len(res.Missed)
		rep.FalseNegatives += len(res.Missed)
		rep.FalsePositives += len(res.Fired)
		rep.TrueNegatives += len(c.Forbid) - len(res.Fired)
		rep.Results = append(rep.Results, res)
	}
	return rep, nil
}

func grade(ctx context.Context, c corpus.Case, root string) Result {
	res := Result{Case: c.Name, Why: c.Why}

	found := map[string]bool{}
	art, err := tessera.Analyze(ctx, root)
	if err == nil {
		for _, f := range art.Findings {
			found[f.ID] = true
		}
	} else if !isUnrecognized(err) {
		res.Error = err.Error()
		return res
	}
	// The directory walk is a separate pass and half the corpus depends on it:
	// a pickle beside a model is invisible to anything that only parses the
	// model file.
	if rep, werr := tessera.Inspect(ctx, root); werr == nil {
		for _, f := range rep.Findings {
			found[f.ID] = true
		}
	}

	for id := range found {
		res.Found = append(res.Found, id)
	}
	sort.Strings(res.Found)

	for _, want := range c.Expect {
		if !found[want] {
			res.Missed = append(res.Missed, want)
		}
	}
	for _, bad := range c.Forbid {
		if found[bad] {
			res.Fired = append(res.Fired, bad)
		}
	}
	return res
}

func isUnrecognized(err error) bool {
	return err != nil && errors.Is(err, tessera.ErrUnrecognized)
}

// Stamp records when the run happened. Kept out of Run so the report itself
// stays deterministic and two runs of the same corpus compare equal.
func (r *Report) Stamp(at time.Time) { r.RunAt = at.UTC().Format(time.RFC3339) }

// Marshal renders a report for a baseline file.
func (r *Report) Marshal() ([]byte, error) {
	enc, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(enc, '\n'), nil
}

// Regressions compares against a baseline and names what got worse.
//
// Only worse. A run that improves is not a regression, and a gate that fired on
// any change at all would be turned off within a week.
func (r *Report) Regressions(base *Report) []string {
	prev := map[string]Result{}
	for _, x := range base.Results {
		prev[x.Case] = x
	}
	var out []string
	for _, cur := range r.Results {
		was, ok := prev[cur.Case]
		if !ok {
			continue // a new case cannot regress
		}
		for _, m := range cur.Missed {
			if !contains(was.Missed, m) {
				out = append(out, cur.Case+": no longer finds "+m)
			}
		}
		for _, f := range cur.Fired {
			if !contains(was.Fired, f) {
				out = append(out, cur.Case+": now falsely reports "+f)
			}
		}
		if cur.Error != "" && was.Error == "" {
			out = append(out, cur.Case+": now errors — "+cur.Error)
		}
	}
	// A case that vanished is a regression in coverage, not in accuracy, but it
	// is still something a reviewer must be told rather than left to notice.
	for name := range prev {
		if !hasCase(r.Results, name) {
			out = append(out, name+": case is no longer in the corpus")
		}
	}
	sort.Strings(out)
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func hasCase(rs []Result, name string) bool {
	for _, r := range rs {
		if r.Case == name {
			return true
		}
	}
	return false
}
