// Package verify checks a bill of materials against the artifact it describes.
//
// Generating a document is the easy half. The harder half is asking, later and
// somewhere else, whether the document still describes these bytes — which is
// the question that matters at the moment of use rather than the moment of
// build.
//
// Several authorities ask for exactly this. Tools that re-check a recorded hash
// exist; what is scarce is re-deriving the non-hash claims — architecture,
// precision, parameter count — and reporting pass or fail per claim, which is
// what this package does. Korea's
// Framework Act Art. 36(1)(3) requires inspecting "the currency and accuracy" of
// safety documentation. Canada's ITSP.80.101 says to verify integrity before a
// model is loaded. Singapore's CSA guidance requires authenticating models as
// assets. The G7 minimum elements make a model hash a required element and name
// the algorithm from the IANA registry specifically so a third party can
// recompute it.
//
// Verification is deliberately one-directional about trust: the document is a
// claim and the bytes are the evidence. Where they disagree the bytes win, and
// the report says which claim failed rather than quietly re-deriving it.
package verify

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// Result is the outcome of checking a document against an artifact.
type Result struct {
	// Verified is true only when every claim the document makes about the
	// artifact held. It is false if anything failed, and also false if the
	// document made claims that could not be checked at all — an unverifiable
	// document has not been verified.
	Verified bool `json:"verified"`
	// DocumentFormat is the bill of materials that was read.
	DocumentFormat string `json:"documentFormat"`
	// Checks are every comparison performed, in a stable order.
	Checks []Check `json:"checks"`
	// Summary counts the outcomes.
	Summary Summary `json:"summary"`
}

// Summary counts check outcomes.
type Summary struct {
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Uncheckable   int `json:"uncheckable"`
	NotInDocument int `json:"notInDocument"`
}

// Outcome of a single check.
type Outcome string

const (
	// OutcomePass means the document's claim matched the artifact.
	OutcomePass Outcome = "pass"
	// OutcomeFail means the document's claim did not match the artifact.
	OutcomeFail Outcome = "fail"
	// OutcomeUncheckable means the document claimed something this tool cannot
	// confirm from the bytes. Reported rather than passed, because silence
	// would read as confirmation.
	OutcomeUncheckable Outcome = "uncheckable"
	// OutcomeExtra means the artifact has something the document never
	// mentioned — a file present on disk and absent from the component list.
	OutcomeExtra Outcome = "extra"
)

// Check is one comparison between a documented claim and a measured fact.
type Check struct {
	Outcome  Outcome `json:"outcome"`
	Subject  string  `json:"subject"`
	Claim    string  `json:"claim,omitempty"`
	Measured string  `json:"measured,omitempty"`
	Detail   string  `json:"detail,omitempty"`
}

// Document is the subset of a bill of materials that can be checked against
// bytes. Both CycloneDX and SPDX reduce to this, so the comparison logic does
// not care which was parsed.
type Document struct {
	Format    string
	ModelName string
	Version   string
	Files     []DocumentedFile
	// Properties carries scalar claims worth checking, keyed by a normalized
	// name: "measuredParameters", "quantization", "architecture".
	Properties map[string]string
}

// DocumentedFile is one component the document claims the model is made of.
type DocumentedFile struct {
	Path   string
	SHA256 string
	SHA384 string
	Size   int64
}

// Verify compares a parsed document against a freshly analysed artifact.
func Verify(ctx context.Context, doc *Document, a *model.Artifact) *Result {
	r := &Result{DocumentFormat: doc.Format}

	r.Checks = append(r.Checks, checkIdentity(doc, a)...)
	r.Checks = append(r.Checks, checkFiles(doc, a)...)
	r.Checks = append(r.Checks, checkProperties(doc, a)...)

	sort.SliceStable(r.Checks, func(i, j int) bool {
		if r.Checks[i].Outcome != r.Checks[j].Outcome {
			return outcomeRank(r.Checks[i].Outcome) < outcomeRank(r.Checks[j].Outcome)
		}
		return r.Checks[i].Subject < r.Checks[j].Subject
	})

	for _, c := range r.Checks {
		switch c.Outcome {
		case OutcomePass:
			r.Summary.Passed++
		case OutcomeFail:
			r.Summary.Failed++
		case OutcomeUncheckable:
			r.Summary.Uncheckable++
		case OutcomeExtra:
			r.Summary.NotInDocument++
		}
	}
	// An artifact carrying files the document never mentioned is not verified.
	// That is the shape a smuggled payload takes: everything documented checks
	// out, and something else rides along.
	r.Verified = r.Summary.Failed == 0 && r.Summary.NotInDocument == 0 && r.Summary.Passed > 0
	return r
}

func outcomeRank(o Outcome) int {
	switch o {
	case OutcomeFail:
		return 0
	case OutcomeExtra:
		return 1
	case OutcomeUncheckable:
		return 2
	}
	return 3
}

func checkIdentity(doc *Document, a *model.Artifact) []Check {
	var out []Check
	if doc.ModelName != "" {
		out = append(out, compare("model name", doc.ModelName, a.Identity.Name,
			strings.EqualFold(doc.ModelName, a.Identity.Name)))
	}
	if doc.Version != "" && a.Identity.Version != "" {
		out = append(out, compare("model version", doc.Version, a.Identity.Version,
			doc.Version == a.Identity.Version))
	}
	return out
}

// checkFiles is the load-bearing comparison: every component the document names
// must exist, and every file the artifact has must be documented.
func checkFiles(doc *Document, a *model.Artifact) []Check {
	actual := map[string]model.FileComponent{}
	for _, f := range a.Files {
		actual[f.Path] = f
	}
	documented := map[string]bool{}

	var out []Check
	for _, df := range doc.Files {
		documented[df.Path] = true
		af, ok := actual[df.Path]
		if !ok {
			out = append(out, Check{
				Outcome: OutcomeFail, Subject: "file " + df.Path,
				Claim:  "present",
				Detail: "the document lists this component; it is not in the artifact",
			})
			continue
		}
		// Prefer the strongest digest both sides carry. A document with only
		// SHA-256 is still checkable — it just gets checked at SHA-256.
		switch {
		case df.SHA384 != "" && af.SHA384 != "":
			out = append(out, compareHash("file "+df.Path+" (SHA-384)", df.SHA384, af.SHA384))
		case df.SHA256 != "" && af.SHA256 != "":
			out = append(out, compareHash("file "+df.Path+" (SHA-256)", df.SHA256, af.SHA256))
		default:
			out = append(out, Check{
				Outcome: OutcomeUncheckable, Subject: "file " + df.Path,
				Detail: "the document records no digest for this component, so its contents cannot be confirmed",
			})
		}
		if df.Size > 0 && af.Size > 0 && df.Size != af.Size {
			out = append(out, Check{
				Outcome: OutcomeFail, Subject: "file " + df.Path + " (size)",
				Claim:    fmt.Sprintf("%d bytes", df.Size),
				Measured: fmt.Sprintf("%d bytes", af.Size),
			})
		}
	}

	for _, f := range a.Files {
		if !documented[f.Path] {
			out = append(out, Check{
				Outcome: OutcomeExtra, Subject: "file " + f.Path,
				Measured: shortHash(f.SHA256),
				Detail: "this file is part of the artifact and absent from the document; " +
					"a bill of materials that omits a component does not describe what shipped",
			})
		}
	}
	return out
}

func checkProperties(doc *Document, a *model.Artifact) []Check {
	var out []Check
	measured := map[string]string{
		"architecture":       a.Params.Architecture,
		"quantization":       a.Params.Quantization,
		"dtype":              a.Params.DType,
		"measuredParameters": formatInt(a.Params.MeasuredParameters),
	}
	for _, key := range sortedKeys(doc.Properties) {
		claim := doc.Properties[key]
		if claim == "" {
			continue
		}
		got, known := measured[key]
		if !known {
			continue // not a property this tool measures
		}
		if got == "" {
			out = append(out, Check{
				Outcome: OutcomeUncheckable, Subject: key, Claim: claim,
				Detail: "the document states this; the artifact does not record it, so it cannot be confirmed",
			})
			continue
		}
		out = append(out, compare(key, claim, got, strings.EqualFold(claim, got)))
	}
	return out
}

func compare(subject, claim, measured string, ok bool) Check {
	if ok {
		return Check{Outcome: OutcomePass, Subject: subject, Claim: claim, Measured: measured}
	}
	return Check{Outcome: OutcomeFail, Subject: subject, Claim: claim, Measured: measured}
}

func compareHash(subject, claim, measured string) Check {
	if strings.EqualFold(claim, measured) {
		return Check{Outcome: OutcomePass, Subject: subject, Claim: shortHash(claim), Measured: shortHash(measured)}
	}
	return Check{
		Outcome: OutcomeFail, Subject: subject,
		Claim: shortHash(claim), Measured: shortHash(measured),
		Detail: "the bytes on disk are not the bytes this document describes",
	}
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	return h
}

func formatInt(n int64) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", n)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
