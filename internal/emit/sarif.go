package emit

import (
	"cmp"
	"sort"
	"strings"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// SARIF renders the artifact's findings as a SARIF 2.1.0 log.
//
// This is the third serialization of the same IR, and it answers a different
// question from the other two. CycloneDX and SPDX describe what the model *is*;
// SARIF describes what is *wrong with it*, in the one format code-scanning
// pipelines already ingest. Emitting it means a model artifact can raise an
// annotation on a pull request through the same path source code does, with no
// bespoke integration on the consuming side.
//
// Only findings become results. A SARIF log with no results is a valid log
// reporting a clean scan, which is exactly what should happen when a model has
// nothing wrong with it — an empty file or a missing one would read as a broken
// pipeline instead.
func SARIF(a *model.Artifact, generatedAt time.Time, tool Tool) ([]byte, error) {
	// Rules are derived from the findings actually present rather than from a
	// hand-maintained catalogue. A static catalogue drifts the moment a check is
	// added, and a result whose ruleId has no matching descriptor is dropped by
	// some consumers rather than reported.
	rules := make([]sarifRule, 0, len(a.Findings))
	seen := map[string]bool{}

	findings := append([]model.Finding(nil), a.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		if si, sj := severityRank(findings[i].Severity), severityRank(findings[j].Severity); si != sj {
			return si < sj
		}
		return findings[i].ID < findings[j].ID
	})

	for _, f := range findings {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		rules = append(rules, sarifRule{
			ID:   f.ID,
			Name: ruleName(f.ID),
			ShortDescription: sarifText{
				Text: f.Title,
			},
			FullDescription: sarifText{
				Text: describeWithTaxonomy(f),
			},
			DefaultConfiguration: sarifConfig{Level: sarifLevel(f.Severity)},
			Properties: sarifRuleProps{
				Tags: tagsFor(f),
				// GitHub reads security-severity to place a finding in its
				// own severity bands; without it every result renders as a
				// plain warning regardless of the level.
				SecuritySeverity: securitySeverity(f.Severity),
			},
		})
	}

	primary := a.PrimaryFile()
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		uri := cmp.Or(f.Location, primary.Path, "model")
		results = append(results, sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: cmp.Or(f.Description, f.Title)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: toURI(uri)},
					// SARIF regions are line-oriented and a model file is
					// binary, so no region is emitted. A fabricated line 1
					// would render as a precise claim about a place in the
					// file where nothing was actually read.
				},
			}},
			// The fingerprint is what stops one finding on one artifact from
			// reappearing as a new alert on every run. It is keyed to the
			// content digest rather than the path, so moving or renaming the
			// file does not resurrect a finding a reviewer already dismissed.
			PartialFingerprints: map[string]string{
				"tesseraFindingV1": shortID(primary.SHA256, a.Identity.Name) + ":" + f.ID,
			},
		})
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           tool.Name,
				Version:        tool.Version,
				Organization:   tool.Vendor,
				InformationURI: "https://github.com/DAVANO-INNOVATION-LAB/tessera",
				Rules:          rules,
			}},
			// The scanned artifact is recorded even when nothing was found, so
			// a clean run still states what it looked at.
			Artifacts: []sarifArtifactEntry{{
				Location: sarifArtifact{URI: toURI(cmp.Or(primary.Path, "model"))},
				Hashes:   hashesForSARIF(primary),
			}},
			Invocations: []sarifInvocation{{
				ExecutionSuccessful: true,
				EndTimeUTC:          generatedAt.UTC().Format(time.RFC3339),
			}},
			Results: results,
		}},
	}
	return marshal(log)
}

// sarifLevel maps Tessera's severities onto SARIF's four levels. SARIF has no
// "critical", so critical and high both become errors; the numeric
// security-severity below is what separates them in a consuming UI.
func sarifLevel(severity string) string {
	switch severity {
	case "Critical", "High":
		return "error"
	case "Medium":
		return "warning"
	case "Low":
		return "note"
	}
	return "none"
}

// securitySeverity is the CVSS-like 0-10 number GitHub buckets on: 9.0+ is
// critical, 7.0+ high, 4.0+ medium, below that low.
func securitySeverity(severity string) string {
	switch severity {
	case "Critical":
		return "9.5"
	case "High":
		return "7.5"
	case "Medium":
		return "5.0"
	case "Low":
		return "2.0"
	}
	return "0.0"
}

func severityRank(severity string) int {
	switch severity {
	case "Critical":
		return 0
	case "High":
		return 1
	case "Medium":
		return 2
	case "Low":
		return 3
	}
	return 4
}

// tagsFor gives a consumer something to filter on.
//
// The CWE tag is the important one and the convention is not ours: GitHub code
// scanning, Defender and most SARIF consumers read a tag of the form
// "external/cwe/cwe-502" and render the weakness class from it. Emitting it is
// what turns TESS-PICKLE-001 — meaningless outside this tool — into something a
// security engineer can group, filter and route by on day one.
func tagsFor(f model.Finding) []string {
	tags := []string{"tessera"}
	if c, ok := model.Classify(f.ID); ok {
		if c.CWE != "" {
			tags = append(tags, "external/cwe/cwe-"+c.CWE)
		}
		if c.ATLAS != "" {
			tags = append(tags, "mitre-atlas/"+c.ATLAS)
		}
	}
	if f.Category != "" {
		tags = append(tags, f.Category)
	}
	if f.Category == "drift" {
		tags = append(tags, "supply-chain")
	}
	return tags
}

// ruleName turns TESS-GGUF-010 into TessGguf010: SARIF wants an opaque
// identifier that reads as a name, and some consumers display it directly.
func ruleName(id string) string {
	parts := strings.Split(strings.ToLower(id), "-")
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]))
		b.WriteString(p[1:])
	}
	return b.String()
}

// toURI normalizes a path for the SARIF artifactLocation. Windows separators
// become forward slashes because a SARIF URI is a URI, not a filesystem path.
func toURI(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}

func hashesForSARIF(f model.FileComponent) map[string]string {
	h := map[string]string{}
	if f.SHA256 != "" {
		h["sha256"] = f.SHA256
	}
	if f.SHA384 != "" {
		h["sha384"] = f.SHA384
	}
	if f.SHA512 != "" {
		h["sha512"] = f.SHA512
	}
	if len(h) == 0 {
		return nil
	}
	return h
}

// The SARIF 2.1.0 subset this emitter produces. Written out rather than pulled
// from a library for the same reason the other two emitters are: no dependency,
// and the shape stays visible next to the code that fills it.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool            `json:"tool"`
	Artifacts   []sarifArtifactEntry `json:"artifacts,omitempty"`
	Invocations []sarifInvocation    `json:"invocations,omitempty"`
	Results     []sarifResult        `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	Organization   string      `json:"organization,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name,omitempty"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription,omitempty"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           sarifRuleProps `json:"properties,omitempty"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifArtifactEntry struct {
	Location sarifArtifact     `json:"location"`
	Hashes   map[string]string `json:"hashes,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	EndTimeUTC          string `json:"endTimeUtc,omitempty"`
}

// describeWithTaxonomy appends the weakness class to a finding's description.
//
// A reader who has never met this tool needs one line telling them what class
// of problem they are looking at. Putting it in the description rather than only
// in a tag means it survives into consumers that render text and ignore tags,
// which is most of them.
func describeWithTaxonomy(f model.Finding) string {
	base := cmp.Or(f.Description, f.Title)
	c, ok := model.Classify(f.ID)
	if !ok {
		return base
	}
	var extra []string
	if c.CWE != "" {
		extra = append(extra, "CWE-"+c.CWE+": "+c.CWEName)
	}
	if c.ATLAS != "" {
		extra = append(extra, "MITRE ATLAS "+c.ATLAS+": "+c.ATLASName)
	}
	if len(extra) == 0 {
		return base
	}
	return base + " [" + strings.Join(extra, "; ") + "]"
}
