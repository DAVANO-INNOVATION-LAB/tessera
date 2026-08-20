package coverage

import (
	"fmt"
	"strings"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

func firstOf(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func hashAlgorithms(f model.FileComponent) string {
	var algs []string
	if f.SHA256 != "" {
		algs = append(algs, "sha-256")
	}
	if f.SHA384 != "" {
		algs = append(algs, "sha-384")
	}
	if f.SHA512 != "" {
		algs = append(algs, "sha-512")
	}
	return strings.Join(algs, ", ")
}

func licenseOf(a *model.Artifact) string {
	for _, l := range a.Licenses {
		if l.SPDXID != "" {
			return l.SPDXID
		}
	}
	for _, l := range a.Licenses {
		if l.Raw != "" {
			return l.Raw
		}
	}
	return ""
}

func architectureOf(a *model.Artifact) string {
	parts := []string{}
	if a.Params.Architecture != "" {
		parts = append(parts, a.Params.Architecture)
	}
	if a.Params.MeasuredParameters > 0 {
		parts = append(parts, fmt.Sprintf("%d parameters", a.Params.MeasuredParameters))
	}
	if a.Params.Quantization != "" {
		parts = append(parts, a.Params.Quantization)
	}
	return strings.Join(parts, ", ")
}

func ioOf(a *model.Artifact) string {
	in, out := inputsOf(a), outputsOf(a)
	if in == "" && out == "" {
		return ""
	}
	return in + " -> " + out
}

func inputsOf(a *model.Artifact) string  { return renderIO(a.Params.Inputs) }
func outputsOf(a *model.Artifact) string { return renderIO(a.Params.Outputs) }

func renderIO(specs []model.IOSpec) string {
	var parts []string
	for _, s := range specs {
		parts = append(parts, s.DType)
	}
	return strings.Join(parts, ", ")
}

func datasetNames(a *model.Artifact) string {
	var names []string
	for _, d := range a.Lineage.Datasets {
		names = append(names, d.Name)
	}
	return strings.Join(names, ", ")
}

func customDomains(a *model.Artifact) string {
	if len(a.Runtime.CustomDomains) > 0 {
		return strings.Join(a.Runtime.CustomDomains, ", ")
	}
	return a.Runtime.Framework
}

func findingSummary(a *model.Artifact) string {
	if len(a.Findings) == 0 {
		return "no findings"
	}
	return fmt.Sprintf("%d finding(s)", len(a.Findings))
}

func integrityStatement(f model.FileComponent) string {
	if f.SHA384 == "" {
		return ""
	}
	return "per-file digests, recomputable"
}

// componentIdentifiers renders the identifiers that can serve as a look-up key
// for this component: the package URL when one can be built, plus any handle
// the artifact disclosed about itself.
func componentIdentifiers(a *model.Artifact) string {
	var parts []string
	if id := firstOf(a.Identity.UUID, a.Identity.RepoURL, a.Identity.URL, a.Identity.DOI); id != "" {
		parts = append(parts, id)
	}
	if sha := a.PrimaryFile().SHA256; sha != "" {
		parts = append(parts, "sha256:"+sha)
	}
	return strings.Join(parts, ", ")
}

// componentRelationships describes how the physical files relate to the model.
// A single-file model has no subcomponents, which is a fact about the artifact
// rather than a missing element, so it is stated rather than left blank.
func componentRelationships(a *model.Artifact) string {
	shards, external := 0, 0
	for _, f := range a.Files {
		switch f.Role {
		case model.RoleShard:
			shards++
		case model.RoleExternalData:
			external++
		}
	}
	switch {
	case shards > 0 && external > 0:
		return fmt.Sprintf("model contains %d shard(s) and %d external data file(s)", shards, external)
	case shards > 0:
		return fmt.Sprintf("model contains %d shard(s)", shards)
	case external > 0:
		return fmt.Sprintf("model contains %d external data file(s)", external)
	case len(a.Files) > 0:
		return "single-file model; no subcomponents"
	}
	return ""
}

// componentCoverage answers the standard's depth question: every physical file
// the model is made of is enumerated, not just the one that was opened.
func componentCoverage(a *model.Artifact) string {
	if len(a.Files) == 0 {
		return ""
	}
	hashed := 0
	for _, f := range a.Files {
		if f.SHA256 != "" {
			hashed++
		}
	}
	return fmt.Sprintf("%d of %d component file(s) enumerated and hashed", hashed, len(a.Files))
}
