// Package spdxlicense resolves a raw license string read from a model file to
// an SPDX license identifier. The G7/CISA "SBOM for AI — Minimum Elements"
// Models cluster asks that the model license point at the SPDX/CycloneDX
// license fields, so a raw "apache 2.0" out of a GGUF header has to become a
// canonical "Apache-2.0" for the BOM to satisfy that element.
//
// This is a pragmatic resolver, not the full SPDX license list: it covers the
// identifiers that actually appear in model metadata plus the common informal
// spellings, and it is honest about confidence. Model-specific licenses with no
// SPDX identifier (Llama, Gemma, RAIL, ...) resolve to a LicenseRef-*, which is
// the SPDX-sanctioned way to name a license that is not on the list.
package spdxlicense

import "strings"

// canonical maps a normalized key to its exact SPDX identifier.
var canonical = map[string]string{
	"apache-2.0": "Apache-2.0", "apache 2.0": "Apache-2.0", "apache2": "Apache-2.0",
	"apache2.0": "Apache-2.0", "apache license 2.0": "Apache-2.0", "asl 2.0": "Apache-2.0",
	"mit": "MIT", "mit license": "MIT",
	"bsd-3-clause": "BSD-3-Clause", "bsd 3-clause": "BSD-3-Clause", "bsd3": "BSD-3-Clause",
	"bsd-2-clause": "BSD-2-Clause", "bsd 2-clause": "BSD-2-Clause",
	"gpl-3.0": "GPL-3.0-only", "gplv3": "GPL-3.0-only", "gpl3": "GPL-3.0-only",
	"gpl-2.0": "GPL-2.0-only", "gplv2": "GPL-2.0-only",
	"lgpl-3.0": "LGPL-3.0-only", "agpl-3.0": "AGPL-3.0-only", "agplv3": "AGPL-3.0-only",
	"mpl-2.0": "MPL-2.0", "mozilla public license 2.0": "MPL-2.0",
	"unlicense": "Unlicense", "the unlicense": "Unlicense",
	"cc0-1.0": "CC0-1.0", "cc0": "CC0-1.0",
	"cc-by-4.0": "CC-BY-4.0", "cc by 4.0": "CC-BY-4.0",
	"cc-by-sa-4.0": "CC-BY-SA-4.0", "cc by-sa 4.0": "CC-BY-SA-4.0",
	"cc-by-nc-4.0": "CC-BY-NC-4.0", "cc-by-nc-sa-4.0": "CC-BY-NC-SA-4.0",
	"cc-by-nd-4.0": "CC-BY-ND-4.0",
	"openrail":     "LicenseRef-OpenRAIL", "bigscience-openrail-m": "LicenseRef-OpenRAIL-M",
	"artistic-2.0": "Artistic-2.0", "isc": "ISC", "zlib": "Zlib",
	"epl-2.0": "EPL-2.0", "wtfpl": "WTFPL",
}

// modelSpecific maps normalized keys of well-known non-SPDX model licenses to a
// stable LicenseRef- identifier, so lineage across the ecosystem stays legible.
var modelSpecific = map[string]string{
	"llama2": "LicenseRef-Llama-2", "llama-2": "LicenseRef-Llama-2",
	"llama3": "LicenseRef-Llama-3", "llama-3": "LicenseRef-Llama-3",
	"llama3.1": "LicenseRef-Llama-3.1", "llama-3.1": "LicenseRef-Llama-3.1",
	"llama3.2": "LicenseRef-Llama-3.2", "llama3.3": "LicenseRef-Llama-3.3",
	"gemma": "LicenseRef-Gemma", "gemma-terms-of-use": "LicenseRef-Gemma",
	"qwen": "LicenseRef-Qwen", "tongyi-qianwen": "LicenseRef-Qwen",
	"deepseek":              "LicenseRef-DeepSeek",
	"falcon-llm-license":    "LicenseRef-Falcon",
	"stabilityai-community": "LicenseRef-StabilityAI-Community",
	"rail":                  "LicenseRef-RAIL",
}

// Resolve maps a raw license string to (spdxID, confidence). Confidence is:
//
//	"exact"      the raw string is already a valid SPDX identifier
//	"normalized" it matched after lowercasing/spacing normalization or alias
//	"model"      it is a known non-SPDX model license, mapped to a LicenseRef-
//	"none"       nothing matched; a LicenseRef- is synthesized from the raw text
//
// It never returns an empty id for a non-empty input: an unrecognized license
// still becomes a LicenseRef-, because dropping it would understate what the
// file disclosed.
func Resolve(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "none"
	}

	key := normalize(raw)

	// Already a canonical SPDX id (case-insensitive match on the value set).
	for _, id := range canonical {
		if strings.EqualFold(raw, id) {
			return id, "exact"
		}
	}
	if id, ok := canonical[key]; ok {
		return id, "normalized"
	}
	if id, ok := modelSpecific[key]; ok {
		return id, "model"
	}

	// Unknown: synthesize a LicenseRef- from the raw text so it is still named.
	return "LicenseRef-" + sanitizeRef(raw), "none"
}

func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "spdx:")
	s = strings.TrimPrefix(s, "license: ")
	return s
}

// sanitizeRef makes a raw license string safe to use as the idstring of a
// LicenseRef-, which SPDX restricts to letters, digits, '.', and '-'.
func sanitizeRef(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		case r == ' ' || r == '_' || r == '/':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}
