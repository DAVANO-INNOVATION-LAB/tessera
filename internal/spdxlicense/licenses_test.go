package spdxlicense

import "testing"

func TestResolve(t *testing.T) {
	cases := []struct {
		raw     string
		wantID  string
		wantCnf string
	}{
		{"Apache-2.0", "Apache-2.0", "exact"},
		{"apache 2.0", "Apache-2.0", "normalized"},
		{"MIT", "MIT", "exact"},
		{"mit license", "MIT", "normalized"},
		{"bsd-3-clause", "BSD-3-Clause", "exact"}, // case-insensitively equals the SPDX id
		{"bsd 3-clause", "BSD-3-Clause", "normalized"},
		{"llama3", "LicenseRef-Llama-3", "model"},
		{"gemma", "LicenseRef-Gemma", "model"},
		{"some-bespoke-eula", "LicenseRef-some-bespoke-eula", "none"},
		{"", "", "none"},
	}
	for _, c := range cases {
		id, conf := Resolve(c.raw)
		if id != c.wantID || conf != c.wantCnf {
			t.Errorf("Resolve(%q) = (%q,%q), want (%q,%q)", c.raw, id, conf, c.wantID, c.wantCnf)
		}
	}
}

func TestResolveNeverEmptyForNonEmptyInput(t *testing.T) {
	id, _ := Resolve("©️ weird / spacing _ thing")
	if id == "" {
		t.Fatalf("resolver dropped a non-empty license")
	}
	if id[:11] != "LicenseRef-" {
		t.Errorf("unrecognized license should be a LicenseRef-, got %q", id)
	}
}
