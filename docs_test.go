package tessera_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var findingID = regexp.MustCompile(`TESS-[A-Z]+-[0-9]+`)

// TestEveryFindingIsDocumented keeps the README's finding table honest.
//
// For a security tool the finding table is an interface: anyone integrating it
// needs the complete set to write suppressions, and an undocumented ID shows up
// in their pipeline as an unexplained failure. Documentation drifts silently
// from code unless something checks, so this checks.
func TestEveryFindingIsDocumented(t *testing.T) {
	emitted := map[string]bool{}
	err := filepath.Walk("internal", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		// Only quoted identifiers are findings actually emitted; a bare mention
		// in a comment is prose.
		for _, m := range regexp.MustCompile(`"(TESS-[A-Z]+-[0-9]+)"`).FindAllStringSubmatch(string(data), -1) {
			emitted[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(emitted) == 0 {
		t.Fatal("no finding IDs found in internal/ — this test is not looking where it thinks it is")
	}

	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, id := range findingID.FindAllString(string(readme), -1) {
		documented[id] = true
	}

	var undocumented, phantom []string
	for id := range emitted {
		if !documented[id] {
			undocumented = append(undocumented, id)
		}
	}
	for id := range documented {
		if !emitted[id] {
			phantom = append(phantom, id)
		}
	}
	sort.Strings(undocumented)
	sort.Strings(phantom)

	if len(undocumented) > 0 {
		t.Errorf("emitted but not documented in README.md: %v", undocumented)
	}
	if len(phantom) > 0 {
		t.Errorf("documented in README.md but never emitted: %v", phantom)
	}
}
