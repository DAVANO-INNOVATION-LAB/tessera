package emit

import (
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

func TestPurlDerivation(t *testing.T) {
	cases := []struct {
		name, repoURL, want string
	}{
		{"huggingface url", "https://huggingface.co/meta-llama/Meta-Llama-3-8B",
			"pkg:huggingface/meta-llama/Meta-Llama-3-8B"},
		{"hf.co short form", "https://hf.co/owner/repo", "pkg:huggingface/owner/repo"},
		{"trailing path is ignored", "https://huggingface.co/owner/repo/tree/main",
			"pkg:huggingface/owner/repo"},
		// Guessing is worse than omitting: a purl pointing at the wrong
		// repository is a false provenance claim in a provenance document.
		{"unrelated host", "https://example.com/owner/repo", ""},
		{"not a url", "just some text", ""},
		{"empty", "", ""},
		{"owner only", "https://huggingface.co/owner", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := &model.Artifact{Identity: model.Identity{RepoURL: c.repoURL}}
			if got := purlFor(a); got != c.want {
				t.Errorf("purlFor(%q) = %q, want %q", c.repoURL, got, c.want)
			}
		})
	}
}

func TestPurlPinsCommitWhenDisclosed(t *testing.T) {
	a := &model.Artifact{
		Identity: model.Identity{RepoURL: "https://huggingface.co/owner/repo"},
		Raw:      map[string]string{"general.source.commit": "ABCDEF1234"},
	}
	// The huggingface purl type requires a lowercased commit.
	if got, want := purlFor(a), "pkg:huggingface/owner/repo@abcdef1234"; got != want {
		t.Errorf("purlFor = %q, want %q", got, want)
	}
}
