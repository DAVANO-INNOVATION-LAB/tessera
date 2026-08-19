package emit

import (
	"cmp"
	"net/url"
	"strings"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
)

// A package URL identifies a component the way the rest of the ecosystem
// expects, and the CISA and G7 minimum elements both ask for a unique
// identifier of exactly this kind. Without one, a bill of materials names a
// model but does not let anything correlate it with a registry entry.
//
// The huggingface purl type is finalised: the namespace is the owner, the name
// is the repository, and the version is a commit which must be lowercased.
// Where a model file discloses its own repository URL there is enough to build
// one without asking the operator for anything.

// purlFor derives a package URL from what the artifact disclosed, or returns ""
// when the file gives no basis for one. Guessing is worse than omitting: a purl
// pointing at the wrong repository is a false provenance claim in a document
// whose whole purpose is provenance.
func purlFor(a *model.Artifact) string {
	owner, repo := huggingFaceRepo(cmp.Or(a.Identity.RepoURL, a.Identity.URL))
	if owner == "" || repo == "" {
		return ""
	}
	p := "pkg:huggingface/" + owner + "/" + repo
	if rev := a.Raw["general.source.commit"]; rev != "" {
		p += "@" + strings.ToLower(rev)
	}
	return p
}

// huggingFaceRepo pulls the owner and repository out of a Hugging Face URL.
func huggingFaceRepo(raw string) (owner, repo string) {
	if raw == "" {
		return "", ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}
	host := strings.ToLower(u.Host)
	if host != "huggingface.co" && host != "www.huggingface.co" && host != "hf.co" {
		return "", ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", ""
	}
	return parts[0], parts[1]
}
