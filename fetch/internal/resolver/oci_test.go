package resolver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// splitReference is small, pure, and the single place a registry port can be
// mistaken for a tag. It had no test at all, which is the sort of gap that
// stays open because the function looks too obvious to break.
func TestSplitReferenceDistinguishesPortsTagsAndDigests(t *testing.T) {
	const digest = "sha256:" + "ab12cd34" + "00000000000000000000000000000000000000000000000000000000"

	for _, tc := range []struct {
		name, ref, repo, tag string
		wantErr              bool
	}{
		{name: "bare name defaults to latest",
			ref: "ghcr.io/org/model", repo: "ghcr.io/org/model", tag: "latest"},
		{name: "explicit tag",
			ref: "ghcr.io/org/model:v1.2.3", repo: "ghcr.io/org/model", tag: "v1.2.3"},
		{name: "digest wins over everything",
			ref: "ghcr.io/org/model@" + digest, repo: "ghcr.io/org/model", tag: digest},
		{name: "tag and digest: the digest is what pins the bytes",
			ref: "ghcr.io/org/model:v1@" + digest, repo: "ghcr.io/org/model:v1", tag: digest},

		// The case the colon rule exists for. A registry on a non-default port
		// puts a colon before the last slash; reading that as a tag would send
		// the pull to a repository that does not exist.
		{name: "registry port is not a tag",
			ref: "localhost:5000/org/model", repo: "localhost:5000/org/model", tag: "latest"},
		{name: "registry port with a tag",
			ref: "localhost:5000/org/model:v2", repo: "localhost:5000/org/model", tag: "v2"},
		{name: "registry port with a digest",
			ref: "localhost:5000/org/model@" + digest, repo: "localhost:5000/org/model", tag: digest},

		{name: "empty", ref: "", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, tag, err := splitReference(tc.ref)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q/%q", repo, tag)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if repo != tc.repo || tag != tc.tag {
				t.Errorf("got %q / %q, want %q / %q", repo, tag, tc.repo, tc.tag)
			}
		})
	}
}

// The two resolvers differ only in the scheme they strip. Getting that wrong
// leaves the scheme inside the reference and the pull fails with a message
// about a repository nobody named.
func TestOCIAndModelCarStripTheirOwnSchemes(t *testing.T) {
	for _, tc := range []struct {
		scheme string
		res    Resolver
	}{
		{"oci", &OCIResolver{}},
		{"modelcar", &ModelCarResolver{}},
	} {
		if got := tc.res.Scheme(); got != tc.scheme {
			t.Errorf("Scheme() = %q, want %q", got, tc.scheme)
		}
		// Resolving an unreachable reference must still fail on the network,
		// not on a malformed reference — proving the scheme was stripped.
		_, err := tc.res.Resolve(t.Context(),
			tc.scheme+"://localhost:1/org/model:v1", t.TempDir())
		if err == nil {
			t.Fatalf("%s: expected a failure against an unreachable registry", tc.scheme)
		}
		if strings.Contains(err.Error(), tc.scheme+"://") {
			t.Errorf("%s: the scheme survived into the reference: %v", tc.scheme, err)
		}
	}
}

// dirSize counts file bytes and ignores directory entries, which is what the
// staged-size figure in a bill of materials depends on.
func TestDirSizeCountsFilesNotDirectories(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "nested", "deeper"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "a.bin"), make([]byte, 100), 0o644)
	os.WriteFile(filepath.Join(root, "nested", "b.bin"), make([]byte, 250), 0o644)
	os.WriteFile(filepath.Join(root, "nested", "deeper", "c.bin"), make([]byte, 7), 0o644)

	got, err := dirSize(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != 357 {
		t.Errorf("dirSize = %d, want 357 (100+250+7, directories excluded)", got)
	}
}

func TestDirSizeOnMissingDirectoryIsAnError(t *testing.T) {
	if _, err := dirSize(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("measuring a directory that does not exist should fail rather than report 0")
	}
}
