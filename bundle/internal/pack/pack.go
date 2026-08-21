// Package pack implements the offline data bundle: a signed, self-describing
// archive of the reference data a scanner needs and cannot look up.
//
// The problem it solves is narrow and specific. Everything Tessera computes
// from a model file is local — parsing, drift, hashing, the walk for executable
// payloads. Three things are not: matching a component against known
// vulnerabilities, matching bytes against malware signatures, and any rule set
// that is updated more often than the binary. Every tool in this space solves
// those by reaching out to a service, which is exactly what an air-gapped
// enclave forbids.
//
// A bundle is how that data crosses the gap. It is one file, it carries a
// manifest describing what is inside and where each part came from, and the
// manifest is signed. The verifier re-derives every digest from the bytes it
// actually received rather than trusting what the manifest claims, because a
// manifest that is only read is a table of contents, not evidence.
//
// The format is deliberately dull: a tar archive, gzip-compressed, with the
// manifest first. A dull format can be inspected with tools the enclave already
// has when this program is unavailable, which is a real consideration on the
// far side of an air gap.
package pack

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ManifestName is the entry every bundle carries first.
const ManifestName = "tessera-bundle.json"

// FormatVersion guards the bundle format itself. A reader that does not
// recognize the version refuses rather than guessing, because guessing at the
// layout of a signed archive is how a downgrade begins.
const FormatVersion = 1

// Kind names what a bundle carries. It is advisory — the manifest lists the
// actual entries — but a consumer that wanted a vulnerability database and
// received a rule pack should be able to say so before unpacking anything.
type Kind string

const (
	KindVulnerability Kind = "vulnerability-database"
	KindMalware       Kind = "malware-signatures"
	KindRules         Kind = "rule-pack"
	KindMixed         Kind = "mixed"
)

// Entry is one file in the bundle.
type Entry struct {
	// Path is the entry's location inside the bundle, always slash-separated
	// and always relative.
	Path string `json:"path"`
	Size int64  `json:"size"`
	// SHA256 is what the surrounding ecosystem reads. SHA512 is what BSI
	// TR-03183-2 requires. Both are recorded, computed in one pass, because a
	// bundle carrying only one of them is unusable to somebody who needs the
	// other and there is no way to add it later without the original bytes.
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
}

// Source records where the data in a bundle came from, so somebody on the far
// side of an air gap can tell what they are trusting.
//
// This is the field that makes a bundle auditable rather than merely portable.
// A vulnerability database is a claim about the world, and a claim with no
// stated origin and no date is not one a reviewer can act on — it could be
// today's feed or three years stale, and the bytes look identical.
type Source struct {
	// Name identifies the upstream data set, e.g. "osv.dev" or "clamav-main".
	Name string `json:"name"`
	// URL is where it was obtained, when there is one.
	URL string `json:"url,omitempty"`
	// Version is the upstream's own version or snapshot identifier.
	Version string `json:"version,omitempty"`
	// RetrievedAt is when it was fetched. Required: a data bundle without a
	// retrieval date cannot be assessed for staleness, which is the first
	// question anybody sensible asks of one.
	RetrievedAt string `json:"retrievedAt"`
}

// Manifest describes a bundle. It is the signed object: signing the manifest
// rather than the archive means verification needs one signature regardless of
// how many files are inside, and the per-entry digests below extend that
// signature to cover every one of them.
type Manifest struct {
	FormatVersion int    `json:"formatVersion"`
	Kind          Kind   `json:"kind"`
	Name          string `json:"name"`
	Version       string `json:"version,omitempty"`
	Description   string `json:"description,omitempty"`
	// CreatedAt is when the bundle was assembled, distinct from when its
	// contents were retrieved.
	CreatedAt string   `json:"createdAt"`
	Sources   []Source `json:"sources,omitempty"`
	Entries   []Entry  `json:"entries"`
}

// TotalSize is the sum of the entries' sizes.
func (m *Manifest) TotalSize() int64 {
	var n int64
	for _, e := range m.Entries {
		n += e.Size
	}
	return n
}

// Create writes a bundle containing the files under root.
//
// Entry order is sorted so the same inputs produce the same archive: a bundle
// that differed run to run could not be compared against a previously approved
// one, and comparing is most of what a reviewer on the far side of a gap can do.
func Create(root string, meta Manifest, out io.Writer) (*Manifest, error) {
	root = filepath.Clean(root)
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("bundle source: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("bundle source %s is not a directory", root)
	}

	files, err := collect(root)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("bundle source %s contains no files", root)
	}

	manifest := meta
	manifest.FormatVersion = FormatVersion
	if manifest.CreatedAt == "" {
		return nil, fmt.Errorf("bundle manifest needs a creation time")
	}
	if manifest.Name == "" {
		return nil, fmt.Errorf("bundle manifest needs a name")
	}
	if manifest.Kind == "" {
		manifest.Kind = KindMixed
	}
	for _, s := range manifest.Sources {
		if s.RetrievedAt == "" {
			return nil, fmt.Errorf("source %q has no retrieval date; "+
				"a data bundle whose age cannot be established is not reviewable", s.Name)
		}
	}

	manifest.Entries = nil
	for _, rel := range files {
		e, err := describe(root, rel)
		if err != nil {
			return nil, err
		}
		manifest.Entries = append(manifest.Entries, e)
	}

	body, err := json.MarshalIndent(&manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	body = append(body, '\n')

	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)

	// The manifest goes first so a reader can learn what the archive holds
	// without buffering the whole thing — which matters when the whole thing is
	// a multi-gigabyte vulnerability database.
	if err := writeEntry(tw, ManifestName, body, manifest.CreatedAt); err != nil {
		return nil, err
	}
	for _, rel := range files {
		if err := copyEntry(tw, root, rel, manifest.CreatedAt); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// Verify reads a bundle and re-derives every digest from the bytes actually
// present, returning the manifest only if all of them agree.
//
// The manifest is not trusted to describe itself. An entry whose recorded
// digest does not match the bytes is a failure, and so is an entry present in
// the archive that the manifest never mentions — an undocumented file is the
// shape a smuggled payload takes, and a verifier that only checked the listed
// entries would walk straight past it.
func Verify(r io.Reader) (*Manifest, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("bundle is not gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var manifest *Manifest
	seen := map[string]bool{}

	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			// Directories, symlinks and devices have no business in a data
			// bundle, and a symlink is the classic way out of an extraction
			// root. Refused rather than skipped: skipping would let a bundle
			// carry something the manifest never accounted for.
			if h.Typeflag == tar.TypeDir {
				continue
			}
			return nil, fmt.Errorf("bundle entry %q is not a regular file", h.Name)
		}
		name := path.Clean(h.Name)
		if err := safeName(name); err != nil {
			return nil, err
		}

		if name == ManifestName {
			body, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			var m Manifest
			if err := json.Unmarshal(body, &m); err != nil {
				return nil, fmt.Errorf("bundle manifest: %w", err)
			}
			if m.FormatVersion != FormatVersion {
				return nil, fmt.Errorf(
					"bundle format version %d is not supported (this build reads %d)",
					m.FormatVersion, FormatVersion)
			}
			manifest = &m
			continue
		}

		if manifest == nil {
			return nil, fmt.Errorf("bundle entry %q precedes the manifest", name)
		}
		want, ok := lookup(manifest, name)
		if !ok {
			return nil, fmt.Errorf(
				"bundle contains %q, which the manifest does not list", name)
		}
		s256, s512, n, err := digest(tr)
		if err != nil {
			return nil, err
		}
		if n != want.Size {
			return nil, fmt.Errorf("bundle entry %q is %d bytes, manifest says %d",
				name, n, want.Size)
		}
		if s256 != want.SHA256 || s512 != want.SHA512 {
			return nil, fmt.Errorf("bundle entry %q does not match its recorded digest", name)
		}
		seen[name] = true
	}

	if manifest == nil {
		return nil, fmt.Errorf("bundle has no %s", ManifestName)
	}
	var missing []string
	for _, e := range manifest.Entries {
		if !seen[e.Path] {
			missing = append(missing, e.Path)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("bundle is missing %d listed entr(y/ies): %s",
			len(missing), strings.Join(missing, ", "))
	}
	return manifest, nil
}

// Extract verifies a bundle and writes its contents under dest.
//
// Verification happens first and completely. Writing files as they are read
// would leave a partially unpacked, partially verified tree on disk when an
// entry fails, and something downstream would eventually read it.
func Extract(r io.ReadSeeker, dest string) (*Manifest, error) {
	manifest, err := Verify(r)
	if err != nil {
		return nil, err
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("bundle rewind: %w", err)
	}

	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	dest = filepath.Clean(dest)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, err
	}

	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(h.Name)
		if name == ManifestName {
			continue
		}
		if err := safeName(name); err != nil {
			return nil, err
		}
		target := filepath.Join(dest, filepath.FromSlash(name))
		// Belt and braces: safeName already refuses traversal, but the check
		// that matters is the one against the resolved path, because that is
		// the value the write actually uses.
		if !strings.HasPrefix(target, dest+string(os.PathSeparator)) {
			return nil, fmt.Errorf("bundle entry %q escapes the destination", name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	}
	return manifest, nil
}

func lookup(m *Manifest, name string) (Entry, bool) {
	for _, e := range m.Entries {
		if e.Path == name {
			return e, true
		}
	}
	return Entry{}, false
}

// safeName refuses anything that is not a plain relative path inside the
// bundle. Absolute paths and parent traversal are the two ways an archive
// writes outside where it was told to.
func safeName(name string) error {
	if name == "" || name == "." {
		return fmt.Errorf("bundle entry has an empty name")
	}
	if path.IsAbs(name) || strings.HasPrefix(name, "/") {
		return fmt.Errorf("bundle entry %q is an absolute path", name)
	}
	if name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
		return fmt.Errorf("bundle entry %q traverses outside the bundle", name)
	}
	if strings.ContainsRune(name, '\\') {
		return fmt.Errorf("bundle entry %q contains a backslash; paths are slash-separated", name)
	}
	return nil
}

func collect(root string) ([]string, error) {
	var out []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			// A symlink in the source would be followed or copied as a link,
			// and neither is a thing a data bundle should carry.
			return fmt.Errorf("%s is not a regular file", p)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func describe(root, rel string) (Entry, error) {
	f, err := os.Open(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	s256, s512, n, err := digest(f)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Path: rel, Size: n, SHA256: s256, SHA512: s512}, nil
}

// digest computes both hashes in one pass over the reader. Two passes over a
// multi-gigabyte database is not a rounding error.
func digest(r io.Reader) (sha256hex, sha512hex string, n int64, err error) {
	h256 := sha256.New()
	h512 := sha512.New()
	n, err = io.Copy(io.MultiWriter(h256, h512), r)
	if err != nil {
		return "", "", 0, err
	}
	return hex.EncodeToString(h256.Sum(nil)), hex.EncodeToString(h512.Sum(nil)), n, nil
}

func writeEntry(tw *tar.Writer, name string, body []byte, at string) error {
	mod, err := time.Parse(time.RFC3339, at)
	if err != nil {
		mod = time.Unix(0, 0).UTC()
	}
	h := &tar.Header{
		Name: name, Mode: 0o644, Size: int64(len(body)),
		ModTime: mod, Typeflag: tar.TypeReg, Format: tar.FormatPAX,
	}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	_, err = tw.Write(body)
	return err
}

func copyEntry(tw *tar.Writer, root, rel, at string) error {
	full := filepath.Join(root, filepath.FromSlash(rel))
	info, err := os.Stat(full)
	if err != nil {
		return err
	}
	mod, err := time.Parse(time.RFC3339, at)
	if err != nil {
		mod = time.Unix(0, 0).UTC()
	}
	h := &tar.Header{
		Name: rel, Mode: 0o644, Size: info.Size(),
		ModTime: mod, Typeflag: tar.TypeReg, Format: tar.FormatPAX,
	}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	f, err := os.Open(full)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}
