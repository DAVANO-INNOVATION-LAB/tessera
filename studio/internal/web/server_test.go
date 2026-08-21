package web

import (
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestServer builds a server over a temporary directory holding one real
// safetensors model plus a subdirectory.
func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	root := t.TempDir()
	writeModel(t, filepath.Join(root, "model.safetensors"))
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".hidden"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return &Server{Root: root, Version: "test"}, root
}

func writeModel(t *testing.T, path string) {
	t.Helper()
	header := []byte(`{"__metadata__":{"format":"pt","license":"mit"},` +
		`"w":{"dtype":"F16","shape":[2,2],"data_offsets":[0,8]}}`)
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(len(header)))
	body := append(append(buf, header...), make([]byte, 8)...)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// get issues a request with a loopback Host, which the host check requires.
func get(t *testing.T, s *Server, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = "127.0.0.1:7777"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// --- resolve: the security-critical one ---

func TestResolveConfinesToRoot(t *testing.T) {
	s, root := newTestServer(t)

	allowed := []string{"", ".", "sub", "model.safetensors", "sub/../model.safetensors", "./notes.txt"}
	for _, in := range allowed {
		got, err := s.resolve(in)
		if err != nil {
			t.Errorf("resolve(%q) rejected a path inside the root: %v", in, err)
			continue
		}
		rootReal, _ := filepath.EvalSymlinks(root)
		if got != rootReal && !strings.HasPrefix(got, rootReal+string(filepath.Separator)) {
			t.Errorf("resolve(%q) = %q, which is outside %q", in, got, rootReal)
		}
	}

	refused := []string{
		"../", "../..", "../../etc/passwd",
		"sub/../../etc/passwd",
		"/etc/passwd", "/",
		"sub/../../../../../../etc/hosts",
	}
	for _, in := range refused {
		if got, err := s.resolve(in); err == nil {
			rootReal, _ := filepath.EvalSymlinks(root)
			if !strings.HasPrefix(got, rootReal) {
				t.Errorf("resolve(%q) = %q escaped the root", in, got)
			}
		}
	}
}

func TestResolveRefusesSymlinkEscape(t *testing.T) {
	s, root := newTestServer(t)

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("classified"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	// A purely lexical check passes this; only symlink resolution catches it.
	if got, err := s.resolve("escape"); err == nil {
		t.Errorf("resolve(\"escape\") = %q — a symlink out of the root must be refused", got)
	}
	if got, err := s.resolve("escape/secret.txt"); err == nil {
		t.Errorf("resolve through a symlink returned %q", got)
	}
}

// --- host checking (DNS rebinding) ---

func TestNonLoopbackHostIsRejected(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/browse", nil)
	req.Host = "evil.example.com"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Host evil.example.com got %d, want 403 — loopback binding alone does not "+
			"stop a rebound hostname from reading these endpoints", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "entries") {
		t.Error("a rebound host received a directory listing")
	}
}

func TestLoopbackHostsAreAccepted(t *testing.T) {
	s, _ := newTestServer(t)
	for _, host := range []string{"127.0.0.1:7777", "localhost:7777", "[::1]:7777"} {
		req := httptest.NewRequest(http.MethodGet, "/api/browse", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Host %q got %d, want 200", host, rec.Code)
		}
	}
}

// --- browse ---

func TestBrowseListsModelsAndHidesDotfiles(t *testing.T) {
	s, _ := newTestServer(t)
	rec := get(t, s, "/api/browse?path=")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var out struct {
		Path    string `json:"path"`
		Entries []struct {
			Name, Path, Format string
			IsDir              bool `json:"isDir"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}

	var sawModel, sawDir bool
	for _, e := range out.Entries {
		if strings.HasPrefix(e.Name, ".") {
			t.Errorf("dotfile %q was listed", e.Name)
		}
		if e.Name == "model.safetensors" {
			sawModel = true
			if e.Format != "safetensors" {
				t.Errorf("model format = %q", e.Format)
			}
		}
		if e.Name == "notes.txt" && e.Format != "" {
			t.Errorf("non-model %q was given format %q", e.Name, e.Format)
		}
		if e.Name == "sub" {
			sawDir = true
			if !e.IsDir {
				t.Error("sub should be a directory")
			}
		}
	}
	if !sawModel || !sawDir {
		t.Errorf("listing incomplete: model=%v dir=%v", sawModel, sawDir)
	}
	// Directories sort before files.
	if len(out.Entries) > 1 && !out.Entries[0].IsDir {
		t.Error("directories should be listed first")
	}
}

func TestBrowseRejectsEscapingPath(t *testing.T) {
	s, _ := newTestServer(t)
	rec := get(t, s, "/api/browse?path=%2Fetc")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", rec.Code)
	}
}

// --- analyze ---

func TestAnalyzeReturnsArtifactAndVerdict(t *testing.T) {
	s, _ := newTestServer(t)
	rec := get(t, s, "/api/analyze?path=model.safetensors")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Artifact struct {
			Format   string `json:"format"`
			Licenses []struct {
				SPDXID string `json:"spdxID"`
			} `json:"licenses"`
			Files []struct {
				SHA256 string `json:"sha256"`
			} `json:"files"`
		} `json:"artifact"`
		Worst string `json:"worst"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Artifact.Format != "safetensors" {
		t.Errorf("format = %q", out.Artifact.Format)
	}
	if len(out.Artifact.Licenses) == 0 || out.Artifact.Licenses[0].SPDXID != "MIT" {
		t.Errorf("licence not resolved: %+v", out.Artifact.Licenses)
	}
	if len(out.Artifact.Files) == 0 || out.Artifact.Files[0].SHA256 == "" {
		t.Error("no hashed file in the artifact")
	}
}

func TestAnalyzeRejectsNonModel(t *testing.T) {
	s, _ := newTestServer(t)
	rec := get(t, s, "/api/analyze?path=notes.txt")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status %d, want 422", rec.Code)
	}
}

// TestErrorsDoNotLeakHostPaths pins that failures describe the category and not
// the filesystem: the absolute path would disclose the host's username and
// directory layout to anything that can reach the port.
func TestErrorsDoNotLeakHostPaths(t *testing.T) {
	s, root := newTestServer(t)
	for _, target := range []string{
		"/api/analyze?path=missing.gguf",
		"/api/browse?path=missing",
		"/api/bom?path=missing.gguf",
	} {
		rec := get(t, s, target)
		body := rec.Body.String()
		if strings.Contains(body, root) || strings.Contains(body, "/Users/") || strings.Contains(body, "/home/") {
			t.Errorf("%s leaked a host path: %s", target, body)
		}
	}
}

// --- bom ---

func TestBOMDownloadsAndIsReproducible(t *testing.T) {
	s, _ := newTestServer(t)

	for _, tc := range []struct{ format, wantExt string }{
		{"", ".cdx.json"},
		{"cyclonedx", ".cdx.json"},
		{"spdx", ".spdx.json"},
	} {
		rec := get(t, s, "/api/bom?format="+tc.format+"&path=model.safetensors")
		if rec.Code != http.StatusOK {
			t.Fatalf("format %q: status %d", tc.format, rec.Code)
		}
		cd := rec.Header().Get("Content-Disposition")
		if !strings.Contains(cd, tc.wantExt) {
			t.Errorf("format %q: Content-Disposition %q lacks %q", tc.format, cd, tc.wantExt)
		}
		if strings.ContainsAny(cd, "\r\n") {
			t.Errorf("Content-Disposition contains a newline: %q", cd)
		}
		var doc map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Errorf("format %q: body is not valid JSON: %v", tc.format, err)
		}
	}

	// The README promises reproducible downloads; pin it.
	first := get(t, s, "/api/bom?path=model.safetensors").Body.String()
	second := get(t, s, "/api/bom?path=model.safetensors").Body.String()
	if first != second {
		t.Error("two downloads of the same model differ — the BOM is not reproducible")
	}
}

// --- headers and index ---

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	s, _ := newTestServer(t)
	for _, target := range []string{"/", "/api/browse", "/api/analyze?path=missing.gguf"} {
		rec := get(t, s, target)
		csp := rec.Header().Get("Content-Security-Policy")
		for _, directive := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, directive) {
				t.Errorf("%s: CSP missing %q (got %q)", target, directive, csp)
			}
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing nosniff", target)
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: missing X-Frame-Options", target)
		}
	}
}

func TestIndexServesTheEmbeddedUI(t *testing.T) {
	s, _ := newTestServer(t)
	rec := get(t, s, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content type = %q", ct)
	}
	body := rec.Body.String()
	if len(body) < 1000 || !strings.Contains(body, "Tessera Studio") {
		t.Error("the embedded UI looks empty or wrong")
	}

	if got := get(t, s, "/nope").Code; got != http.StatusNotFound {
		t.Errorf("/nope returned %d, want 404", got)
	}
}
