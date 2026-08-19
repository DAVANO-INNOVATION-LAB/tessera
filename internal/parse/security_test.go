package parse

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Regression tests for vulnerabilities found in the pre-release adversarial
// review. Each one failed against the code as originally written, and each was
// reproduced with a working proof of concept before being fixed. They are kept
// here so a future refactor that reopens any of them fails loudly rather than
// shipping.

func findingIDs(t *testing.T, path string) []string {
	t.Helper()
	a, err := Parse(context.Background(), path, Options{})
	if err != nil {
		return []string{"ERROR:" + err.Error()}
	}
	var ids []string
	for _, f := range a.Findings {
		ids = append(ids, f.ID)
	}
	return ids
}

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// TestNestedGGUFArrayDoesNotOverflowTheStack covers the worst bug found in
// review. readValue and readArray were mutually recursive with no depth bound,
// and each nesting level cost only twelve bytes of file, so roughly 23 MB of
// crafted metadata produced `fatal error: stack overflow`. That is not a panic
// and recover cannot catch it, so every embedder — the operator, the FFI host,
// the web server — died with it. GGUF has no nested arrays, so the construct is
// now refused outright.
func TestNestedGGUFArrayDoesNotOverflowTheStack(t *testing.T) {
	var b []byte
	put32 := func(v uint32) { var t [4]byte; binary.LittleEndian.PutUint32(t[:], v); b = append(b, t[:]...) }
	put64 := func(v uint64) { var t [8]byte; binary.LittleEndian.PutUint64(t[:], v); b = append(b, t[:]...) }

	b = append(b, "GGUF"...)
	put32(3)
	put64(0) // tensors
	put64(1) // one metadata entry
	put64(4)
	b = append(b, "evil"...)
	put32(uint32(ggArray))
	// 200k levels of array-of-array. Against the old code this was fatal.
	const levels = 200_000
	for i := 0; i < levels; i++ {
		put32(uint32(ggArray))
		put64(1)
	}

	path := filepath.Join(t.TempDir(), "nested.gguf")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}

	done := make(chan []string, 1)
	go func() { done <- findingIDs(t, path) }()

	select {
	case ids := <-done:
		if !contains(ids, "TESS-GGUF-006") {
			t.Errorf("nested array should be reported as TESS-GGUF-006, got %v", ids)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("parsing a nested-array GGUF did not terminate")
	}
	runtime.GC()
}

// TestSafetensorsIndexCannotEscapeTheModelDirectory covers an arbitrary
// host-file read. Shard names came straight out of attacker-controlled JSON and
// were joined to the model directory with no containment check, so a weight_map
// naming ../../../../etc/passwd got that file opened and hashed — turning the
// tool into a SHA-256 oracle for arbitrary host files, reachable from a browser
// through Studio.
func TestSafetensorsIndexCannotEscapeTheModelDirectory(t *testing.T) {
	dir := t.TempDir()
	writeMinimalSafetensors(t, filepath.Join(dir, "model.safetensors"))
	index := `{"weight_map":{"w":"../../../../../../etc/passwd","x":"../../../../../../etc/hosts"}}`
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors.index.json"), []byte(index), 0o644); err != nil {
		t.Fatal(err)
	}

	a, err := Parse(context.Background(), dir, Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, f := range a.Files {
		if strings.Contains(f.Path, "passwd") || strings.Contains(f.Path, "hosts") {
			t.Fatalf("a file outside the model directory was read: %+v", f)
		}
	}
	var escaped bool
	for _, f := range a.Findings {
		if f.ID == "TESS-FILE-003" {
			escaped = true
		}
	}
	if !escaped {
		t.Error("an escaping shard reference should be reported as TESS-FILE-003")
	}
}

// TestSymlinkCannotEscapeTheModelDirectory covers the same containment boundary
// approached differently: the path is entirely local, but it is a symlink whose
// target is not. A lexical check cannot see this, which is why containment is
// decided after resolving symlinks.
func TestSymlinkCannotEscapeTheModelDirectory(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("classified"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	writeMinimalSafetensors(t, filepath.Join(dir, "model.safetensors"))
	if err := os.Symlink(outside, filepath.Join(dir, "shard.safetensors")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	index := `{"weight_map":{"w":"shard.safetensors"}}`
	os.WriteFile(filepath.Join(dir, "model.safetensors.index.json"), []byte(index), 0o644)

	a, err := Parse(context.Background(), dir, Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, f := range a.Files {
		if f.Role == "shard" {
			t.Errorf("a symlink pointing outside the model directory was hashed: %+v", f)
		}
	}
}

// TestNonRegularFilesAreRefused covers a permanent hang. Opening a FIFO blocks
// until a writer appears, and a character device such as /dev/zero hashes until
// the process dies. Neither is a plausible model component, so both are refused
// before the open rather than after.
func TestNonRegularFilesAreRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs on Windows")
	}
	dir := t.TempDir()
	writeMinimalSafetensors(t, filepath.Join(dir, "model.safetensors"))
	fifo := filepath.Join(dir, "shard.safetensors")
	if err := makeFIFO(fifo); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "model.safetensors.index.json"),
		[]byte(`{"weight_map":{"w":"shard.safetensors"}}`), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = Parse(context.Background(), dir, Options{})
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("parsing blocked on a FIFO — non-regular files must be refused before opening")
	}
}

// TestGGUFIndexSortIsNotQuadratic covers a CPU exhaustion path. The index keys
// of lineage entries were ordered with a hand-written insertion sort, so a file
// declaring many base models cost O(n²): 200k entries took roughly 85 seconds,
// and the cap allowed enough to pin a core for over half an hour.
func TestGGUFIndexSortIsNotQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}
	const entries = 60_000

	var b []byte
	put32 := func(v uint32) { var t [4]byte; binary.LittleEndian.PutUint32(t[:], v); b = append(b, t[:]...) }
	put64 := func(v uint64) { var t [8]byte; binary.LittleEndian.PutUint64(t[:], v); b = append(b, t[:]...) }
	str := func(s string) { put64(uint64(len(s))); b = append(b, s...) }

	b = append(b, "GGUF"...)
	put32(3)
	put64(0)
	put64(entries)
	for i := 0; i < entries; i++ {
		str("general.base_model." + strconv.Itoa(i) + ".name")
		put32(uint32(ggString))
		str("m")
	}

	path := filepath.Join(t.TempDir(), "many.gguf")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if _, err := Parse(context.Background(), path, Options{}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Generous: an O(n log n) sort of this input is milliseconds. The old
	// quadratic version needed minutes.
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("parsing %d lineage entries took %s — the index sort looks quadratic again",
			entries, elapsed)
	}
}

func writeMinimalSafetensors(t *testing.T, path string) {
	t.Helper()
	header := []byte(`{"__metadata__":{"format":"pt"}}`)
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(len(header)))
	if err := os.WriteFile(path, append(append(buf, header...), 0, 0, 0, 0), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestContainmentAcceptsRelativeInvocation guards against the containment check
// being too strict rather than too loose. The root is resolved before comparing,
// and an early version resolved it without making it absolute first — so a
// relative invocation compared an absolute candidate against a relative root,
// rejected everything, and reported the model's own primary file as escaping.
// A false Critical on every ordinary run is its own kind of broken.
func TestContainmentAcceptsRelativeInvocation(t *testing.T) {
	dir := t.TempDir()
	writeMinimalSafetensors(t, filepath.Join(dir, "model.safetensors"))

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)
	if err := os.Chdir(filepath.Dir(dir)); err != nil {
		t.Fatal(err)
	}

	rel := filepath.Join(filepath.Base(dir), "model.safetensors")
	a, err := Parse(context.Background(), rel, Options{})
	if err != nil {
		t.Fatalf("Parse(%q): %v", rel, err)
	}
	for _, f := range a.Findings {
		if f.ID == "TESS-FILE-003" {
			t.Errorf("a relative invocation reported its own primary file as escaping: %+v", f)
		}
	}
	if len(a.Files) != 1 || a.Files[0].SHA256 == "" {
		t.Errorf("primary file was not collected: %+v", a.Files)
	}
}

// TestIsTraversalCoversWindowsConventions guards the only gate on the Critical
// external-data finding. Windows binaries are shipped, and a drive-absolute
// path contains no ".." and does not begin with a separator, so a POSIX-only
// check reports C:\Windows\... as perfectly local on the one platform where it
// is not.
func TestIsTraversalCoversWindowsConventions(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"weights.bin", false},
		{"sub/weights.bin", false},
		{"./weights.bin", false},
		{"", false},
		{"../weights.bin", true},
		{"a/../../b", true},
		{"/etc/passwd", true},
		{`..\weights.bin`, true},
		{`C:\Windows\System32\config\SAM`, true},
		{"C:/Windows/System32", true},
		{`c:file.bin`, true},
		{`\\server\share\x`, true},
	}
	for _, c := range cases {
		if got := isTraversal(c.path); got != c.want {
			t.Errorf("isTraversal(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}
