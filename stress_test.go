package tessera_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	tessera "github.com/DAVANO-INNOVATION-LAB/tessera"
)

// Stress tests. The criteria here are resource criteria, not correctness ones:
// a hostile artifact must not be able to decide how much memory this process
// allocates, how long it runs, or whether it stays alive. Each test states the
// bound it enforces, because a bound nobody asserts is a bound that drifts.

const (
	// stressMemBudget is the extra heap a single hostile file may cause. The
	// real files under test are kilobytes; anything approaching this means a
	// length field was believed.
	stressMemBudget = 256 << 20 // 256 MiB
	// stressTimeBudget is how long any single analysis may take.
	stressTimeBudget = 10 * time.Second
)

// hostileGGUF builds a GGUF header that lies about its contents in the ways the
// format's CVE history says attackers actually lie.
func hostileGGUF(kind string) []byte {
	var b []byte
	put64 := func(v uint64) { var t [8]byte; binary.LittleEndian.PutUint64(t[:], v); b = append(b, t[:]...) }
	put32 := func(v uint32) { var t [4]byte; binary.LittleEndian.PutUint32(t[:], v); b = append(b, t[:]...) }
	str := func(s string) { put64(uint64(len(s))); b = append(b, s...) }

	b = append(b, "GGUF"...)
	put32(3)

	switch kind {
	case "huge-tensor-count":
		put64(^uint64(0)) // 2^64-1 tensors
		put64(0)
	case "huge-kv-count":
		put64(0)
		put64(^uint64(0)) // 2^64-1 metadata entries
	case "huge-string-len":
		put64(0)
		put64(1)
		put64(^uint64(0) - 8) // a key whose length is near the whole address space
	case "huge-array-count":
		put64(0)
		put64(1)
		str("evil")
		put32(9)          // ARRAY
		put32(8)          // of STRING
		put64(^uint64(0)) // with 2^64-1 elements
	case "huge-alignment":
		put64(0)
		put64(1)
		str("general.alignment")
		put32(4) // UINT32
		put32(^uint32(0))
	case "huge-tensor-dims":
		put64(1)
		put64(0)
		str("t")
		put32(^uint32(0)) // dimension count
	case "truncated":
		put64(5)
		put64(5)
		// and then nothing at all
	}
	return b
}

func TestStressHostileGGUFStaysBounded(t *testing.T) {
	kinds := []string{
		"huge-tensor-count", "huge-kv-count", "huge-string-len",
		"huge-array-count", "huge-alignment", "huge-tensor-dims", "truncated",
	}

	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "hostile.gguf")
			if err := os.WriteFile(p, hostileGGUF(kind), 0o644); err != nil {
				t.Fatal(err)
			}

			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)

			start := time.Now()
			done := make(chan struct{})
			go func() {
				defer close(done)
				// A panic here fails the test by crashing it, which is the
				// correct outcome to surface loudly.
				_, _ = tessera.Analyze(context.Background(), p)
			}()

			select {
			case <-done:
			case <-time.After(stressTimeBudget):
				t.Fatalf("analysis exceeded %s on %q — a hostile header stalled the parser",
					stressTimeBudget, kind)
			}
			elapsed := time.Since(start)

			runtime.ReadMemStats(&after)
			grew := int64(after.TotalAlloc - before.TotalAlloc)
			if grew > stressMemBudget {
				t.Errorf("%q allocated %d bytes (budget %d) — a declared length was believed",
					kind, grew, stressMemBudget)
			}
			t.Logf("%-20s %8s  alloc %d KiB", kind, elapsed.Round(time.Microsecond), grew>>10)
		})
	}
}

func TestStressProtobufBomb(t *testing.T) {
	// Deeply nested length-delimited submessages: the classic protobuf
	// exhaustion shape. The walker's depth guard is what has to hold.
	depth := 5000
	payload := []byte{}
	for i := 0; i < depth && len(payload) < 1<<20; i++ {
		inner := payload
		payload = append([]byte{0x3a}, appendUvarint(nil, uint64(len(inner)))...)
		payload = append(payload, inner...)
	}

	p := filepath.Join(t.TempDir(), "bomb.onnx")
	if err := os.WriteFile(p, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = tessera.Analyze(context.Background(), p) }()

	select {
	case <-done:
		t.Logf("nested depth %d handled in %s", depth, time.Since(start).Round(time.Millisecond))
	case <-time.After(stressTimeBudget):
		t.Fatalf("protobuf bomb stalled the parser past %s", stressTimeBudget)
	}
}

func appendUvarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func TestStressZeroAndTinyFiles(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]byte{
		"empty.gguf":        {},
		"one.gguf":          {'G'},
		"magic.gguf":        []byte("GGUF"),
		"empty.safetensors": {},
		"short.safetensors": {1, 2, 3},
		"empty.onnx":        {},
		"garbage.onnx":      {0xff, 0xff, 0xff},
	}
	for name, data := range cases {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		// Must return, must not panic. Error or findings are both acceptable.
		_, _ = tessera.Analyze(context.Background(), p)
	}
}

func TestStressConcurrentAnalyses(t *testing.T) {
	// The library is meant to be embedded in a service that may analyse many
	// artifacts at once. Run under -race to make a shared-state bug visible.
	dir := t.TempDir()
	paths := make([]string, 0, 8)
	for i, kind := range []string{"huge-kv-count", "huge-alignment", "truncated", "huge-array-count"} {
		p := filepath.Join(dir, fmt.Sprintf("m%d.gguf", i))
		os.WriteFile(p, hostileGGUF(kind), 0o644)
		paths = append(paths, p)
	}
	paths = append(paths, writeSafetensors(t, dir, map[string]string{"format": "pt", "license": "mit"}))

	const workers = 32
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = tessera.Analyze(context.Background(), paths[i%len(paths)])
		}(i)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(stressTimeBudget * 3):
		t.Fatal("concurrent analyses did not finish — possible deadlock")
	}
}

func TestStressDeepDirectoryAndManyFiles(t *testing.T) {
	// A directory holding many recognizable files should be bounded by
	// WithMaxFiles rather than by whatever the directory happens to contain.
	dir := t.TempDir()
	for i := 0; i < 200; i++ {
		writeShardFile(t, dir, fmt.Sprintf("model-%05d-of-00200.gguf", i+1))
	}

	art, err := tessera.Analyze(context.Background(), dir, tessera.WithMaxFiles(10))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(art.Files) > 10 {
		t.Errorf("WithMaxFiles(10) produced %d files", len(art.Files))
	}
}

func writeShardFile(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), hostileGGUF("truncated"), 0o644); err != nil {
		t.Fatal(err)
	}
}
