package resolver

import (
	"encoding/binary"
	"strings"
	"testing"
)

// The decision that saves the bandwidth: a header-inspectable format is sampled
// whatever its size.
//
// Order matters here and getting it backwards is the whole bug. Checking the
// size first would pull a forty-gigabyte safetensors in full to read a header
// measured in kilobytes — which is exactly what every backend except Hugging
// Face was doing.
func TestPlanSamplesLargeTensorFilesRatherThanSkippingThem(t *testing.T) {
	lim := SamplingLimits{MaxFileBytes: 8 << 30, MaxTotalBytes: 32 << 30, HeaderBytes: 16 << 20}
	const forty = 40 << 30

	for _, name := range []string{"model.safetensors", "model.gguf", "weights.npy"} {
		got, why := planFor(name, forty, 0, lim)
		if got != planHeader {
			t.Errorf("%s at 40 GiB: plan %v (%s), want planHeader", name, got, why)
		}
	}

	// ONNX is deliberately not header-inspectable: an operator can appear
	// anywhere in the protobuf, so sampling would report "no findings" for a
	// graph nobody read.
	if got, _ := planFor("model.onnx", forty, 0, lim); got == planHeader {
		t.Error("ONNX was header-sampled; a suspicious operator can be anywhere in the graph")
	}

	// A pickle is the payload. It is read whole, and generously.
	if got, _ := planFor("pytorch_model.bin", 2<<30, 0, lim); got != planWhole {
		t.Error("a 2 GiB pickle was not read in full; that is the file most worth reading")
	}
}

// The limits still bound an artifact that is hostile rather than merely large.
func TestPlanStillEnforcesLimits(t *testing.T) {
	lim := SamplingLimits{MaxFileBytes: 1 << 20, MaxTotalBytes: 4 << 20, HeaderBytes: 4096}

	if got, why := planFor("huge.bin", 2<<20, 0, lim); got != planSkip {
		t.Errorf("oversized non-samplable file: plan %v (%s), want planSkip", got, why)
	}
	if got, why := planFor("ok.bin", 1<<19, 4<<20, lim); got != planSkip {
		t.Errorf("file past the total budget: plan %v (%s), want planSkip", got, why)
	}
}

// safetensors declares its own header length, so the sampler reads exactly that
// and nothing more. This is what turns a 40 GiB file into a few kilobytes.
func TestSampleHeaderReadsOnlyTheDeclaredHeader(t *testing.T) {
	header := []byte(`{"__metadata__":{"format":"pt"}}`)
	var reads []int64

	read := func(_ string, off, length int64) ([]byte, error) {
		reads = append(reads, length)
		buf := make([]byte, 8+len(header))
		binary.LittleEndian.PutUint64(buf, uint64(len(header)))
		copy(buf[8:], header)
		if length < int64(len(buf)) {
			return buf[:length], nil
		}
		return buf, nil
	}

	body, err := sampleHeader("model.safetensors", read, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(reads) != 2 || reads[0] != 8 {
		t.Fatalf("reads = %v, want an 8-byte probe then the declared length", reads)
	}
	if reads[1] != int64(8+len(header)) {
		t.Errorf("second read was %d bytes, want exactly the declared header", reads[1])
	}
	if !strings.Contains(string(body), "__metadata__") {
		t.Error("the sampled bytes are not the header")
	}
}

// The declared length is attacker-controlled. A file claiming an absurd header
// must not turn into an absurd request.
func TestSampleHeaderGuardsAnAbsurdDeclaredLength(t *testing.T) {
	var largest int64
	read := func(_ string, off, length int64) ([]byte, error) {
		if length > largest {
			largest = length
		}
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, ^uint64(0)) // claims 18 exabytes
		if length < 8 {
			return buf[:length], nil
		}
		return buf, nil
	}

	const fallback = 4096
	if _, err := sampleHeader("model.safetensors", read, fallback); err != nil {
		t.Fatal(err)
	}
	if largest > fallback {
		t.Errorf("requested %d bytes on a file claiming 18 exabytes; the cap is %d",
			largest, fallback)
	}
}
