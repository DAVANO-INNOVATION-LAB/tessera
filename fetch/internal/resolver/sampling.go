package resolver

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
)

// Fetching only what a scan can actually read.
//
// The size problem is the same wherever a model is stored, and so is the answer.
// A frontier model is most of a terabyte and downloading it to run a scanner
// over it is not viable; it is also unnecessary, because the parts that can
// execute code are tiny — configs enabling remote code, custom Python, pickles —
// while the bulk is tensor data whose only inspectable part is a header at byte
// zero.
//
// That reasoning was worked out for the Hugging Face resolver and stayed there,
// which meant a model in object storage was downloaded whole and a model on the
// Hub was not. Same artifact, same scan, two orders of magnitude apart in cost.
// This file is that strategy with the transport taken out, so every backend can
// use it.
//
// What it buys in bandwidth it owes in honesty. A partial fetch is recorded as a
// partial fetch — which files were read whole, which only far enough to validate
// a header, which not at all — so a clean report over an unread file is never
// mistaken for a clean artifact.

// SamplingLimits bounds a partial fetch.
type SamplingLimits struct {
	// MaxFiles caps how many files are considered.
	MaxFiles int
	// MaxFileBytes is the largest file fetched in full. Anything larger is
	// header-sampled if its format supports it, and otherwise skipped.
	MaxFileBytes int64
	// MaxTotalBytes caps the whole staged artifact.
	MaxTotalBytes int64
	// HeaderBytes bounds a header sample.
	HeaderBytes int64
	// Parallel is how many files are fetched at once.
	Parallel int
}

// DefaultSamplingLimits are deliberately small. The interesting files are all
// kilobytes; an artifact whose configs are hundreds of megabytes is itself worth
// a second look.
func DefaultSamplingLimits() SamplingLimits {
	return SamplingLimits{
		MaxFiles: 5000,
		// Generous on purpose. A pytorch_model.bin is a pickle, and a pickle is
		// the payload — the single file most worth reading, and real ones run to
		// several gigabytes. Skipping it to save bandwidth would be optimising
		// away the scan.
		MaxFileBytes:  8 << 30,
		MaxTotalBytes: 32 << 30,
		HeaderBytes:   16 << 20,
		Parallel:      8,
	}
}

// withDefaults fills any zero field, so a caller can set one limit without
// having to restate the rest.
func (l SamplingLimits) withDefaults() SamplingLimits {
	d := DefaultSamplingLimits()
	if l.MaxFiles == 0 {
		l.MaxFiles = d.MaxFiles
	}
	if l.MaxFileBytes == 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxTotalBytes == 0 {
		l.MaxTotalBytes = d.MaxTotalBytes
	}
	if l.HeaderBytes == 0 {
		l.HeaderBytes = d.HeaderBytes
	}
	if l.Parallel == 0 {
		l.Parallel = d.Parallel
	}
	return l
}

// HeaderInspectable reports whether a format's risk lives entirely in a header
// at byte zero, so reading that header is as good as reading the file.
//
// ONNX is deliberately absent: a suspicious operator can appear anywhere in the
// protobuf, so the inspector reads the whole file. Sampling one would return
// "no findings" for a graph it never looked at.
func HeaderInspectable(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".safetensors", ".gguf", ".ggml", ".npy":
		return true
	}
	return false
}

// rangeReader fetches a byte range of one file. Each backend supplies its own;
// the sampling logic below does not care how the bytes arrive.
type rangeReader func(path string, offset, length int64) ([]byte, error)

// sampleHeader reads as little of a file as will still answer the question.
//
// safetensors declares its own header length in the first eight bytes, so two
// small reads get exactly the header and nothing else. Everything else falls
// back to a fixed prefix, which is far past any real tensor header.
//
// The declared length is guarded because it is attacker-controlled: a file
// claiming a header of eighteen exabytes would otherwise turn into a request
// for eighteen exabytes.
func sampleHeader(name string, read rangeReader, fallback int64) ([]byte, error) {
	if strings.EqualFold(filepath.Ext(name), ".safetensors") {
		prefix, err := read(name, 0, 8)
		if err == nil && len(prefix) == 8 {
			declared := binary.LittleEndian.Uint64(prefix)
			if declared > 0 && declared <= uint64(fallback) {
				body, err := read(name, 0, int64(8+declared))
				if err == nil && int64(len(body)) >= 8 {
					return body, nil
				}
			}
		}
	}
	body, err := read(name, 0, fallback)
	if err != nil {
		return nil, fmt.Errorf("sample header of %s: %w", name, err)
	}
	return body, nil
}

// plan describes what to do with one file before any bytes move.
type plan int

const (
	// planWhole reads the file in full.
	planWhole plan = iota
	// planHeader reads only enough to validate a header.
	planHeader
	// planSkip reads nothing, and says so in the coverage record.
	planSkip
)

// planFor decides how much of a file to fetch.
//
// Order matters. A header-inspectable format is sampled whatever its size,
// because the rest is inert weight data — checking the size first would pull a
// forty-gigabyte safetensors in full for a header that is measured in
// kilobytes.
func planFor(name string, size int64, staged int64, lim SamplingLimits) (plan, string) {
	if HeaderInspectable(name) {
		return planHeader, ""
	}
	if size > lim.MaxFileBytes {
		return planSkip, fmt.Sprintf("larger than the %d-byte file limit", lim.MaxFileBytes)
	}
	if staged+size > lim.MaxTotalBytes {
		return planSkip, "total fetch limit reached"
	}
	return planWhole, ""
}
