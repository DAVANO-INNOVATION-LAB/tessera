package parse

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/scan"
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/spdxlicense"
)

// Defaults for the bounds an embedder can override.
const (
	// DefaultMaxFileSize caps bytes held in memory for a single file. ONNX is
	// the case that matters: protobuf must be walked in memory.
	DefaultMaxFileSize = 4 << 30 // 4 GiB
	// DefaultMaxFiles caps physical files gathered for one model.
	DefaultMaxFiles = 4096
)

// Options are the analysis bounds, supplied by the caller.
type Options struct {
	SkipHashing bool
	MaxFileSize int64
	MaxFiles    int
}

func (o Options) withDefaults() Options {
	if o.MaxFileSize <= 0 {
		o.MaxFileSize = DefaultMaxFileSize
	}
	if o.MaxFiles <= 0 {
		o.MaxFiles = DefaultMaxFiles
	}
	return o
}

// Parse is the entry point: it takes a file or a directory, finds the model,
// parses its format, resolves and hashes every physical file it is made of,
// resolves declared licenses to SPDX identifiers, and runs the security scan.
// The result is a fully assembled Artifact ready for any emitter.
//
// Parse reads only headers and metadata; it never reads a tensor-data region,
// and for ONNX it never resolves an operator or fetches external data.
func Parse(ctx context.Context, path string, opts Options) (*model.Artifact, error) {
	opts = opts.withDefaults()
	if ctx == nil {
		ctx = context.Background()
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	var primary, dir string
	if info.IsDir() {
		dir = path
		primary, err = pickPrimary(dir)
		if err != nil {
			return nil, err
		}
	} else {
		primary = path
		dir = filepath.Dir(path)
	}

	format, ok := Detect(primary)
	if !ok {
		return nil, fmt.Errorf("%s: not a recognized model format (gguf, safetensors, onnx)", primary)
	}

	var a *model.Artifact
	switch format {
	case model.FormatGGUF:
		a, err = ParseGGUF(primary)
	case model.FormatSafetensors:
		a, err = ParseSafetensors(primary)
	case model.FormatONNX:
		a, err = parseONNXBounded(primary, opts.MaxFileSize)
	default:
		return nil, fmt.Errorf("unsupported format %q", format)
	}
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Name fallback: a file that disclosed no name is named by its file.
	if a.Identity.Name == "" {
		a.Identity.Name = strings.TrimSuffix(filepath.Base(primary), filepath.Ext(primary))
	}

	// Assemble the physical-file set and hash each independently, so a
	// multi-file model is a set of pinned components rather than one blob.
	if err := collectFiles(ctx, a, primary, dir, opts); err != nil {
		return nil, err
	}

	// The measured precision: whichever dtype holds the most parameters. This
	// is the figure a model card means when it advertises one, and it is what
	// the declared value gets compared against.
	if a.Params.DType == "" {
		a.Params.DType = dominantDType(a.Tensors)
	}

	// Sidecar claims are read last so they can never overwrite anything
	// measured from the binary; they land in a separate part of the record.
	readSidecars(a, dir)

	// Resolve every disclosed license string to an SPDX identifier.
	for i := range a.Licenses {
		id, conf := spdxlicense.Resolve(a.Licenses[i].Raw)
		a.Licenses[i].SPDXID = id
		a.Licenses[i].Confidence = conf
	}

	// Run the security scan over the parsed IR and attach its findings.
	a.Findings = append(a.Findings, scan.Analyze(a)...)

	return a, nil
}

// pickPrimary chooses the model file to parse from a directory. It prefers a
// single-file model, then the first shard of a sharded set, then any recognized
// file, so a directory of one model resolves to that model.
func pickPrimary(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var gguf, onnx, safet []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		switch strings.ToLower(filepath.Ext(name)) {
		case ".gguf", ".ggml":
			gguf = append(gguf, name)
		case ".onnx":
			onnx = append(onnx, name)
		case ".safetensors":
			safet = append(safet, name)
		}
	}
	sort.Strings(gguf)
	sort.Strings(onnx)
	sort.Strings(safet)

	switch {
	case len(gguf) > 0:
		return filepath.Join(dir, firstShard(gguf)), nil
	case len(safet) > 0:
		return filepath.Join(dir, firstShard(safet)), nil
	case len(onnx) > 0:
		return filepath.Join(dir, onnx[0]), nil
	}
	return "", fmt.Errorf("%s: no gguf, safetensors, or onnx file found", dir)
}

// firstShard returns the first shard of a sharded set, or the lone file. Shard
// names sort so that -00001-of-000NN comes first.
func firstShard(names []string) string {
	return names[0]
}

var ggufSplitRe = regexp.MustCompile(`-(\d{5})-of-(\d{5})\.gguf$`)

// collectFiles finds every physical file the model is made of, hashes each, and
// records it as a component with a role.
func collectFiles(ctx context.Context, a *model.Artifact, primary, dir string, opts Options) error {
	// The model directory, with symlinks already resolved. Containment is
	// checked against this rather than against the path as written, because a
	// lexical check cannot see where a symlink actually points.
	// Absolute first, then resolved. Both halves matter: candidates are made
	// absolute below, and comparing an absolute candidate against a relative
	// root rejects everything — including the model's own primary file.
	rootAbs, err := filepath.Abs(dir)
	if err != nil {
		rootAbs = filepath.Clean(dir)
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		rootReal = rootAbs
	}

	seen := map[string]bool{}
	add := func(path, role string) error {
		abs, err := filepath.Abs(path)
		if err != nil {
			abs = filepath.Clean(path)
		}
		if seen[abs] {
			return nil
		}
		if len(a.Files) >= opts.MaxFiles {
			// Stopping silently would produce a bill of materials that is
			// incomplete without saying so, which reads as complete to anyone
			// downstream. Say it once.
			if !a.HasFinding("TESS-FILE-002") {
				a.AddFinding(model.Finding{
					ID: "TESS-FILE-002", Title: "Component set is incomplete", Severity: "Medium", Category: "model",
					Location: relDisplay(dir, primary),
					Description: fmt.Sprintf("the model references more than the %d-file limit, so the "+
						"remaining files are absent from this bill of materials", opts.MaxFiles),
				})
			}
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		seen[abs] = true

		// Everything the model names is attacker-controlled, so containment is
		// enforced here, once, rather than at each call site. Two checks are
		// needed and neither subsumes the other: a lexical one, because a path
		// that never resolves still says where it wanted to go, and a resolved
		// one, because a symlink inside the directory can point anywhere.
		if !withinRoot(rootReal, abs) {
			a.AddFinding(model.Finding{
				ID: "TESS-FILE-003", Title: "Referenced file escapes the model directory", Severity: "Critical",
				Category: "model", Location: filepath.Base(path),
				Description: fmt.Sprintf("the model references %q as a %s, which resolves outside the model "+
					"directory. Reading it would disclose an unrelated file on the host, so it was not opened.",
					filepath.Base(path), role),
			})
			return nil
		}

		fc, err := hashFile(ctx, abs, role, opts.SkipHashing)
		if err != nil {
			// A missing referenced file is a finding, not a fatal error: the
			// model may reference external data that was not shipped.
			a.AddFinding(model.Finding{
				ID: "TESS-FILE-001", Title: "Referenced file is missing", Severity: "Medium", Category: "model",
				Location: relDisplay(dir, path),
				Description: fmt.Sprintf("the model references %s (%s) but it could not be read: %v",
					filepath.Base(path), role, err),
			})
			return nil
		}
		fc.Path = relDisplay(dir, path)
		a.Files = append(a.Files, fc)
		return nil
	}

	if err := add(primary, "primary"); err != nil {
		return err
	}

	switch a.Format {
	case model.FormatGGUF:
		// A gguf-split set: gather sibling shards sharing the base name.
		if m := ggufSplitRe.FindStringSubmatch(filepath.Base(primary)); m != nil {
			base := ggufSplitRe.ReplaceAllString(filepath.Base(primary), "")
			entries, _ := os.ReadDir(dir)
			var shards []string
			for _, e := range entries {
				if ggufSplitRe.MatchString(e.Name()) && strings.HasPrefix(e.Name(), base) {
					shards = append(shards, e.Name())
				}
			}
			sort.Strings(shards)
			for _, s := range shards {
				if err := add(filepath.Join(dir, s), "shard"); err != nil {
					return err
				}
			}
		}
	case model.FormatSafetensors:
		// A sharded set is described by model.safetensors.index.json.
		if err := addSafetensorsShards(a, dir, add); err != nil {
			return err
		}
	case model.FormatONNX:
		// External tensor data files sit beside the model.
		if refs := a.Raw["onnx.external_data"]; refs != "" {
			for _, loc := range strings.Split(refs, ", ") {
				loc = strings.TrimSpace(loc)
				if loc == "" || isTraversal(loc) {
					continue // never open a traversal path
				}
				if err := add(filepath.Join(dir, loc), "external-data"); err != nil {
					return err
				}
			}
		}
	}

	// Stable order: primary first, then by path.
	sort.SliceStable(a.Files, func(i, j int) bool {
		if (a.Files[i].Role == "primary") != (a.Files[j].Role == "primary") {
			return a.Files[i].Role == "primary"
		}
		return a.Files[i].Path < a.Files[j].Path
	})
	return nil
}

// addSafetensorsShards reads a sibling index file, if present, and adds each
// distinct shard it names.
func addSafetensorsShards(a *model.Artifact, dir string, add func(path, role string) error) error {
	indexPath := filepath.Join(dir, "model.safetensors.index.json")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return nil // no index: single-file model, nothing more to add
	}
	var index struct {
		WeightMap map[string]string `json:"weight_map"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return nil
	}
	shards := map[string]bool{}
	for _, shard := range index.WeightMap {
		shards[shard] = true
	}
	var names []string
	for s := range shards {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, s := range names {
		if err := add(filepath.Join(dir, s), "shard"); err != nil {
			return err
		}
	}
	return nil
}

// withinRoot reports whether candidate resolves inside root. Symlinks are
// resolved first, so a link inside the model directory pointing at /etc is
// caught even though its path looks perfectly local.
//
// A path that does not exist cannot be resolved, so its nearest existing parent
// is resolved instead; that still answers the question that matters, which is
// where the path would land.
func withinRoot(root, candidate string) bool {
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		dir, err2 := filepath.EvalSymlinks(filepath.Dir(candidate))
		if err2 != nil {
			return false
		}
		resolved = filepath.Join(dir, filepath.Base(candidate))
	}
	root = filepath.Clean(root)
	if resolved == root {
		return true
	}
	return strings.HasPrefix(resolved, root+string(filepath.Separator))
}

// ctxReader makes an io.Copy abandonable. Hashing a multi-gigabyte model is the
// longest single operation here, and without this a cancelled request or a
// shutting-down process would still wait for it to finish.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// hashFile computes the SHA-256 of a file and returns it as a component. When
// skipHash is set the file is still stat'd — size and role are cheap and always
// wanted — but the content is not read.
//
// Only regular files are opened. A model that names a FIFO gets its parser
// blocked forever on the open, and one that names a character device such as
// /dev/zero gets it hashing until the process dies; neither is a plausible
// component of a model, so both are refused before the open rather than after.
func hashFile(ctx context.Context, path, role string, skipHash bool) (model.FileComponent, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return model.FileComponent{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// Containment already resolved this; stat the target for its real mode.
		if info, err = os.Stat(path); err != nil {
			return model.FileComponent{}, err
		}
	}
	if !info.Mode().IsRegular() {
		return model.FileComponent{}, fmt.Errorf("not a regular file (%s)", info.Mode().Type())
	}

	fc := model.FileComponent{Size: info.Size(), Role: role}
	if skipHash {
		return fc, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return model.FileComponent{}, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, ctxReader{ctx: ctx, r: f}); err != nil {
		return model.FileComponent{}, err
	}
	fc.SHA256 = hex.EncodeToString(h.Sum(nil))
	return fc, nil
}

func relDisplay(dir, path string) string {
	if rel, err := filepath.Rel(dir, path); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return filepath.Base(path)
}
