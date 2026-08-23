package corpus

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// The corpus: model artifacts with known answers.
//
// Generated rather than committed. A model file is large and opaque, and a
// directory of checked-in blobs is a corpus nobody can read, diff or review —
// the reason a case exists ends up in a commit message and is lost. Here the
// spec *is* the fixture: it says what the file claims, what its tensors
// actually are, and therefore why the answer is what it is.
//
// Generation is deterministic. Byte-identical output every run is what lets a
// score be compared against a baseline at all; a corpus that varied would make
// every regression indistinguishable from noise.

// GGML tensor type codes, from the GGUF specification. Only the ones the corpus
// uses are named.
const (
	ggmlF32  uint32 = 0
	ggmlF16  uint32 = 1
	ggmlQ4K  uint32 = 12
	ggmlQ8_0 uint32 = 8
)

// TypeCode maps a human name in a spec to its GGML code, so a case can say
// "Q4_K" rather than 12.
func TypeCode(name string) (uint32, error) {
	switch name {
	case "F32":
		return ggmlF32, nil
	case "F16":
		return ggmlF16, nil
	case "Q4_K":
		return ggmlQ4K, nil
	case "Q8_0":
		return ggmlQ8_0, nil
	}
	return 0, fmt.Errorf("unknown tensor type %q", name)
}

// Case is one labeled entry.
type Case struct {
	Name string `json:"name"`
	// Why records what this case is testing, in a sentence. A corpus entry
	// whose purpose is not written down becomes undeletable: nobody can tell
	// whether it still earns its place.
	Why string `json:"why"`

	GGUF   *GGUFSpec         `json:"gguf,omitempty"`
	Files  map[string]string `json:"files,omitempty"`
	Config map[string]any    `json:"config,omitempty"`

	// Expect are finding IDs that must be reported.
	Expect []string `json:"expect"`
	// Forbid are finding IDs that must NOT be reported.
	//
	// The more valuable half. A benchmark that only measures what a tool finds
	// rewards a tool that reports everything, and precision without traps is
	// unmeasurable.
	Forbid []string `json:"forbid,omitempty"`
}

// GGUFSpec describes a GGUF file: what it claims, and what it actually holds.
// The gap between those two is the thing Tessera exists to find.
type GGUFSpec struct {
	Name         string            `json:"name,omitempty"`
	Architecture string            `json:"architecture,omitempty"`
	Author       string            `json:"author,omitempty"`
	Organization string            `json:"organization,omitempty"`
	License      string            `json:"license,omitempty"`
	ChatTemplate string            `json:"chatTemplate,omitempty"`
	KV           map[string]string `json:"kv,omitempty"`
	// DeclaredParams is what the file says it has; Tensors is what it has.
	DeclaredParams uint32       `json:"declaredParams,omitempty"`
	FileType       string       `json:"fileType,omitempty"`
	Tensors        []TensorSpec `json:"tensors,omitempty"`
}

// TensorSpec is one tensor's real shape and type.
type TensorSpec struct {
	Name string  `json:"name"`
	Dims []int64 `json:"dims"`
	Type string  `json:"type"`
}

// Write materialises one case into dir, returning the path to scan.
func (c Case) Write(dir string) (string, error) {
	root := filepath.Join(dir, c.Name)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	if c.GGUF != nil {
		data, err := c.GGUF.Bytes()
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(root, "model.gguf"), data, 0o644); err != nil {
			return "", err
		}
	}
	for name, body := range c.Files {
		p := filepath.Join(root, filepath.Clean("/"+name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(p, decodeBody(body), 0o644); err != nil {
			return "", err
		}
	}
	if c.Config != nil {
		enc, err := json.MarshalIndent(c.Config, "", "  ")
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(root, "config.json"), enc, 0o644); err != nil {
			return "", err
		}
	}
	return root, nil
}

// decodeBody expands the small escape vocabulary a spec needs to express binary
// content in JSON. Pickle opcodes are the whole reason: a case about a pickle
// that executes on load has to contain the opcodes that do it.
func decodeBody(s string) []byte {
	var out bytes.Buffer
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			out.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			out.WriteByte('\n')
		case 't':
			out.WriteByte('\t')
		case '\\':
			out.WriteByte('\\')
		case 'x':
			if i+2 < len(s) {
				var v int
				fmt.Sscanf(s[i+1:i+3], "%x", &v)
				out.WriteByte(byte(v))
				i += 2
			}
		default:
			out.WriteByte(s[i])
		}
	}
	return out.Bytes()
}

// Bytes assembles a valid GGUF file from the spec.
func (g *GGUFSpec) Bytes() ([]byte, error) {
	b := &builder{}
	if g.Architecture != "" {
		b.str("general.architecture", g.Architecture)
	}
	if g.Name != "" {
		b.str("general.name", g.Name)
	}
	if g.Author != "" {
		b.str("general.author", g.Author)
	}
	if g.Organization != "" {
		b.str("general.organization", g.Organization)
	}
	if g.License != "" {
		b.str("general.license", g.License)
	}
	if g.ChatTemplate != "" {
		b.str("tokenizer.chat_template", g.ChatTemplate)
	}
	if g.DeclaredParams != 0 {
		b.u32("general.parameter_count", g.DeclaredParams)
	}
	if g.FileType != "" {
		code, err := TypeCode(g.FileType)
		if err != nil {
			return nil, err
		}
		b.u32("general.file_type", code)
	}
	for _, p := range sortedKV(g.KV) {
		b.str(p.k, p.v)
	}
	for _, t := range g.Tensors {
		code, err := TypeCode(t.Type)
		if err != nil {
			return nil, err
		}
		b.tensor(t.Name, t.Dims, code)
	}
	return b.bytes(), nil
}

type builder struct {
	kv      bytes.Buffer
	kvCount uint64
	tensors bytes.Buffer
	tCount  uint64
}

func (b *builder) putStr(buf *bytes.Buffer, s string) {
	binary.Write(buf, binary.LittleEndian, uint64(len(s)))
	buf.WriteString(s)
}

func (b *builder) str(key, val string) {
	b.putStr(&b.kv, key)
	binary.Write(&b.kv, binary.LittleEndian, uint32(8)) // GGUF string
	b.putStr(&b.kv, val)
	b.kvCount++
}

func (b *builder) u32(key string, val uint32) {
	b.putStr(&b.kv, key)
	binary.Write(&b.kv, binary.LittleEndian, uint32(4)) // GGUF uint32
	binary.Write(&b.kv, binary.LittleEndian, val)
	b.kvCount++
}

func (b *builder) tensor(name string, dims []int64, ggmlType uint32) {
	b.putStr(&b.tensors, name)
	binary.Write(&b.tensors, binary.LittleEndian, uint32(len(dims)))
	for _, d := range dims {
		binary.Write(&b.tensors, binary.LittleEndian, uint64(d))
	}
	binary.Write(&b.tensors, binary.LittleEndian, ggmlType)
	binary.Write(&b.tensors, binary.LittleEndian, uint64(0))
	b.tCount++
}

func (b *builder) bytes() []byte {
	var out bytes.Buffer
	out.WriteString("GGUF")
	binary.Write(&out, binary.LittleEndian, uint32(3))
	binary.Write(&out, binary.LittleEndian, b.tCount)
	binary.Write(&out, binary.LittleEndian, b.kvCount)
	out.Write(b.kv.Bytes())
	out.Write(b.tensors.Bytes())
	out.Write(make([]byte, 64))
	return out.Bytes()
}

// sortedKV iterates extra key/values in a stable order.
//
// Map iteration order in Go is deliberately random, and emitting KV pairs in
// that order would make the generated file differ byte-for-byte between runs —
// which would defeat the point of a baseline, since every comparison would show
// a change nobody made.
func sortedKV(m map[string]string) []kvPair {
	out := make([]kvPair, 0, len(m))
	for k, v := range m {
		out = append(out, kvPair{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].k < out[j].k })
	return out
}

type kvPair struct{ k, v string }
