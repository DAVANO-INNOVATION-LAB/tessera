# Tessera

**Offline AI bill-of-materials generator for model files.** Tessera reads a
local **GGUF**, **safetensors**, or **ONNX** file — off disk, no framework, no
network — and emits a normalized bill of materials in both **CycloneDX 1.6** and
**SPDX 3.0.1** from a single parse, with the security findings the metadata
discloses attached to the same document.

It is named for the *tessera hospitalis*, a token two parties broke in half so
either could later prove the other's provenance. That is the job: turn the bytes
of a model file into a verifiable record of what it is and where it came from.

## Why

The crowded corner of the AIBOM space reads the Hugging Face API and the model
card. That fails the moment the artifact is a bare `.gguf` on a share drive, an
`.onnx` inside a hardened container, or a sharded `.safetensors` with no repo
behind it — which is exactly the artifact that lands in an air-gapped enclave.
Tessera reads the **file itself**:

- **GGUF** carries the richest self-description — name, license, author,
  base-model lineage, datasets, quantization — in its key/value metadata store.
  Most tooling throws it away. Tessera lifts all of it into the BOM.
- **ONNX** carries producer, opset, IR version, and a full operator graph.
  Tessera walks the protobuf by hand (never `onnx.checker`, never a runtime
  session) so the parse cannot resolve a custom operator or fetch external data.
- **safetensors** carries almost nothing; Tessera harvests what is there and
  pulls shard sets from `model.safetensors.index.json`.

### What it does that the others do not

Reading model binaries offline is no longer unusual — several projects now do
it, and several produce security findings from what they read. Two things are
still not done anywhere else, as of a survey on 2026-08-19:

**It checks the claims against the bytes.** A model states things about itself
in `config.json` and its model card: an architecture, a precision, a shard
count. Tessera reads those, reads what the tensor headers actually contain, and
reports where the two disagree — a config declaring `bfloat16` over 8-bit
weights, an architecture the binary does not implement, a shard set short a
file. Other tools read both sides and never compare them; syft, for instance,
parses `config.json` and the safetensors header in the same cataloger and asks
nothing about whether they agree. A declaration nobody checks is exactly where a
wrong claim survives, and these findings say plainly that a claim is
unsupported — not that anyone lied, because a stale config is far more common
than a forged one.

**It emits both standards in substance, from one parse.** Producing a CycloneDX
1.6 `modelCard` and an SPDX 3.0.1 `ai_AIPackage` with datasets, licences and
per-file hashes — from the same read, so the two documents cannot disagree — is
still unoccupied. Tools that emit both tend to have one of them as a stub, or to
stop at SPDX 2.3, which has no AI profile at all.

Being an embeddable zero-dependency library rather than a CLI or a container
pipeline is the third difference, and the one that matters most if you are
putting this inside something else.

## One analyser, four shapes

The analyser is a library first. Everything else is a thin wrapper, so nothing
has to run as a sidecar, a second container, or a subprocess unless you want it
to.

| Shape | For | Build |
|---|---|---|
| **Library** | Go callers — in-process, no container | `go get` and import |
| **CLI** | anything that can exec | `make build` |
| **C shared library** | Python, Rust, Java, C#, Node — in-process via FFI | `make ffi` |
| **WebAssembly** | WASI runtimes (wasmtime, wasmer, Node) | `make wasm` |

### Embedding in Go

```go
import tessera "github.com/DAVANO-INNOVATION-LAB/tessera"

art, err := tessera.Analyze(ctx, "/models/llama3.gguf")
if err != nil { return err }

for _, f := range art.Findings {
    log.Printf("%s %s: %s", f.Severity, f.ID, f.Title)
}
if tessera.Worst(art.Findings) == tessera.SeverityCritical {
    return fmt.Errorf("artifact refused")
}

bom, err := tessera.CycloneDX(art, time.Now())
```

Three properties make that safe to import into a long-running service. Each is
pinned by a test that fails if it ever stops being true:

- **Zero third-party dependencies.** Standard library only. An importer's module
  graph gains exactly one entry — this one — so there is no transitive tree to
  audit, no version conflict to resolve, and nothing added to its image.
- **No global state, no init side effects, and nothing written to stdout or
  stderr, ever.** The caller owns all output.
- **No network.** `net` is not in the dependency tree, so an analysis cannot
  reach out even if a malicious artifact asks it to.

Options exist for embedders with different constraints:
`tessera.WithoutHashing()` for a fast metadata-only read (note that it produces
a document which is *not* a compliant SBOM, since the hash is a required minimum
element), plus `WithMaxFileSize` and `WithMaxFiles` to bound the work.

### Embedding elsewhere

`make ffi` produces `libtessera.{so,dylib,dll}` and a header. The surface is
three functions and one ownership rule — every returned string is yours to free:

```python
import ctypes, json
lib = ctypes.CDLL("./libtessera.dylib")
lib.tessera_analyze.restype = ctypes.c_void_p

p = lib.tessera_analyze(b"model.gguf", b"cyclonedx")
bom = json.loads(ctypes.string_at(p).decode())
lib.tessera_free(p)
```

`make wasm` produces a WASI module that any sandboxed runtime can execute with
only the model directory preopened — so the analyser can see the artifact and
nothing else on the host. A `GOOS=js` module is also built, but it is the same
command-line program: running it in a browser needs a filesystem shim, which is
not shipped here.

## Install

```bash
make build   # CLI
make all     # CLI + FFI library + WebAssembly
```

## Use

```bash
# Human-readable read of a model's metadata and findings
tessera inspect model.gguf

# Emit a CycloneDX 1.6 ML-BOM to stdout
tessera bom model.gguf --format cyclonedx

# Emit both standards into a directory
tessera bom ./model-dir --out ./boms

# Byte-identical output for the same input (timestamp from the file mtime)
tessera bom model.onnx --format spdx --reproducible
```

`bom` accepts a single file or a directory containing one model (it resolves
shard sets and ONNX external-data files, hashing each physical file
independently).

**Exit codes** are made for CI gates: `0` clean, `2` findings up to High, `3` a
Critical finding, `1` the parse itself failed.

## What it detects

Every finding this tool can emit is listed here. A security tool's finding table
is its interface — anything integrating it needs the full set to write
suppressions — so the list is complete rather than illustrative.

### Load-time risk, read from the model binary

| ID | Severity | What |
|----|----------|------|
| `TESS-ONNX-011` | Critical | An `external_data` location escaping the model directory. Loading reads an arbitrary host file (CVE-2022-25882 → 2024-27318 → 2026-27489). The path is never opened. |
| `TESS-FILE-003` | Critical | A referenced shard or sidecar resolving outside the model directory, including via a symlink. Never opened. |
| `TESS-ONNX-010` | High | A non-standard operator domain, which resolves to an out-of-tree native kernel that runs when the model runs. |
| `TESS-GGUF-010` | High | Jinja control logic in the GGUF `chat_template`. Loaders that render it unsandboxed execute it (the CVE-2024-34359 "Llama Drama" class) — attacker-controlled metadata as code execution. |
| `TESS-GGUF-011` | Medium | An implausible `general.alignment`, a known integer-overflow and arbitrary-seek vector. |

### Malformed or hostile structure

| ID | Severity | What |
|----|----------|------|
| `TESS-GGUF-001` | High | The file does not begin with the GGUF magic. |
| `TESS-GGUF-002` | High | An implausible metadata-entry count (the heap-overflow class); metadata was not read. |
| `TESS-GGUF-005` | High | An implausible tensor count. |
| `TESS-GGUF-003` | High | A metadata string declaring a length past the safety cap. |
| `TESS-GGUF-007` | High | A metadata array declaring more elements than the cap. |
| `TESS-GGUF-006` | High | A nested metadata array. GGUF has none legally, and deep nesting exhausts a parser's stack. |
| `TESS-GGUF-004` | Medium | A tensor declaring an impossible dimension count; the tensor table is truncated. |
| `TESS-GGUF-008` | Medium | An unsupported GGUF version. Version 1 laid out its counts differently, so nothing past the header was examined rather than misparsed. |
| `TESS-ST-002` | High | A safetensors header length inconsistent with the file size. |
| `TESS-ST-001` | Medium | A truncated safetensors header. |
| `TESS-ST-003` | Medium | A safetensors header that is not valid JSON. |
| `TESS-ONNX-005` | Medium | The protobuf walk stopped early. What was read is reported; the rest was not. |
| `TESS-ONNX-006` | Medium | The file exceeds the parse ceiling, so its graph was not examined. |

### Declared versus measured

What the model claims about itself, checked against what its bytes contain.
None of these prove malice — a stale config is far more common than a forged
one. They establish that a specific claim is unsupported by the artifact.

| ID | Severity | What |
|----|----------|------|
| `TESS-DRIFT-001` | High | The declared architecture does not match the model binary. |
| `TESS-DRIFT-002` | High | The declared precision does not match the tensors — a quantized model presented as full precision. |
| `TESS-DRIFT-004` | High | The shard set does not match the count the index names. |
| `TESS-DRIFT-003` | Medium | The declared quantization differs from the file. |
| `TESS-DRIFT-006` | Medium | An executable weight format shipped beside a safe one; which one loads depends on the loader. |
| `TESS-DRIFT-005` | Low | A declared claim that no present format can verify. Reported so it is not mistaken for a checked one. |

### Completeness

| ID | Severity | What |
|----|----------|------|
| `TESS-FILE-001` | Medium | A referenced file could not be read. |
| `TESS-FILE-002` | Medium | The component set hit the file limit, so the bill of materials is incomplete. |
| `TESS-LIC-001` | Low | No license disclosed, so the license element the CISA and G7 minimum elements ask for cannot be populated. |

Findings travel inside both documents — as a vulnerability-disclosure report in
CycloneDX, and as `ai_limitation` entries in SPDX — so the bill of materials and
the risk verdict cannot be separated in transit.

### Scope, stated honestly

Tessera is a **supply-chain / artifact** tool: it reports what a file discloses
and how a file can hurt you on load. It does **not** do behavioural evaluation —
data poisoning, backdoor-trigger discovery, jailbreak robustness — because those
need training data and runtime behaviour a static parse cannot see. That is a
scope edge, not a silent gap.

## Standards mapping

The bill of materials is built to satisfy named requirements:

- **CISA / G7 "SBOM for AI — Minimum Elements"** (Jun 2026): the Models cluster —
  model hash + IANA-named algorithm, identifier, version, producer, license
  pointed at the SPDX/CycloneDX fields, lineage, external references.
- **CISA 2026 "Minimum Elements for an SBOM"**: Component Hash + Algorithm,
  Component License, Tool Name, Generation Context.
- **NSA/allied "AI/ML Supply Chain Risks and Mitigations"** (Mar 2026) and
  **MITRE ATLAS** AML.M0014 (Verify AI Artifacts): every physical file is pinned
  by SHA-256, and the format's own risky fields are recorded, not discarded.

## Architecture

Four stages over one format-neutral intermediate representation
(`internal/model.Artifact`):

```
sniff/parse ──▶ normalize to IR ──▶ enrich (hash, resolve SPDX license, scan) ──▶ emit
  gguf                                                                              cyclonedx
  safetensors    every disclosed field lands in a typed slot AND in Raw,            spdx
  onnx           so nothing read is ever silently dropped                           (+ findings as VDR)
```

Add a format by writing one parser; add a standard by writing one emitter.
Neither side knows the other exists.

## Layout

```
tessera.go             the public API — Analyze, CycloneDX, SPDX
types.go               the public vocabulary
options.go             analysis bounds an embedder can set
cmd/tessera            CLI
cmd/libtessera         C shared library for non-Go embedders
internal/model         the Artifact IR — the join everything reads/writes
internal/parse         gguf / safetensors / onnx parsers + protobuf wire reader
internal/spdxlicense   raw license string → SPDX identifier
internal/scan          IR → security findings
internal/emit          CycloneDX 1.6 and SPDX 3.0.1 emitters
```

Parsers and emitters stay in `internal/`, so they are free to change without
breaking anyone. The root package is the surface that must stay stable — it
re-exports the IR types as aliases, so a value the parser produced is the same
value the caller holds, with no conversion layer in between.

A user interface lives in a separate repository,
[tessera-studio](../tessera-studio), which consumes this library the same way
any other caller would.

## License

Apache-2.0.
