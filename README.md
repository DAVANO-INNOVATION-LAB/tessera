# Tessera

**Offline AI bill-of-materials generator for model files.** Tessera reads a
local **GGUF**, **safetensors**, or **ONNX** file — off disk, no framework, no
network — and emits a normalized bill of materials in both **CycloneDX
(1.6 or 1.7)** and **SPDX 3.0.1** from a single parse, with the security findings
the metadata discloses attached to the same document and to a **SARIF 2.1.0**
report for code scanning.

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

### What it does

Reading model binaries offline is no longer unusual, and neither is producing
security findings from what they disclose. Several projects do both. What
follows describes what Tessera does, not what anyone else fails to do — a
comparative claim in a README goes stale faster than the README does, and two of
them here already did.

**It checks the claims against the bytes.** A model states things about itself
in `config.json` and its model card: an architecture, a precision, a shard
count. Tessera reads those, reads what the tensor headers actually contain, and
reports where the two disagree — a config declaring `bfloat16` over 8-bit
weights, an architecture the binary does not implement, a shard set short a
file. A declaration nobody checks is where a wrong claim survives. These
findings say a specific claim is unsupported by the artifact; they do not say
anyone lied, because a stale config is far more common than a forged one.

Tools that do compare declarations against weights generally do it against the
Hugging Face API. Tessera does it from local bytes, which is the case that
matters in an air-gapped enclave, and it is why the comparison happens in the
parser rather than in a hub client.

**It emits both standards from a single parse,** so the CycloneDX
`modelCard` and the SPDX 3.0.1 `ai_AIPackage` describe the same read and cannot
disagree with each other about the same artifact. CycloneDX 1.6 is the default
and 1.7 is a flag away; the two documents are identical apart from the declared
`specVersion`, which is asserted by a test rather than assumed.

**It verifies, not just generates.** `tessera verify` takes a bill of materials
and the artifact it claims to describe, and asks whether the document still
holds: every documented component present with the digest recorded, every file
present documented. Producing a document at build time says nothing about the
bytes in front of you later unless somebody checks, and the checking is the part
that is usually missing. A document whose claims all pass but which omits a file
that is present is reported as **not verified** — an undocumented component is
the shape a smuggled payload takes.

**It judges, not just describes.** `tessera scan` runs the parse, the deep walk,
the document emitters and a policy gate in one pass, and exits on the verdict.
The gate is the same one that decides admission inside a Kubernetes cluster —
thresholds, format allow-lists, signature and bill-of-materials requirements,
time-boxed waivers bound to a content digest. It needs no cluster to run,
because none of it was ever orchestration: a threshold comparison is
computation. Rules are JSON, since the standard library parses that and the
zero-dependency guarantee is worth more than YAML.

**It reports its own coverage.** `tessera coverage` maps the output against the
**CISA/NSA/FBI 2026 Minimum Elements** (29 July 2026, which replaced the 2021
NTIA elements), the **G7 SBOM for AI minimum elements** (May 2026), **CERT-In's
AIBOM table**, and **BSI TR-03183-2** — the only published technical specification of what a Cyber
Resilience Act SBOM must contain, since the Article 13(24) implementing act has
not been adopted and no harmonised standard has been cited in the Official
Journal. It says which rows it fills. It distinguishes an element this artifact happens
not to disclose from one no static parse can ever supply — training properties,
dataset hashes, benchmark results — and gives the reason for each. Those
checklists are what a regulated buyer will hold the output against, and neither
publisher ships anything that measures conformance. The gaps are the honest
part: a buyer discovers them either from this report or on their own.

**It is a library first.** Zero third-party dependencies, no network, no output
of its own — so it embeds inside another program rather than being shelled out
to. That is the difference that matters most if you are putting it inside
something else, and it is pinned by tests rather than asserted.

Related work worth knowing about: [`airom`](https://github.com/airomhq/airom)
also parses local model binaries in Go and emits both formats, with a broader
discovery surface across code, containers and Kubernetes.

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

## In a GitHub workflow

The action downloads a released binary, verifies its Sigstore signature against
the checksum manifest before running it, and uploads the SARIF to code scanning
so findings land as annotations on the pull request.

```yaml
permissions:
  contents: read
  security-events: write   # required to upload SARIF

steps:
  - uses: actions/checkout@v7
  - uses: DAVANO-INNOVATION-LAB/tessera@v1
    with:
      path: ./models/llama3
      fail-on: critical            # or high, medium, low, never
      cyclonedx-version: "1.7"
```

Every published release is covered by a `checksums.txt` signed with Sigstore.
Signing is keyless, so there is no key to distribute — the certificate names the
repository and the workflow that built the binary:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/DAVANO-INNOVATION-LAB/tessera/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

## Install

```bash
make build   # CLI
make all     # CLI + FFI library + WebAssembly
```

## Use

```bash
# Everything in one pass: parse, deep walk, document, judge
tessera scan ./model-dir --out ./boms

# Human-readable read of a model's metadata and findings
tessera inspect model.gguf

# Emit a CycloneDX ML-BOM to stdout (1.6 by default)
tessera bom model.gguf --format cyclonedx

# ...or at CycloneDX 1.7
tessera bom model.gguf --format cyclonedx --cyclonedx-version 1.7

# Emit a SARIF report for code scanning
tessera bom model.gguf --format sarif

# Emit both standards into a directory
tessera bom ./model-dir --out ./boms

# Byte-identical output for the same input (timestamp from the file mtime)
tessera bom model.onnx --format spdx --reproducible

# Deep walk: also read the formats that CAN carry code, beside the model
tessera inspect ./model-dir --deep

# Check a document against the artifact it claims to describe
tessera verify model.cdx.json ./model-dir

# Report coverage against a published minimum-elements standard
tessera coverage ./model-dir --standard cisa-2026   # or g7, cert-in, bsi

# Gate a pipeline on severity (High and Medium share an exit code otherwise)
tessera bom model.gguf --format sarif --fail-on high
```

`bom` accepts a single file or a directory containing one model (it resolves
shard sets and ONNX external-data files, hashing each physical file
independently).

**Exit codes** are made for CI gates:

| Code | Meaning |
|------|---------|
| `0` | scanned, nothing above Low |
| `2` | scanned, findings up to High |
| `3` | scanned, at least one Critical |
| `1` | the scan itself failed |
| `64` | the command line was wrong — **nothing was scanned** |

For `verify`, `0` means the artifact matches the document and `3` means it does
not. That is a failed gate rather than a scan finding: nothing in it is a
judgement about the model's contents.

`64` is separate from `1` on purpose. A gate that treats a nonzero-but-known code
as "findings, warn and continue" would otherwise pass silently on a typo'd flag,
having never looked at the artifact at all.

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

### Executable payloads beside the model (`--deep`)

GGUF, safetensors and ONNX are the formats that **cannot** carry code — which is
why an attack lands in the pickle, the Keras `Lambda`, or the TensorFlow graph op
sitting in the same directory. `tessera inspect --deep` walks the whole artifact
and reads those formats too, so a clean weights file next to a poisoned tokenizer
is not reported as a clean artifact.

| ID | Severity | What |
|----|----------|------|
| `TESS-PICKLE-001` | Critical | A pickle imports a dangerous callable (`os.system`, `subprocess.*`, `builtins.eval`, …). Executes on load. |
| `TESS-PY-001` | Critical | Python in the artifact executes a shell command. |
| `TESS-HF-001` | Critical | `trust_remote_code` is enabled, so loading runs code fetched with the model. |
| `TESS-ARCHIVE-003` | Critical | An archive entry whose path escapes the extraction root. |
| `TESS-ONNX-002` | Critical | An ONNX `external_data` path traversing outside the model directory. |
| `TESS-CONFIG-001` | Critical/High | A config naming a callable a Hydra-style loader imports and calls before any weight is read. |
| `TESS-KERAS-001` | High | A Keras `Lambda` layer, which carries arbitrary serialized Python. |
| `TESS-KERAS-002` | High | A layer that loads another model from a path in the config. |
| `TESS-KERAS-003` | High | A layer implemented outside the Keras and TensorFlow namespaces. |
| `TESS-TF-001` | High | A SavedModel graph op that reads, writes or executes outside the graph (`PyFunc`, `ReadFile`, `WriteFile`, `Save`). |
| `TESS-ONNX-001` | High | A suspicious ONNX operator (`PythonOp`, `TorchScript`, contrib custom ops). |
| `TESS-HF-002` | High | Custom `auto_map` classes, which resolve to code shipped with the model. |
| `TESS-NATIVE-001` | High | A native shared library inside the artifact. |
| `TESS-BIN-001` | High | An ELF executable inside the artifact. |
| `TESS-BIN-002` | High | A PE executable inside the artifact. |
| `TESS-BIN-003` | High | A Mach-O executable inside the artifact. |
| `TESS-PY-002` | High | Python dynamic code execution (`eval`, `exec`, `compile`). |
| `TESS-PY-003` | High | Python network egress. |
| `TESS-PY-004` | High | An unsafe deserialization call. |
| `TESS-PY-006` | High | A custom native extension. |
| `TESS-NPY-001` | High | An object-dtype NumPy array, which unpickles on load. |
| `TESS-ARCHIVE-002` | High | An archive exceeding the entry cap; the rest was not examined. |
| `TESS-ARCHIVE-004` | High | A symlink inside an archive. |
| `TESS-ARCHIVE-005` | High | An archive exceeding the decompression cap. |
| `TESS-ARCHIVE-006` | High | A compression ratio consistent with a decompression bomb. |
| `TESS-LINK-001` | High | A symlink escaping the model directory. |
| `TESS-COVERAGE-001` | High | The walk was truncated, so part of the artifact was never examined. A clean result over a partial walk is not a clean artifact. |
| `TESS-KERAS-004` | Medium | A Keras container that could not be examined. |
| `TESS-PICKLE-002` | Medium | A Torch zip container. |
| `TESS-PICKLE-004` | Medium | An unsafe serialization format where a safe one exists. |
| `TESS-EXEC-001` | Medium | A file carrying the executable bit. |
| `TESS-SHELL-001` | Medium | A shell script inside the artifact. |
| `TESS-SHELL-002` | Medium | A script with an interpreter directive. |
| `TESS-PY-005` | Medium | A base64-decoded payload. |
| `TESS-NPY-002` | Medium | An invalid NumPy header length. |
| `TESS-ARCHIVE-001` | Medium | A malformed archive. |
| `TESS-IO-001` | Medium | A file that could not be read. |
| `TESS-IO-002` | Medium/High | Inspection of a file failed part-way. |
| `TESS-PICKLE-003` | Low | Pickle-based weights execute code on load. Inherent to the format, not a defect in this model. |

### Declared versus measured

What the model claims about itself, checked against what its bytes contain.
None of these prove malice — a stale config is far more common than a forged
one. They establish that a specific claim is unsupported by the artifact.

| ID | Severity | What |
|----|----------|------|
| `TESS-DRIFT-001` | High | The declared architecture does not match the model binary. |
| `TESS-DRIFT-002` | High | The declared precision does not match the tensors — a quantized model presented as full precision. |
| `TESS-DRIFT-004` | High | The shard set does not match the count the index names. |
| `TESS-DRIFT-007` | High | The declared parameter count does not match the sum of the tensor shapes — a model sold as 8B whose weights are 3B. |
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
and how a file can hurt you on load. Behavioural evaluation — data poisoning,
backdoor-trigger discovery, jailbreak robustness — is a separate discipline
built on training data and runtime observation, and it produces its own
evidence alongside this.

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
internal/emit          CycloneDX, SPDX 3.0.1 and SARIF emitters
internal/inspect       deep walk: pickle, Keras, SavedModel, archives, Python
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
