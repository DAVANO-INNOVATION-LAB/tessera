# Embedding Tessera

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
