# Security history

This project parses untrusted binary files, so its own defects matter as much as
the ones it reports. Everything found in review is published here, including the
findings that were never exposed to a user, because a security tool that only
discusses its successes is not giving you enough to judge it by.

Each entry names what an attacker could do before the fix, and links the
regression test that keeps it closed. Those tests exist so a future refactor
cannot quietly reopen a hole; each one was confirmed to fail against the code as
it was originally written.

---

## Pre-release adversarial review — 2026-08-18

An internal adversarial review before the first public release. Every finding
below was reproduced with a working proof of concept before being fixed. Three
were critical.

### Unrecoverable crash from a crafted GGUF file

**Severity: Critical.** `readValue` and `readArray` were mutually recursive with
no depth bound, and each nesting level cost only twelve bytes of file. Roughly
23 MB of crafted metadata produced `fatal error: stack overflow`.

That is not a panic. Go's runtime raises it directly and `recover` cannot catch
it, so the process dies with no opportunity to handle the failure. For a library
whose stated purpose is being safe to embed, this was the most consequential
defect available: it killed the host — a Kubernetes operator, an FFI caller in
Python or Java, the Studio web server — rather than the scan.

GGUF has no legal nested arrays, so the construct is now refused outright rather
than bounded. Removing the recursion is a stronger fix than limiting it.

Reported as `TESS-GGUF-006`. Pinned by
`TestNestedGGUFArrayDoesNotOverflowTheStack`.

### Arbitrary host-file read through the shard index

**Severity: Critical.** Shard names were read from
`model.safetensors.index.json` — attacker-controlled JSON — and joined to the
model directory with no containment check. The equivalent ONNX path had one; this
path did not.

A `weight_map` naming `../../../../etc/passwd` caused that file to be opened and
hashed, and the resulting component was relabelled to its base name, so the
bill of materials showed a plausible `passwd` shard and the traversal was
invisible. That is a SHA-256 oracle over arbitrary host files — enough to
confirm a guess at a service-account token or a private key — and through Tessera
Studio it was reachable from a web page.

Symlinks defeated every path guard independently: nothing in the codebase
resolved them, so a link created inside the model directory pointing anywhere on
the host was followed without complaint.

Containment now happens once, inside the single function that adds a file, so
every present and future call site inherits it. Both a lexical check and a
symlink-resolved check are applied, because neither subsumes the other.

Reported as `TESS-FILE-003`. Pinned by
`TestSafetensorsIndexCannotEscapeTheModelDirectory` and
`TestSymlinkCannotEscapeTheModelDirectory`.

### Detection bypass via ONNX subgraphs

**Severity: Critical.** The graph walker read only top-level nodes. It never
descended into `NodeProto.attribute`, which is where the branch bodies of
control-flow operators (`If`, `Loop`, `Scan`) live, and it never walked
`ModelProto.functions`.

ONNX Runtime executes those bodies exactly like top-level nodes. So an identical
malicious payload — a custom operator domain plus an external-data traversal —
produced a Critical finding and exit code 3 at the top level, and **no findings
and exit code 0** when moved one `If` deep.

For a tool used as a CI gate this is the worst failure mode there is: not a
crash, not a false alarm, but a silent clean verdict on the exact artifact it
exists to catch. The walker now descends subgraphs and function bodies, bounded
by the depth guard that already existed.

Pinned by an ONNX subgraph regression fixture asserting that the hidden variant
produces the same findings as the visible one.

### Denial of service: quadratic sort

**Severity: High.** Lineage index keys were ordered with a hand-written
insertion sort. A file declaring many base models cost O(n²): 200,000 entries
took roughly 85 seconds, and the metadata cap allowed enough entries to pin a
core for over half an hour. The analysis was not interruptible, so a client
disconnecting did not stop it.

The code carried a comment justifying the hand-rolled sort as avoiding a `sort`
import; that reasoning was simply wrong, as three files in the same package
already imported it. Now 0.17 seconds for the same input.

Pinned by `TestGGUFIndexSortIsNotQuadratic`.

### Denial of service: memory amplification

**Severity: High.** Repeated two-byte ONNX fields were appended to unbounded
slices and maps, turning a 10 MB file into roughly 600 MB of resident memory —
and then into a bill of materials of comparable size. Retained structure is now
capped per category, and the file measured 17 MB resident.

### Denial of service: permanent hang on non-regular files

**Severity: High.** Hashing opened whatever path a model named. Opening a FIFO
blocks until a writer appears — forever — and a character device such as
`/dev/zero` hashes until the process dies. Combined with the traversal above, a
model could name either one.

Only regular files are opened now, and hashing is cancellable, so a caller going
away actually stops the work.

Pinned by `TestNonRegularFilesAreRefused`.

### Data race at the shared-library boundary

**Severity: High.** The C entry point assigned a package-level variable on every
call. Two threads calling the shared library concurrently — the ordinary way a
shared library is used — raced on a string header, which is a potential
segfault rather than merely a garbled value. Confirmed under the race detector.

The version is now published once at load time, and the emitters take tool
identity as a value rather than reading a global. A `recover` guard was also
added at the C boundary, since a Go panic crossing into C aborts the host
process with no usable diagnostic.

### Released binaries misidentified themselves in every document

**Severity: Medium.** The linker's version stamp never reached the emitters, so
every bill of materials produced by a released build recorded its generating
tool as version `dev`. A consumer reads that field to decide whether a document
came from a scanner that had these fixes, so it has to be true.

### Studio: DNS rebinding

**Severity: Medium.** Binding to loopback keeps other machines out, but it is not
a boundary against the user's own browser: a page they visit can point a hostname
at `127.0.0.1`, at which point the browser treats the server as same-origin and
lets that page read the responses — the model directory listing, model
identities, and the hash of every private artifact. The `Host` header is now
checked, which an attacker's page cannot forge.

### Studio: host paths disclosed in errors

**Severity: Medium.** Errors were returned verbatim, and the underlying values
carry absolute paths — disclosing the server's root, the host username, and the
directory layout. Errors now report the category; the detail stays server-side.

### Regression introduced while fixing the above

**Severity: Medium (never released).** The first version of the containment fix
resolved the model directory without first making it absolute, so a relative
invocation compared an absolute candidate against a relative root, rejected
everything, and reported the model's own primary file as escaping. A false
Critical on every ordinary run is its own kind of broken. Caught by testing a
relative path before release.

Pinned by `TestContainmentAcceptsRelativeInvocation`.

### Standards conformance

Not a vulnerability, but a correctness defect of the same weight for this tool:
emitted SPDX documents failed the published SPDX 3.0.1 schema whenever
hyperparameters or datasets were present. `ai_typeOfModel` is multi-valued and
was emitted as a bare string, and `dataset_DatasetPackage` requires
`dataset_datasetType`. Because the schema sets `unevaluatedProperties: false`, one
wrong-shaped property rejects the entire object — so the output was valid JSON
and an invalid SBOM.

Found by validating against the real upstream schema rather than against our own
idea of it. `scripts/validate-boms.sh` now does that in CI on every change.

---

## Reporting

See [SECURITY.md](SECURITY.md). Reports are welcome and credited.

We expect more findings. This code is young, it parses hostile input in three
binary formats, and one review pass found three critical bugs — that ratio does
not suggest the remainder is empty. Treat the current release as something to
test, not as something already proven.
