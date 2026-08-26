# What Tessera detects

Every finding the tool can emit is listed here. A security tool's finding table
is its interface — anything integrating it needs the full set to write
suppressions — so the list is complete rather than illustrative, and a test
fails the build if the tool can emit an identifier this page does not name.

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
| `TESS-HF-003` | High | The same in a `tokenizer_config.json` beside safetensors weights. The template is rendered before the first token whichever way the model is packaged. |
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
| `TESS-GGUF-009` | Medium | A GGUF file that could not be examined. Nothing inside it was checked, which is not the same as nothing being wrong with it. |
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
| `TESS-DRIFT-008` | High | The file's own header contradicts its tensors — `general.file_type` declares one precision while the tensor block holds another. Distinct from `TESS-DRIFT-002`: no sidecar can reconcile a file that disagrees with itself. |
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
