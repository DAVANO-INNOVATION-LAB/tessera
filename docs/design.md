# Why it works this way

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
