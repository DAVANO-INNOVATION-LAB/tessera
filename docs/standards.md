# Standards

Government buyers increasingly require an AIBOM against a published list, so
Tessera reports its own coverage rather than asserting conformance:

| Standard | Elements |
|---|---|
| **CISA/NSA/FBI 2026 Minimum Elements** (29 Jul 2026, replaces NTIA 2021) | 17 data fields + 6 practices |
| **G7 SBOM for AI — Minimum Elements** (May 2026) | full table |
| **CERT-In Technical Guidelines v2.0 §9** — AIBOM | full table |
| **BSI TR-03183-2** — the operative CRA SBOM specification | required fields |

```bash
tessera coverage ./model-dir --standard cisa-2026
```

It reports which rows the artifact fills, which it could fill and did not, and
which **no static parse can ever fill** — each with the reason. A tool that
quietly dropped the unfillable rows would report a better number and tell you
less.

It is named for the *tessera hospitalis*, a token two parties broke in half so
either could later prove the other's provenance. That is the job: turn the bytes
of a model file into a verifiable record of what it is and where it came from.

The bill of materials is built to satisfy named requirements:

- **CISA / G7 "SBOM for AI — Minimum Elements"** (Jun 2026): the Models cluster —
  model hash + IANA-named algorithm, identifier, version, producer, license
  pointed at the SPDX/CycloneDX fields, lineage, external references.
- **CISA 2026 "Minimum Elements for an SBOM"**: Component Hash + Algorithm,
  Component License, Tool Name, Generation Context.
- **NSA/allied "AI/ML Supply Chain Risks and Mitigations"** (Mar 2026) and
  **MITRE ATLAS** AML.M0014 (Verify AI Artifacts): every physical file is pinned
  by SHA-256, and the format's own risky fields are recorded, not discarded.
