# Tessera Sign

Signs a [Tessera](https://github.com/DAVANO-INNOVATION-LAB/tessera) bill of
materials with a **hybrid post-quantum signature**, so a document can be shown
to have come from you and to have not changed since.

```bash
tessera-sign keygen --out ./keys
tessera-sign sign   --key ./keys/signing.key model.cdx.json
tessera-sign verify --pub ./keys/signing.pub model.cdx.json model.cdx.json.sig
```

## Why this is a separate repository

Tessera itself has **zero third-party dependencies**, and that is a promise made
to every program that embeds it — pinned by a test. Post-quantum signatures need
a vetted cryptographic library, and nobody should be hand-rolling one. Keeping
the signing in its own module means a service that only wants to read model
files never acquires a crypto dependency it did not ask for, and this module can
take one without touching that guarantee.

## The algorithm choice

Signatures are **hybrid**: every document is signed twice, independently, and
**both signatures must verify**. If either algorithm is later broken, the other
still holds. That is the conservative composition, and it is also the only one
that satisfies every major authority at once rather than optimising for one:

| Component | Algorithm | Why |
|---|---|---|
| Post-quantum | **ML-DSA-87** (FIPS 204, Category 5) | NSA CNSA 2.0's designated general-purpose signature, at its highest parameter set |
| Classical | **ECDSA P-384** (FIPS 186-5) | ANSSI requires a classical algorithm alongside any post-quantum one; BSI TR-02102-1 concurs |
| Digest | **SHA-384** (FIPS 180-4) | The weakest digest CNSA 2.0 permits |

A pure ML-DSA signature would satisfy the NSA and fail ANSSI's hybrid
requirement. A pure ECDSA signature satisfies neither for the long term. Signing
twice costs a few kilobytes and removes the argument.

**SLH-DSA-SHA2-256s** (FIPS 205) is also available with `--conservative`. It is
hash-based, so it rests on strictly weaker assumptions than ML-DSA's lattices,
which is why BSI favours it; the signatures are much larger and slower to
produce. Use it when the assumption matters more than the size.

## What a signature covers

The signature is over the document's bytes. The document contains a SHA-256 and
SHA-384 digest of every file the model is made of, so signing it transitively
covers the artifact — provided the document is then *checked* against the
artifact, which is what `tessera verify` does. Signing a document nobody
verifies proves only that the document is unaltered, not that it is true.

The intended sequence is therefore:

```bash
tessera bom ./model --format cyclonedx > model.cdx.json   # describe
tessera-sign sign --key signing.key model.cdx.json        # attest
tessera-sign verify --pub signing.pub model.cdx.json model.cdx.json.sig
tessera verify model.cdx.json ./model                     # confirm it still holds
```

## Licence

Apache-2.0.
