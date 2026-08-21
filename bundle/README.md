# Tessera Bundle

**Signed offline data packs for scanners that cannot reach a network.**

Everything Tessera computes from a model file is local: parsing, drift, hashing,
the walk for executable payloads. Three things are not — which vulnerabilities
are known, which byte patterns are malware, and whatever rules were published
after the binary shipped. Every tool in this space fetches those from a service.
An enclave that forbids egress cannot, and so gets a scanner that silently
checks less than it appears to.

A bundle is how that data crosses the gap: one file, self-describing, every part
digested, and the whole thing signed with a hybrid post-quantum signature.

```bash
# On the connected side
tessera-bundle create ./osv-snapshot --out osv.tsb \
  --name osv --kind vulnerability-database --version 2026.08.20 \
  --source osv.dev --source-url https://osv.dev --retrieved 2026-08-20T00:00:00Z
tessera-bundle sign osv.tsb --key signing.key

# Carry osv.tsb and osv.tsb.sig across. On the far side
tessera-bundle verify  osv.tsb --public signing.pub
tessera-bundle extract osv.tsb --dest /var/lib/tessera/db --public signing.pub
```

## What verification actually checks

**The manifest is evidence, not a table of contents.** Every digest is
re-derived from the bytes that arrived, never read and trusted. A bundle whose
manifest is internally consistent but whose contents were altered fails.

**An entry the manifest does not list is a failure, not a curiosity.** An
undocumented file is the shape a smuggled payload takes, and a verifier that
only checked the listed entries would walk straight past it.

**Traversal is refused before anything is written.** `../`, absolute paths and
backslashes are rejected at verification, and the resolved destination is
checked again at extraction.

**Verification completes before extraction begins.** A partially unpacked,
partially verified tree left on disk would eventually be read by something that
believed it was complete.

**The public key comes from the operator, never from the signature.** A verifier
that trusts the key travelling inside the thing it is verifying is not verifying
anything.

Passing `--public` requires a valid signature. Without it the contents are still
checked for internal consistency, and the tool says plainly that nothing has
established who produced them.

## Why hybrid signatures

Signing is delegated to [tessera-sign](https://github.com/DAVANO-INNOVATION-LAB/tessera-sign):
ML-DSA-87 (FIPS 204) and ECDSA P-384 over the same payload, both required. Data
that will sit inside a classified enclave for years should not be authenticated
by a signature a later decade breaks, and nobody knows which of the two families
fails first. Requiring both means a break in either degrades this to the other
rather than to nothing.

## Sources must carry a retrieval date

`--source` without `--retrieved` is refused. A vulnerability database is a claim
about the world, and a claim with no date cannot be assessed for staleness —
which is the first question anybody sensible asks of one. Today's feed and a
three-year-old snapshot look identical in the bytes.

## Format

A gzip-compressed tar with the manifest first, so a reader can learn what the
archive holds without buffering a multi-gigabyte database. Deliberately dull: it
can be inspected with tools an enclave already has when this program is not
available, which is a real consideration on the far side of a gap.

Bundles are deterministic — the same tree produces the same bytes — because a
reviewer across a gap mostly compares a new bundle against one already approved.

## Exit codes

| code | meaning |
|------|---------|
| 0 | verified |
| 1 | the command itself failed |
| 3 | verification failed |
| 64 | the command line was wrong |

## Licence

Apache-2.0.
