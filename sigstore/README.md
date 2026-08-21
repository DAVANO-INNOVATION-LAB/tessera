# Tessera Sigstore

**Verify that a model artifact was signed by a publisher you trust — and see
what that signature actually covers.**

A separate module from [tessera](https://github.com/DAVANO-INNOVATION-LAB/tessera)
for one reason: sigstore-go brings a large dependency tree, and tessera has
none. An embedder who wants to parse a model file should not inherit an AWS SDK
to do it. Splitting the module is what lets both statements stay true.

## The distinction it is careful about

A signature that exists and a signature that means something are different
facts. Three cases, reported separately rather than collapsed into a boolean:

- a bundle is present on disk
- a bundle verifies, but against an identity no policy names
- a bundle verifies against a publisher the policy trusts

Only the third is evidence. A tool that answered "signed: true" to the first
would be worse than one that said nothing.

## Partial coverage is its own finding

A signature covering three files in a directory of five is not a signed
artifact. The files it does not cover are reported by name, because that is
exactly where something unsigned would be placed.

## Unsigned is weighted by what the format can do

An unsigned safetensors file and an unsigned pickle are not the same risk:
safetensors cannot execute anything, and a pickle runs on load. The finding
severity reflects which one it is.

## Use

```go
v, err := sigstore.NewVerifier(sigstore.Policy{
    TrustRootPath:          "/etc/tessera/trust-root.json",
    RequireTransparencyLog: true,
    Publishers: []sigstore.Publisher{{
        Identity: "https://github.com/example/models/.github/workflows/publish.yml@refs/heads/main",
        Issuer:   "https://token.actions.githubusercontent.com",
    }},
})
if err != nil {
    return err // a policy that cannot be made usable fails here, loudly
}
res, err := v.Verify("/workspace/model", "oci://registry/example/model@sha256:...")
```

A misconfigured verifier must not return "unverified" for everything: that is
indistinguishable from a working verifier looking at unsigned artifacts, and the
two mean opposite things. `NewVerifier` errors rather than degrading.

## Licence

Apache-2.0.
