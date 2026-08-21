# Tessera Fetch

**Stage a model artifact from wherever it lives onto local disk, so something
else can read it.**

Backends: `oci://`, `modelcar://`, `s3://`, `pvc://`, `hf://`, `mlflow://`,
`https://`, `http://`.

A separate module from [tessera](https://github.com/DAVANO-INNOVATION-LAB/tessera)
because fetching is where the dependencies are — an S3 client, an OCI registry
client, HTTP. Parsing a model needs none of that, and tessera's zero-dependency
guarantee is worth more than the convenience of a single import path. An
embedder that already has the bytes never sees this module.

## A partial fetch says so

The property this package exists to preserve. When a resolver reads only part of
an artifact — a range request, a size cap — it records what it actually read.
A scan over a partial fetch is not entitled to report a clean result: *no
findings across files that were never retrieved* is a different statement from
*no findings*, and only the resolver knows which one is being made.

```go
art, err := fetch.Resolve(ctx, "hf://meta-llama/Llama-3-8B", "/staging")
if art.Coverage != nil {
    // Part of the artifact was never read. Whatever comes next has to say so.
}
```

## Register only what you need

An air-gapped deployment can build a registry containing only the local
resolvers. An unregistered scheme is refused rather than falling through to a
default, so the deployment *cannot* reach the network — a stronger guarantee
than a flag that asks it not to.

```go
r := &fetch.Registry{}
r.Register(&fetch.PVCResolver{MountRoot: "/mnt/pvc"})
// https:// now fails with an error instead of fetching
```

A URI with no scheme is an error. Guessing a default would silently hand a local
path to a network resolver, or the reverse.

## Format risk travels with the file

`CanExecuteCode` reports whether a filename implies a format that runs code when
loaded. Fetching a pickle is not dangerous; treating it like a safetensors
afterwards is.

## Licence

Apache-2.0.
