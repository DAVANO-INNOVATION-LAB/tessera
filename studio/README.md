# Tessera Studio

A local interface over [Tessera](../tessera): browse a directory of models,
analyse one, read the findings its own metadata discloses, and download a
CycloneDX 1.6 or SPDX 3.0.1 bill of materials.

```bash
make build
./bin/tessera-studio /path/to/models
#   http://127.0.0.1:7777
```

## What it is, and what it deliberately isn't

Studio is a **separate program** from the Tessera library and CLI. It depends on
Tessera exactly the way any other consumer would — by importing it:

```go
import tessera "github.com/DAVANO-INNOVATION-LAB/tessera"
```

Studio depends on the published module, with a checksummed `go.sum` like any
other consumer — there is no sibling-directory arrangement to reproduce. To work
on both at once, point Go at a local checkout without editing `go.mod`:

```bash
go work init . ../tessera
```

`go.work` is gitignored, so that stays a local convenience and never becomes a
condition of building this repository.

Nothing in the analyser knows Studio exists. That direction of dependency is the
point: the analyser stays a small, embeddable, zero-dependency library, and the
interface is one of several things built on top of it. Studio's own module graph
is itself plus Tessera, and nothing else.

It is **not** a service. There is no database, no queue, no job history, no
accounts. A request runs an analysis and returns it. Restarting the process
loses nothing because there was nothing to lose.

## Security posture

Studio is a viewer for artifacts you do not trust yet, so it is built to be
uninteresting as a target:

- **Loopback by default.** It binds `127.0.0.1:7777`. Pass `--addr` to change
  that, and understand what you are doing if you bind a routable interface.
- **Confined to one directory.** Every path is resolved inside the directory
  named on the command line. Absolute paths are refused; `..` is neutralised.
  The UI must not become a way to read arbitrary files off the host.
- **Content-Security-Policy that allows nothing external.** The page is
  self-contained: no fonts, no scripts, no images from anywhere else.
- **It inherits Tessera's guarantees.** Analysis reads headers and metadata
  only — no framework loads, no ONNX operator resolution, no external-data
  fetch, and no network access at all.

## Endpoints

| Route | Purpose |
|---|---|
| `GET /` | the interface |
| `GET /api/browse?path=` | list a directory, marking recognised models |
| `GET /api/analyze?path=` | full analysis as JSON |
| `GET /api/bom?path=&format=cyclonedx\|spdx` | bill of materials as a download |
| `GET /api/coverage?path=&standard=g7\|cert-in` | coverage against a published minimum-elements standard |

The coverage view is the one a regulated reader wants, and it is built to be
honest: elements no static parse can supply — training properties, dataset
hashes, benchmark results — are shown alongside the ones it fills, each with its
reason, rather than dropped to flatter the total.

Downloads are reproducible: the BOM is stamped from the model file's own
modification time rather than the wall clock, so fetching twice gives you the
same bytes.

## Layout

```
cmd/tessera-studio    the server binary
internal/web          routes, path confinement, and the embedded UI
```

The interface is a single embedded `ui.html` — no build step, no bundler, no
node_modules. `go build` produces one binary with the UI inside it.


## Running it

One image, one process, 31 MB. No shell, no package manager, no interpreter —
which is the right shape for something whose job is to open files it does not
trust.

```bash
docker run --rm -p 7777:7777 -v /path/to/models:/models:ro \
  ghcr.io/davano-innovation-lab/tessera:latest
```

The image also carries the command-line tools, so the same container scans in a
pipeline as serves the interface:

```bash
docker run --rm -v /path/to/models:/models:ro \
  --entrypoint /usr/local/bin/tessera \
  ghcr.io/davano-innovation-lab/tessera:latest scan /models/llama3
```

Version tags carry no leading `v` — `:1.0.1`, not `:v1.0.1`.

`tessera`, `tessera-sign` and `tessera-bundle` are all present. Signing and
offline data bundles are included because an operator working across an air gap
needs them in the same place as everything else — asking them to assemble a
toolchain on the far side of a gap is asking them not to bother.

Every binary reports the release it was built from, so the image can account for
what is inside it.

**Seven Go modules, one container.** A module is a source boundary, not a
deployment boundary: the split exists so a program embedding the parser does not
inherit an AWS SDK to do it. It was never meant to imply seven things to run.

The Kubernetes operator is a separate image and a separate decision. Nobody
should need a cluster to scan a model.

## Authentication

**A port reachable beyond this machine requires authentication.** The server
refuses to start otherwise, or generates a token if one was not supplied —
never both silently open and exposed.

That distinction matters because the Host-header check is a DNS-rebinding
guard, not an authentication boundary: `curl -H "Host: localhost"` satisfies it
from anywhere on the network. On a loopback bind that is fine, since nothing off
the machine can connect. On an exposed bind it is not.

**Loopback stays frictionless.** `tessera-studio /models` on a laptop needs no
configuration and no token, exactly as before.

**An exposed bind generates a token** and prints a link, unless you supply one:

```
This port is reachable beyond this machine, so a token was generated.
Open:  http://0.0.0.0:7777/?token=tss_…
Or:    Authorization: Bearer tss_…
```

The token in the link is accepted once, exchanged for an HttpOnly cookie, and
stripped from the URL — tokens in URLs survive in browser history, referrer
headers and proxy logs.

Supply your own with `--auth-token` or `TESSERA_AUTH_TOKEN`.

### OIDC

For anything shared, use an identity provider:

```bash
tessera-studio /models --addr 0.0.0.0:7777 \
  --oidc-issuer https://login.example.com \
  --oidc-client-id tessera \
  --oidc-client-secret "$SECRET" \
  --oidc-redirect-url https://tessera.example.com/auth/callback \
  --oidc-allowed-domains example.com
```

Authorization code with PKCE. Discovery runs at startup, so a misconfigured
issuer is a boot failure rather than a surprise for whoever signs in first. The
issuer in the discovery document must match what was configured, which is how a
redirect to somebody else's provider gets caught.

`--oidc-allowed-emails` and `--oidc-allowed-domains` restrict who may sign in.
Leaving both empty means anyone the provider authenticates — correct for a
company issuer, wrong for a public one, and yours to decide rather than ours to
guess.

Bearer tokens keep working alongside OIDC so a pipeline does not need an
interactive login.

### Turning it off

`--insecure-no-auth` permits an exposed bind with no authentication. It prints a
warning on every start. It exists so the decision is deliberate rather than
worked around by someone who does not know what it protects.

## Licence

Apache-2.0.
