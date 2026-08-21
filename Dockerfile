# The Tessera application: one image, one process.
#
# Six Go modules produce one container. That is not a contradiction — a module
# is a source boundary, not a deployment boundary. The nesting exists so a
# program embedding the parser inherits nothing: the root module has no
# dependencies at all, and signing, fetching and provenance keep theirs to
# themselves. It was never meant to imply six things to run.
#
# Everything is built from this tree rather than fetched from a registry, so the
# image is reproducible from a single checkout and needs no network beyond the
# module cache.

FROM golang:1.25-alpine AS build
WORKDIR /src
ARG VERSION=dev
ENV CGO_ENABLED=0

# The root module has no go.sum, because it has no dependencies to record. That
# is the guarantee this whole layout exists to protect, so the build copies the
# tree rather than pretending a lock file is there.
COPY . .

RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/tessera ./cmd/tessera && \
    cd studio && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/tessera-studio ./cmd/tessera-studio && \
    cd ../sign && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/tessera-sign ./cmd/tessera-sign && \
    cd ../bundle && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/tessera-bundle ./cmd/tessera-bundle

# Nothing from the toolchain survives. No shell, no package manager, no
# interpreter — the right shape for something whose job is opening files it does
# not trust.
FROM gcr.io/distroless/static-debian12:nonroot

# The source label is what links the published package to this repository. A
# GHCR package pushed without it is orphaned: it exists, but it is not attached
# to the repo, does not inherit its visibility, and cannot be pulled by anyone
# who was told to pull it. The failure looks like a permissions problem and is
# not one.
LABEL org.opencontainers.image.source="https://github.com/DAVANO-INNOVATION-LAB/tessera"
LABEL org.opencontainers.image.description="Scan model artifacts and produce a provable AI bill of materials"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.title="Tessera"

COPY --from=build /out/tessera         /usr/local/bin/tessera
COPY --from=build /out/tessera-studio  /usr/local/bin/tessera-studio
COPY --from=build /out/tessera-sign    /usr/local/bin/tessera-sign
COPY --from=build /out/tessera-bundle  /usr/local/bin/tessera-bundle

# Models mount read-only. The application never writes to them, and saying so in
# the image is worth more than saying so in a document nobody reads.
VOLUME ["/models"]
EXPOSE 7777
USER nonroot:nonroot

# Binding to every interface is the container's default and only the container's:
# inside one, loopback is unreachable from outside, so the host decides exposure
# by how it publishes the port. The standalone binary still defaults to loopback,
# because on a laptop the default should be the safe one.
ENTRYPOINT ["/usr/local/bin/tessera-studio"]
CMD ["--addr", "0.0.0.0:7777", "/models"]
