// Package fetch stages a model artifact from wherever it lives onto local disk,
// so that something else can read it.
//
// This is the embedding surface. The implementation stays in internal/ so it
// can change without breaking importers.
//
// It is a separate module from tessera because fetching is where the
// dependencies are: an S3 client, an OCI registry client, HTTP. Parsing a model
// needs none of that, and tessera's zero-dependency guarantee is worth more
// than the convenience of one import path. An embedder that already has the
// bytes never has to see this module at all.
//
// The property that matters most here is that a partial fetch says so. A
// resolver that reads part of an artifact — because a range request was used,
// or a cap was hit — records what it actually read, and a scan over a partial
// fetch is not entitled to report a clean result. "No findings" across files
// that were never retrieved is not the same statement as "no findings", and
// only the resolver knows which one is being made.
package fetch

import (
	"context"

	"github.com/DAVANO-INNOVATION-LAB/tessera/fetch/internal/resolver"
)

type (
	// Artifact is a staged artifact on local disk.
	Artifact = resolver.Artifact
	// Coverage records what a partial fetch actually read. Nil means the whole
	// artifact was staged.
	Coverage = resolver.Coverage
	// Resolver fetches one URI scheme.
	Resolver = resolver.Resolver
	// Registry dispatches a URI to the resolver that handles its scheme.
	Registry = resolver.Registry

	// The individual resolvers, exported so a caller can build a registry with
	// only the backends it wants. An air-gapped deployment that registers only
	// the local resolver cannot accidentally reach the network, which is a
	// stronger guarantee than a flag that asks it not to.
	OCIResolver         = resolver.OCIResolver
	ModelCarResolver    = resolver.ModelCarResolver
	S3Resolver          = resolver.S3Resolver
	PVCResolver         = resolver.PVCResolver
	HuggingFaceResolver = resolver.HuggingFaceResolver
	MLflowResolver      = resolver.MLflowResolver
	HTTPResolver        = resolver.HTTPResolver
	// KubeflowResolver reads a model registry entry and follows it to wherever
	// the bytes actually live. Re-exported like the rest so a caller assembling
	// a restricted registry by hand — the air-gapped case — can include it;
	// without the type, that caller could reach every backend except the
	// registry that tells them which backend to use.
	KubeflowResolver = resolver.KubeflowResolver
)

// NewRegistry returns a registry with every built-in resolver registered:
// oci, modelcar, s3, pvc, hf, mlflow, https and http.
//
// Build a Registry directly and register only what you need when the deployment
// should not be able to reach a given backend at all.
func NewRegistry() *Registry { return resolver.NewRegistry() }

// SchemeOf reports the URI scheme, or an error when the URI has none.
func SchemeOf(uri string) (string, error) { return resolver.SchemeOf(uri) }

// Resolve stages the artifact at uri into destDir using the default registry.
func Resolve(ctx context.Context, uri, destDir string) (*Artifact, error) {
	return NewRegistry().Resolve(ctx, uri, destDir)
}

// CanExecuteCode reports whether a filename implies a format that runs code
// when it is loaded. Fetching such a file is not itself dangerous; treating it
// like a safetensors afterwards is.
func CanExecuteCode(name string) bool { return resolver.CanExecuteCode(name) }

// ParseHuggingFaceURI splits an hf:// URI into its repository and revision.
func ParseHuggingFaceURI(uri string) (repo, revision string, err error) {
	return resolver.ParseHuggingFaceURI(uri)
}

// RewriteMLflowURI turns an MLflow artifact URI into one a resolver can fetch,
// given the tracking server it came from.
func RewriteMLflowURI(artifactURI, trackingURL string) (string, bool) {
	return resolver.RewriteMLflowURI(artifactURI, trackingURL)
}

// ParseKubeflowURI splits a kubeflow:// URI into its registry host, registered
// model, and optional version.
func ParseKubeflowURI(uri string) (host, model, version string, err error) {
	return resolver.ParseKubeflowURI(uri)
}
