package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// KubeflowResolver reads the Kubeflow Model Registry and hands back the place a
// model actually lives.
//
// This is the highest-leverage registry to speak to, and not because Kubeflow is
// the most popular: OpenShift AI's model registry *is* Kubeflow's, so one
// connector reaches both. A registry entry is metadata — the bytes sit in S3,
// GCS, an OCI registry or a PVC — so this resolver's job is to walk
// registered model → version → artifact and then hand the artifact's real URI
// to whichever resolver owns that scheme.
//
// URI forms:
//
//	kubeflow://host/<model>                 latest version of a registered model
//	kubeflow://host/<model>/<version>       a named version
//
// The indirection is the whole point. A scan pod given "kubeflow://.../fraud-v2"
// should not need to know that fraud-v2 happens to live in an S3 bucket this
// week and an OCI registry next week; that is precisely the coupling a registry
// exists to remove.
type KubeflowResolver struct {
	HTTPClient *http.Client
	Token      string
	// Insecure reaches the registry over plain HTTP. Needed for the in-cluster
	// service address, which is how OpenShift AI deploys it; never appropriate
	// for a registry reached across a network anyone else is on.
	Insecure bool
	// Registry resolves the URI the model registry points at. Injected rather
	// than constructed so an air-gapped deployment can supply a registry with
	// only the backends it is allowed to reach.
	Registry *Registry
}

// Scheme implements Resolver.
func (k *KubeflowResolver) Scheme() string { return "kubeflow" }

func (k *KubeflowResolver) client() *http.Client {
	if k.HTTPClient != nil {
		return k.HTTPClient
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

// apiBase is the Model Registry's REST prefix, fixed by its OpenAPI document.
const apiBase = "/api/model_registry/v1alpha3"

// kfList is the envelope every list endpoint returns.
type kfList[T any] struct {
	Items []T `json:"items"`
}

type kfRegisteredModel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type kfModelVersion struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// CreateTimeSinceEpoch orders versions when no name is given. The registry
	// does not promise "latest" as a concept, so it has to be derived.
	CreateTimeSinceEpoch string `json:"createTimeSinceEpoch"`
}

type kfModelArtifact struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// URI is where the bytes are. May be empty: the registry explicitly allows
	// an entry with no physical artifact, and that case has to be reported
	// rather than resolved into a confusing failure further down.
	URI                string `json:"uri"`
	ArtifactType       string `json:"artifactType"`
	ModelFormatName    string `json:"modelFormatName"`
	ModelFormatVersion string `json:"modelFormatVersion"`
	StorageKey         string `json:"storageKey"`
	StoragePath        string `json:"storagePath"`
}

// Resolve stages the model the registry entry points at.
func (k *KubeflowResolver) Resolve(ctx context.Context, uri, destDir string) (*Artifact, error) {
	host, model, version, err := ParseKubeflowURI(uri)
	if err != nil {
		return nil, err
	}
	return k.resolveAgainst(ctx, k.baseURL(host), model, version, destDir)
}

// baseURL decides how to reach the registry.
//
// Defaults to https, with an explicit opt-out, because the common in-cluster
// deployment is plain HTTP on a service DNS name —
// model-registry-service.kubeflow.svc.cluster.local:8080 — and that is exactly
// how OpenShift AI ships it. Hardcoding https would have made this connector
// work against a public ingress and fail in the deployment it was written for.
// The opt-out is explicit rather than inferred so nobody downgrades a public
// endpoint by accident.
func (k *KubeflowResolver) baseURL(host string) string {
	scheme := "https://"
	if k.Insecure {
		scheme = "http://"
	}
	return scheme + host
}

// resolveAgainst is the body of Resolve with the registry root supplied, which
// is what lets this be tested against a local server.
func (k *KubeflowResolver) resolveAgainst(ctx context.Context, root, model, version, destDir string) (*Artifact, error) {
	base := root + apiBase
	host := strings.TrimPrefix(strings.TrimPrefix(root, "https://"), "http://")

	rm, err := k.findModel(ctx, base, model)
	if err != nil {
		return nil, err
	}
	mv, err := k.findVersion(ctx, base, rm.ID, version)
	if err != nil {
		return nil, err
	}
	art, err := k.findArtifact(ctx, base, mv.ID)
	if err != nil {
		return nil, err
	}

	if art.URI == "" {
		return nil, fmt.Errorf(
			"model registry entry %q version %q records no artifact URI, so there is "+
				"nothing to fetch; the registry has metadata but no location for the bytes",
			rm.Name, mv.Name)
	}

	// Hand off by scheme. The registry told us where the model lives; it is not
	// this resolver's business to know how to read an S3 bucket.
	if k.Registry == nil {
		return nil, fmt.Errorf("no resolver registry configured to follow %q", art.URI)
	}
	staged, err := k.Registry.Resolve(ctx, art.URI, destDir)
	if err != nil {
		return nil, fmt.Errorf("registry entry %q points at %q: %w", rm.Name, art.URI, err)
	}
	// Report the registry URI rather than the bucket path the registry pointed
	// at. "kubeflow://host/fraud/v2" is what a reviewer recognises; the S3 key
	// underneath it is an implementation detail that changes without the model
	// changing, and a bill of materials naming it would look different every
	// time storage moved.
	staged.URI = fmt.Sprintf("kubeflow://%s/%s/%s", host, rm.Name, mv.Name)
	return staged, nil
}

func (k *KubeflowResolver) findModel(ctx context.Context, base, name string) (*kfRegisteredModel, error) {
	var list kfList[kfRegisteredModel]
	if err := k.get(ctx, base+"/registered_models?pageSize=200", &list); err != nil {
		return nil, err
	}
	for _, m := range list.Items {
		if m.Name == name {
			return &m, nil
		}
	}
	return nil, fmt.Errorf("no registered model named %q in this registry", name)
}

func (k *KubeflowResolver) findVersion(ctx context.Context, base, modelID, want string) (*kfModelVersion, error) {
	var list kfList[kfModelVersion]
	if err := k.get(ctx, base+"/registered_models/"+url.PathEscape(modelID)+"/versions?pageSize=200", &list); err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, fmt.Errorf("registered model has no versions")
	}
	if want != "" {
		for _, v := range list.Items {
			if v.Name == want {
				return &v, nil
			}
		}
		return nil, fmt.Errorf("no version named %q", want)
	}
	// No version named: take the most recently created. Deriving "latest" from
	// creation time rather than from list order, because the API documents
	// neither an ordering nor a latest pointer, and depending on an undocumented
	// order is how a scan silently starts checking the wrong model.
	latest := list.Items[0]
	for _, v := range list.Items[1:] {
		if v.CreateTimeSinceEpoch > latest.CreateTimeSinceEpoch {
			latest = v
		}
	}
	return &latest, nil
}

func (k *KubeflowResolver) findArtifact(ctx context.Context, base, versionID string) (*kfModelArtifact, error) {
	var list kfList[kfModelArtifact]
	if err := k.get(ctx, base+"/model_versions/"+url.PathEscape(versionID)+"/artifacts?pageSize=200", &list); err != nil {
		return nil, err
	}
	for _, a := range list.Items {
		// A version can carry documentation and dataset artifacts alongside the
		// model. Picking the first entry would sometimes stage a README.
		if a.ArtifactType == "" || a.ArtifactType == "model-artifact" {
			return &a, nil
		}
	}
	return nil, fmt.Errorf("version has no model artifact (found %d other artifact(s))", len(list.Items))
}

func (k *KubeflowResolver) get(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if k.Token != "" {
		req.Header.Set("Authorization", "Bearer "+k.Token)
	}
	res, err := k.client().Do(req)
	if err != nil {
		// The URL can carry a proxy credential; only the shape is reported.
		return fmt.Errorf("could not reach the model registry")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		switch res.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Errorf("the model registry refused the credential (%s)", res.Status)
		case http.StatusNotFound:
			return fmt.Errorf("the model registry has no such entry (%s)", res.Status)
		}
		return fmt.Errorf("model registry returned %s", res.Status)
	}
	// Bounded: a registry listing is metadata, and an unbounded read here would
	// let a compromised or misconfigured endpoint exhaust the scan pod.
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

// ParseKubeflowURI splits kubeflow://host/model[/version].
func ParseKubeflowURI(uri string) (host, model, version string, err error) {
	u, perr := url.Parse(uri)
	if perr != nil || u.Scheme != "kubeflow" {
		return "", "", "", fmt.Errorf("not a kubeflow:// URI")
	}
	if u.Host == "" {
		return "", "", "", fmt.Errorf("kubeflow:// URI needs the registry host")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return "", "", "", fmt.Errorf("kubeflow:// URI needs a registered model name")
	}
	if len(parts) > 2 {
		return "", "", "", fmt.Errorf(
			"kubeflow:// URI takes a model and an optional version, got %d path segments", len(parts))
	}
	host, model = u.Host, parts[0]
	if len(parts) == 2 {
		version = parts[1]
	}
	return host, model, version, nil
}
