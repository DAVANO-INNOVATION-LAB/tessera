package resolver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseKubeflowURI(t *testing.T) {
	for _, tc := range []struct {
		uri, host, model, version string
		wantErr                   bool
	}{
		{uri: "kubeflow://mr.example.com/fraud", host: "mr.example.com", model: "fraud"},
		{uri: "kubeflow://mr.example.com/fraud/v2", host: "mr.example.com", model: "fraud", version: "v2"},
		{uri: "kubeflow://mr:8080/a-b_c", host: "mr:8080", model: "a-b_c"},
		{uri: "kubeflow:///fraud", wantErr: true},
		{uri: "kubeflow://mr.example.com/", wantErr: true},
		{uri: "kubeflow://mr.example.com/a/b/c", wantErr: true},
		{uri: "s3://bucket/key", wantErr: true},
		{uri: "not a uri at all", wantErr: true},
	} {
		t.Run(tc.uri, func(t *testing.T) {
			h, m, v, err := ParseKubeflowURI(tc.uri)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q/%q/%q", h, m, v)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h != tc.host || m != tc.model || v != tc.version {
				t.Errorf("got %q/%q/%q, want %q/%q/%q", h, m, v, tc.host, tc.model, tc.version)
			}
		})
	}
}

// registryServer stands in for a Model Registry, speaking the paths and field
// names from its published OpenAPI document.
func registryServer(t *testing.T, artifacts []kfModelArtifact, versions []kfModelVersion) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc(apiBase+"/registered_models", func(w http.ResponseWriter, r *http.Request) {
		write(w, kfList[kfRegisteredModel]{Items: []kfRegisteredModel{{ID: "7", Name: "fraud"}}})
	})
	mux.HandleFunc(apiBase+"/registered_models/7/versions", func(w http.ResponseWriter, r *http.Request) {
		write(w, kfList[kfModelVersion]{Items: versions})
	})
	for _, v := range versions {
		id := v.ID
		mux.HandleFunc(apiBase+"/model_versions/"+id+"/artifacts", func(w http.ResponseWriter, r *http.Request) {
			write(w, kfList[kfModelArtifact]{Items: artifacts})
		})
	}
	return httptest.NewServer(mux)
}

// "Latest" is derived from creation time, not from list order. The API
// documents neither an ordering nor a latest pointer, and depending on an
// undocumented order is how a scan silently starts checking the wrong model.
func TestKubeflowPicksLatestByCreationTimeNotListOrder(t *testing.T) {
	staged := t.TempDir()
	src := filepath.Join(t.TempDir(), "model.safetensors")
	os.WriteFile(src, []byte("weights"), 0o644)

	versions := []kfModelVersion{
		{ID: "1", Name: "v1", CreateTimeSinceEpoch: "1000"},
		{ID: "3", Name: "v3", CreateTimeSinceEpoch: "3000"},
		{ID: "2", Name: "v2", CreateTimeSinceEpoch: "2000"},
	}
	srv := registryServer(t, []kfModelArtifact{
		{ID: "9", Name: "m", URI: "file://" + src, ArtifactType: "model-artifact"},
	}, versions)
	defer srv.Close()

	k := &KubeflowResolver{
		HTTPClient: srv.Client(),
		Registry:   stubRegistry(t, src),
	}
	// Point the resolver at the test server rather than https://host.
	art, err := k.resolveAgainst(context.Background(), srv.URL, "fraud", "", staged)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(art.URI, "/v3") {
		t.Errorf("picked %q; v3 is the most recently created", art.URI)
	}
}

// A version carrying documentation alongside the model must not stage the
// README. Picking the first entry would sometimes do exactly that.
func TestKubeflowSkipsNonModelArtifacts(t *testing.T) {
	staged := t.TempDir()
	src := filepath.Join(t.TempDir(), "model.safetensors")
	os.WriteFile(src, []byte("weights"), 0o644)

	srv := registryServer(t, []kfModelArtifact{
		{ID: "8", Name: "readme", URI: "file:///nope", ArtifactType: "doc-artifact"},
		{ID: "9", Name: "model", URI: "file://" + src, ArtifactType: "model-artifact"},
	}, []kfModelVersion{{ID: "1", Name: "v1", CreateTimeSinceEpoch: "1"}})
	defer srv.Close()

	k := &KubeflowResolver{HTTPClient: srv.Client(), Registry: stubRegistry(t, src)}
	if _, err := k.resolveAgainst(context.Background(), srv.URL, "fraud", "", staged); err != nil {
		t.Fatalf("staged the wrong artifact or failed: %v", err)
	}
}

// A registry entry with metadata but no location must say so plainly. The API
// explicitly permits an empty uri, and letting that fall through produces a
// confusing failure in whichever resolver receives an empty string.
func TestKubeflowReportsAnEntryWithNoArtifactURI(t *testing.T) {
	srv := registryServer(t,
		[]kfModelArtifact{{ID: "9", Name: "model", URI: "", ArtifactType: "model-artifact"}},
		[]kfModelVersion{{ID: "1", Name: "v1", CreateTimeSinceEpoch: "1"}})
	defer srv.Close()

	k := &KubeflowResolver{HTTPClient: srv.Client(), Registry: NewRegistry()}
	_, err := k.resolveAgainst(context.Background(), srv.URL, "fraud", "", t.TempDir())
	if err == nil {
		t.Fatal("an entry with no artifact URI resolved successfully")
	}
	if !strings.Contains(err.Error(), "no artifact URI") {
		t.Errorf("unhelpful error for a locationless entry: %v", err)
	}
}

// A refused credential must be distinguishable from an unreachable host, or
// somebody debugs a network problem that is actually a token problem.
func TestKubeflowDistinguishesAuthFailureFromUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	k := &KubeflowResolver{HTTPClient: srv.Client(), Registry: NewRegistry()}
	_, err := k.resolveAgainst(context.Background(), srv.URL, "fraud", "", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "refused the credential") {
		t.Errorf("got %v, want a credential-specific message", err)
	}
}

// stubRegistry resolves file:// URIs to a staged copy, standing in for whatever
// backend the model registry points at.
func stubRegistry(t *testing.T, src string) *Registry {
	t.Helper()
	r := &Registry{}
	r.Register(&fileStub{src: src})
	return r
}

type fileStub struct{ src string }

func (f *fileStub) Scheme() string { return "file" }
func (f *fileStub) Resolve(ctx context.Context, uri, destDir string) (*Artifact, error) {
	data, err := os.ReadFile(f.src)
	if err != nil {
		return nil, err
	}
	out := filepath.Join(destDir, filepath.Base(f.src))
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return nil, err
	}
	return &Artifact{URI: uri, LocalPath: destDir, SizeBytes: int64(len(data))}, nil
}
