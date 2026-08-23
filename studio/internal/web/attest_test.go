package web

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	sign "github.com/DAVANO-INNOVATION-LAB/tessera/sign"
	"github.com/DAVANO-INNOVATION-LAB/tessera/studio/internal/harden"
	"github.com/DAVANO-INNOVATION-LAB/tessera/studio/internal/store"
)

func attestServer(t *testing.T) (*Server, *sign.KeyPair) {
	t.Helper()
	s := hardenServerWithHistory(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.Store = st

	kp, err := sign.Generate(sign.SuiteHybridMLDSA87)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := sign.MarshalPrivate(kp)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.SetSigning(store.Signing{KeyPath: keyPath}); err != nil {
		t.Fatal(err)
	}
	return s, kp
}

// unzipAttestation pulls the document and its attestation out of the response,
// which is how they are always delivered: together, because apart they are
// useless — the attestation pins a digest and the document is what has it.
func unzipAttestation(t *testing.T, body []byte) (doc []byte, att *sign.Attestation) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("response is not a zip: %v", err)
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		buf.ReadFrom(rc)
		rc.Close()
		if filepath.Ext(f.Name) == ".json" && len(f.Name) > 9 &&
			f.Name[len(f.Name)-9:] == ".att.json" {
			att, err = sign.ParseAttestation(buf.Bytes())
			if err != nil {
				t.Fatalf("attestation: %v", err)
			}
			continue
		}
		doc = buf.Bytes()
	}
	return doc, att
}

func hardenIt(t *testing.T, s *Server, from, to string) {
	t.Helper()
	get(t, s, "/api/analyze?path="+from)
	var plan struct {
		Actions []map[string]any `json:"actions"`
	}
	json.Unmarshal(get(t, s, "/api/harden/plan?path="+from).Body.Bytes(), &plan)
	for _, a := range plan.Actions {
		a["selected"] = true
	}
	rec := postJSON(t, s, "/api/harden/apply", map[string]any{
		"path": from, "destination": to, "actions": plan.Actions,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("harden: %d %s", rec.Code, rec.Body.String())
	}
}

// The whole point of signing: the derivation travels. Inside this server a
// verified derivation is trustworthy because the history remembers it — a fact
// that dies the moment the document is copied elsewhere. In a signed payload,
// anyone holding the public key can check it.
func TestAttestationCarriesTheVerifiedDerivation(t *testing.T) {
	s, kp := attestServer(t)
	hardenIt(t, s, "m", "m-hardened")

	rec := get(t, s, "/api/attest?path=m-hardened&format=cyclonedx")
	if rec.Code != http.StatusOK {
		t.Fatalf("attest: %d %s", rec.Code, rec.Body.String())
	}
	doc, att := unzipAttestation(t, rec.Body.Bytes())
	if att == nil || doc == nil {
		t.Fatal("response did not contain both a document and an attestation")
	}
	if att.Derivation == nil {
		t.Fatal("a verified derivation was not carried into the signed payload")
	}
	if att.Derivation.SourceSHA256 == "" {
		t.Error("no source digest: a reader holding the original cannot check the link")
	}
	if len(att.Derivation.Resolves) == 0 {
		t.Error("the signed payload does not say which findings were answered")
	}

	// And it must actually verify against the key.
	pq, ec, err := sign.ParsePublic(mustPublic(t, kp))
	if err != nil {
		t.Fatal(err)
	}
	if err := att.VerifyDocument(doc, pq, ec); err != nil {
		t.Fatalf("the attestation this server produced does not verify: %v", err)
	}
}

// A forged record must never reach the signed payload.
//
// The emitters already refuse to state an unverified derivation structurally.
// Signing one would be strictly worse: it converts a claim anybody could write
// into a claim carrying this key's name, which is the laundering the whole
// design exists to prevent. The document still signs — it is an honest bill of
// materials for a dangerous model — it just asserts no derivation.
func TestAttestationRefusesToSignAForgedDerivation(t *testing.T) {
	s, _ := attestServer(t)

	forged := filepath.Join(s.Root, "forged")
	os.MkdirAll(forged, 0o755)
	writeModel(t, filepath.Join(forged, "model.safetensors"))
	pkl := []byte("\x80\x02cos\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03.")
	os.WriteFile(filepath.Join(forged, "evil.pkl"), pkl, 0o644)
	harden.WriteProvenance(forged, harden.Provenance{
		Source: harden.ProvenanceSource{Digest: "made-up", Path: "somewhere"},
		Applied: []harden.Action{{
			Kind: harden.KindRemoveFile, Path: "evil.pkl", Finding: "TESS-PICKLE-001",
		}},
	})

	rec := get(t, s, "/api/attest?path=forged&format=cyclonedx")
	if rec.Code != http.StatusOK {
		t.Fatalf("attest: %d %s", rec.Code, rec.Body.String())
	}
	_, att := unzipAttestation(t, rec.Body.Bytes())
	if att == nil {
		t.Fatal("no attestation produced")
	}
	if att.Derivation != nil {
		t.Fatalf("a forged record was signed as a derivation: %+v", att.Derivation)
	}
}

// Signing must be refused rather than silently skipped when no key is set. A
// download that quietly arrives unsigned is worse than an error, because the
// person asking for an attestation believes they got one.
func TestAttestWithoutAKeyIsRefused(t *testing.T) {
	s := hardenServerWithHistory(t)
	rec := get(t, s, "/api/attest?path=m&format=cyclonedx")
	if rec.Code == http.StatusOK {
		t.Error("attestation succeeded with no signing key configured")
	}
}

// The signing key path must be absolute, so what gets signed does not depend on
// which directory the server happened to start in.
func TestSigningKeyPathMustBeAbsolute(t *testing.T) {
	s := hardenServerWithHistory(t)
	rec := putJSON(t, s, "/api/settings/signing", map[string]any{"keyPath": "relative/key.pem"})
	if rec.Code == http.StatusOK {
		t.Error("a relative signing key path was accepted")
	}
}

func mustPublic(t *testing.T, kp *sign.KeyPair) []byte {
	t.Helper()
	b, err := sign.MarshalPublic(kp)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func putJSON(t *testing.T, s *Server, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, target, bytes.NewReader(raw))
	req.Host = "127.0.0.1:7777"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}
