package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/tessera/studio/internal/harden"
	"github.com/DAVANO-INNOVATION-LAB/tessera/studio/internal/store"
)

// hardenTestServer lays out a directory that has something worth hardening: a
// model file with a pickle beside it, which is the case the plan exists for.
func hardenTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "m")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeModel(t, filepath.Join(dir, "model.safetensors"))
	// Protocol-2 pickle containing a GLOBAL opcode: executes on load.
	pkl := []byte("\x80\x02cos\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03.")
	if err := os.WriteFile(filepath.Join(dir, "tokenizer.pkl"), pkl, 0o644); err != nil {
		t.Fatal(err)
	}
	return &Server{Root: root, Version: "test"}, root
}

func postJSON(t *testing.T, s *Server, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(raw))
	req.Host = "127.0.0.1:7777"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// The destination must come back as the caller expressed it, not as the host
// stores it. resolve rejects absolute paths outright, so returning the resolved
// path made "open the copy" a button that could only ever fail — and leaked the
// host's directory layout into the interface on the way.
func TestHardenApplyReturnsCallerRelativeDestination(t *testing.T) {
	s, _ := hardenTestServer(t)

	var plan struct {
		Actions []map[string]any `json:"actions"`
	}
	rec := get(t, s, "/api/harden/plan?path=m")
	if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected the plan to propose removing the pickle")
	}
	for _, a := range plan.Actions {
		a["selected"] = true
	}

	rec = postJSON(t, s, "/api/harden/apply", map[string]any{
		"path": "m", "destination": "m-hardened", "actions": plan.Actions,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body.String())
	}
	var res struct {
		Destination string `json:"destination"`
		Before      int    `json:"before"`
		After       int    `json:"after"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Destination != "m-hardened" {
		t.Errorf("destination = %q, want the caller's relative path; an absolute "+
			"path cannot be passed back to any other endpoint", res.Destination)
	}
	if res.After >= res.Before {
		t.Errorf("findings %d -> %d: hardening removed nothing", res.Before, res.After)
	}
	if _, err := os.Stat(filepath.Join(s.Root, "m", "tokenizer.pkl")); err != nil {
		t.Error("the original was modified; hardening must only ever write a copy")
	}
	if _, err := os.Stat(filepath.Join(s.Root, "m-hardened", "tokenizer.pkl")); !os.IsNotExist(err) {
		t.Error("the pickle survived into the hardened copy")
	}
}

// The verdict the dialog reports and the verdict shown when that copy is opened
// come from the same gate. Two call sites computing it separately would drift,
// and "Approved" followed one click later by "Quarantined" discredits both.
func TestHardenVerdictMatchesAnalyzingTheCopy(t *testing.T) {
	s, _ := hardenTestServer(t)

	var plan struct {
		Actions []map[string]any `json:"actions"`
	}
	json.Unmarshal(get(t, s, "/api/harden/plan?path=m").Body.Bytes(), &plan)
	for _, a := range plan.Actions {
		a["selected"] = true
	}
	rec := postJSON(t, s, "/api/harden/apply", map[string]any{
		"path": "m", "destination": "m-hardened", "actions": plan.Actions,
	})
	var applied struct {
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &applied); err != nil {
		t.Fatal(err)
	}
	if applied.Verdict == "" {
		t.Fatal("apply reported no verdict; the count alone does not say whether " +
			"the copy can be deployed")
	}

	var analysed struct {
		Verdict struct {
			Verdict string `json:"verdict"`
		} `json:"verdict"`
	}
	body := get(t, s, "/api/analyze?path=m-hardened").Body.Bytes()
	if err := json.Unmarshal(body, &analysed); err != nil {
		t.Fatal(err)
	}
	if analysed.Verdict.Verdict != applied.Verdict {
		t.Errorf("harden reported %q but opening the copy shows %q",
			applied.Verdict, analysed.Verdict.Verdict)
	}
}

// A destination outside the served root is refused. A remediation endpoint that
// wrote anywhere on the host would be a worse hole than any finding it fixes.
func TestHardenApplyRefusesEscapingDestination(t *testing.T) {
	s, _ := hardenTestServer(t)
	for _, dest := range []string{"../escaped", "/tmp/escaped"} {
		rec := postJSON(t, s, "/api/harden/apply", map[string]any{
			"path": "m", "destination": dest, "actions": []map[string]any{},
		})
		if rec.Code == http.StatusOK {
			t.Errorf("destination %q was accepted", dest)
		}
	}
}

// A missing destination is refused rather than defaulted, because every default
// that could be chosen here is a path the caller did not name.
func TestHardenApplyRequiresDestination(t *testing.T) {
	s, _ := hardenTestServer(t)
	rec := postJSON(t, s, "/api/harden/apply", map[string]any{
		"path": "m", "destination": "", "actions": []map[string]any{},
	})
	if rec.Code == http.StatusOK {
		t.Error("apply with no destination was accepted")
	}
}

// hardenServerWithHistory gives the server somewhere to record derivations,
// which is what separates a verified label from a claim.
func hardenServerWithHistory(t *testing.T) *Server {
	t.Helper()
	s, _ := hardenTestServer(t)
	h, err := store.OpenHistory(filepath.Join(t.TempDir(), "scans"))
	if err != nil {
		t.Fatal(err)
	}
	s.History = h
	return s
}

// The label a forger can mint by writing a file must not be the label the
// server issues for work it did.
//
// This is the whole reason HardenedLabel has two booleans. A hardening record
// is an ordinary file in an ordinary directory; anybody who can write a model
// can write one beside it. If the badge came from the file, "hardened" would be
// a property an attacker could grant to an untouched malicious model — turning
// the mark meant to vouch for safety into a laundering mechanism.
func TestForgedHardeningRecordIsNotVerified(t *testing.T) {
	s := hardenServerWithHistory(t)

	// A directory nobody hardened, carrying a record that says otherwise.
	forged := filepath.Join(s.Root, "forged")
	if err := os.MkdirAll(forged, 0o755); err != nil {
		t.Fatal(err)
	}
	writeModel(t, filepath.Join(forged, "model.safetensors"))
	pkl := []byte("\x80\x02cos\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03.")
	os.WriteFile(filepath.Join(forged, "evil.pkl"), pkl, 0o644)
	if err := harden.WriteProvenance(forged, harden.Provenance{
		Source: harden.ProvenanceSource{Digest: "made-up", Path: "somewhere"},
	}); err != nil {
		t.Fatal(err)
	}

	var got struct {
		Hardened *HardenedLabel `json:"hardened"`
	}
	rec := get(t, s, "/api/analyze?path=forged")
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Hardened == nil {
		t.Fatal("the claim was dropped entirely; it should be reported as unverified")
	}
	if !got.Hardened.Claimed {
		t.Error("the record in the directory was not noticed")
	}
	if got.Hardened.Verified {
		t.Fatal("a record written by anyone was accepted as proof of hardening")
	}
	if got.Hardened.Note == "" {
		t.Error("an unverified claim was shown without saying so")
	}
}

// A copy this server actually hardened is verified, labelled, and mapped back
// to what it came from.
func TestHardenedCopyIsLabelledAndMappedToItsSource(t *testing.T) {
	s := hardenServerWithHistory(t)

	// Scan the original first, so history knows it.
	get(t, s, "/api/analyze?path=m")

	var plan struct {
		Actions []map[string]any `json:"actions"`
	}
	json.Unmarshal(get(t, s, "/api/harden/plan?path=m").Body.Bytes(), &plan)
	for _, a := range plan.Actions {
		a["selected"] = true
	}
	rec := postJSON(t, s, "/api/harden/apply", map[string]any{
		"path": "m", "destination": "m-hardened", "actions": plan.Actions,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body.String())
	}

	var got struct {
		Hardened *HardenedLabel `json:"hardened"`
		Artifact struct {
			Files []struct {
				SHA256 string `json:"sha256"`
			} `json:"files"`
		} `json:"artifact"`
	}
	body := get(t, s, "/api/analyze?path=m-hardened").Body.Bytes()
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Hardened == nil || !got.Hardened.Verified {
		t.Fatalf("a copy this server hardened is not labelled verified: %+v", got.Hardened)
	}
	if got.Hardened.Source == nil || got.Hardened.Source.Digest == "" {
		t.Fatal("the label does not say what the copy was derived from")
	}
	if len(got.Hardened.Applied) == 0 {
		t.Error("the label does not say what was changed")
	}

	// And the lineage maps the copy back to the original by digest.
	digest := got.Artifact.Files[0].SHA256
	var lin store.Lineage
	linBody := get(t, s, "/api/lineage?digest="+digest+"&path=m-hardened").Body.Bytes()
	if err := json.Unmarshal(linBody, &lin); err != nil {
		t.Fatal(err)
	}
	if len(lin.Ancestors) == 0 {
		t.Fatalf("no ancestors for a hardened copy: %s", linBody)
	}
	if lin.Ancestors[0].Digest != got.Hardened.Source.Digest {
		t.Errorf("lineage parent %q does not match the recorded source %q",
			lin.Ancestors[0].Digest, got.Hardened.Source.Digest)
	}

	// The original, asked from the other end, knows what came from it.
	var back store.Lineage
	json.Unmarshal(get(t, s, "/api/lineage?digest="+
		got.Hardened.Source.Digest+"&path=m").Body.Bytes(), &back)
	if len(back.Descendants) == 0 {
		t.Error("the original does not list the copy hardened from it")
	}
}

// An ordinary model gets no label at all, rather than a "not hardened" badge on
// every row in the inventory.
func TestUnhardenedArtifactHasNoLabel(t *testing.T) {
	s := hardenServerWithHistory(t)
	var got struct {
		Hardened *HardenedLabel `json:"hardened"`
	}
	json.Unmarshal(get(t, s, "/api/analyze?path=m").Body.Bytes(), &got)
	if got.Hardened != nil {
		t.Errorf("an untouched model was labelled: %+v", got.Hardened)
	}
}

// The bill of materials for a hardened copy declares its pedigree. A document
// for a derivative that does not say what it came from describes an artifact
// that appears to have arrived from nowhere.
func TestBOMForHardenedCopyCarriesPedigree(t *testing.T) {
	s := hardenServerWithHistory(t)
	get(t, s, "/api/analyze?path=m")

	var plan struct {
		Actions []map[string]any `json:"actions"`
	}
	json.Unmarshal(get(t, s, "/api/harden/plan?path=m").Body.Bytes(), &plan)
	for _, a := range plan.Actions {
		a["selected"] = true
	}
	postJSON(t, s, "/api/harden/apply", map[string]any{
		"path": "m", "destination": "m-hardened", "actions": plan.Actions,
	})

	rec := get(t, s, "/api/bom?format=cyclonedx&path=m-hardened")
	if rec.Code != http.StatusOK {
		t.Fatalf("bom: %d %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Metadata struct {
			Component struct {
				Pedigree struct {
					Ancestors []struct {
						Hashes []struct {
							Content string `json:"content"`
						} `json:"hashes"`
					} `json:"ancestors"`
					Patches []struct {
						Type     string `json:"type"`
						Resolves []struct {
							ID   string `json:"id"`
							Type string `json:"type"`
						} `json:"resolves"`
					} `json:"patches"`
					Notes string `json:"notes"`
				} `json:"pedigree"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	p := doc.Metadata.Component.Pedigree
	if len(p.Ancestors) == 0 || len(p.Ancestors[0].Hashes) == 0 {
		t.Fatal("no ancestor carrying a digest: the pedigree is not checkable")
	}
	if len(p.Patches) == 0 {
		t.Fatal("the document does not say what was changed")
	}
	if len(p.Patches[0].Resolves) == 0 || p.Patches[0].Resolves[0].Type != "security" {
		t.Errorf("patch resolves nothing: %+v", p.Patches[0])
	}
}

// A forged record must not put a resolved-finding claim into a document.
//
// This is the laundering case in its most dangerous form: a BOM asserting that
// a pickle was removed, naming this tool as the source of the assertion, for an
// artifact where the pickle is still present and still executes on load.
func TestBOMForForgedRecordAssertsNoRemediation(t *testing.T) {
	s := hardenServerWithHistory(t)

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

	body := get(t, s, "/api/bom?format=cyclonedx&path=forged").Body.String()
	if strings.Contains(body, "TESS-PICKLE-001\"") && strings.Contains(body, "\"resolves\"") {
		t.Error("the document claims a finding was resolved on a forged record's word")
	}
	if strings.Contains(body, `"patches"`) {
		t.Error("a forged record produced patch entries")
	}
	if !strings.Contains(body, "unverified") {
		t.Error("the document does not mention that a claim could not be verified")
	}
	// The pickle is still there, so the scan must still report it.
	if !strings.Contains(get(t, s, "/api/analyze?path=forged").Body.String(), "TESS-PICKLE-001") {
		t.Error("the live pickle stopped being reported")
	}
}
