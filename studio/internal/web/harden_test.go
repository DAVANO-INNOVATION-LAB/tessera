package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
