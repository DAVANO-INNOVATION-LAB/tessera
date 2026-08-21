package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The rule this file exists to enforce. Serving an unauthenticated port beyond
// the machine exposes every model under the served directory, and the Host
// check does not stop it — `curl -H "Host: localhost"` passes that check from
// anywhere. This is the regression test for a hole that shipped.
func TestExposedBindWithoutAuthIsRefused(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:7777", ":7777", "[::]:7777", "192.168.1.5:7777"} {
		if err := (Auth{}).CheckBind(addr); err == nil {
			t.Errorf("%s was accepted with no authentication; anything reaching that port "+
				"could read every model served", addr)
		}
	}
}

// A laptop must stay frictionless. Loopback with no auth is the original design
// and remains correct: nothing off the machine can reach it.
func TestLoopbackWithoutAuthIsAllowed(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:7777", "localhost:7777", "[::1]:7777"} {
		if err := (Auth{}).CheckBind(addr); err != nil {
			t.Errorf("%s was refused: %v", addr, err)
		}
	}
}

func TestAuthOrExplicitOptOutPermitsExposedBind(t *testing.T) {
	if err := (Auth{Token: "x"}).CheckBind("0.0.0.0:7777"); err != nil {
		t.Errorf("a token should permit an exposed bind: %v", err)
	}
	if err := (Auth{InsecureNoAuth: true}).CheckBind("0.0.0.0:7777"); err != nil {
		t.Errorf("an explicit opt-out should permit an exposed bind: %v", err)
	}
}

func authServe(t *testing.T, a Auth) *httptest.Server {
	t.Helper()
	s := &Server{Root: t.TempDir(), Auth: a}
	return httptest.NewServer(s.Handler())
}

func authGet(t *testing.T, ts *httptest.Server, path string, hdr map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "localhost"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	return res.StatusCode
}

// The exact bypass that existed: a forged Host header from anywhere reached the
// API. With a token configured it must not.
func TestForgedHostDoesNotBypassToken(t *testing.T) {
	ts := authServe(t, Auth{Token: "sekrit"})
	defer ts.Close()

	if code := authGet(t, ts, "/api/browse?path=", nil); code != http.StatusUnauthorized {
		t.Errorf("unauthenticated request returned %d, want 401", code)
	}
	if code := authGet(t, ts, "/api/browse?path=", map[string]string{
		"Authorization": "Bearer sekrit"}); code != http.StatusOK {
		t.Errorf("correct token returned %d, want 200", code)
	}
	if code := authGet(t, ts, "/api/browse?path=", map[string]string{
		"Authorization": "Bearer wrong"}); code != http.StatusUnauthorized {
		t.Errorf("wrong token returned %d, want 401", code)
	}
}

// A token in the query string is a link somebody can paste. It must be
// exchanged for a cookie and removed, because tokens in URLs survive in browser
// history, referrer headers and proxy logs.
func TestQueryTokenIsExchangedAndStripped(t *testing.T) {
	ts := authServe(t, Auth{Token: "linky"})
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/?token=linky", nil)
	req.Host = "localhost"
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusFound {
		t.Fatalf("query token returned %d, want a redirect", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); strings.Contains(loc, "token=") {
		t.Errorf("redirect still carries the token: %s", loc)
	}
	var found bool
	for _, ck := range res.Cookies() {
		if ck.Name == sessionCookie && ck.Value == "linky" {
			found = true
			if !ck.HttpOnly {
				t.Error("session cookie is readable by scripts")
			}
		}
	}
	if !found {
		t.Error("no session cookie was set, so the link works once and never again")
	}

	if code := authGet(t, ts, "/?token=nope", nil); code != http.StatusUnauthorized {
		t.Errorf("a wrong query token returned %d, want 401", code)
	}
}

// No authentication configured means loopback-only use, and the handler must
// stay open there or the laptop case breaks.
func TestNoAuthConfiguredServesNormally(t *testing.T) {
	ts := authServe(t, Auth{})
	defer ts.Close()
	if code := authGet(t, ts, "/api/browse?path=", nil); code != http.StatusOK {
		t.Errorf("unauthenticated loopback use returned %d, want 200", code)
	}
}

func TestIsExposedBind(t *testing.T) {
	for addr, want := range map[string]bool{
		"0.0.0.0:7777":     true,
		":7777":            true,
		"[::]:7777":        true,
		"10.0.0.4:7777":    true,
		"example.com:7777": true,
		"127.0.0.1:7777":   false,
		"localhost:7777":   false,
		"[::1]:7777":       false,
	} {
		if got := IsExposedBind(addr); got != want {
			t.Errorf("IsExposedBind(%q) = %v, want %v", addr, got, want)
		}
	}
}
