package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Authentication, and the rule that makes it matter.
//
// The Host check in server.go is a DNS-rebinding guard. It stops a page the
// user visits from reading this server's responses, and it is genuinely load
// bearing for that. It is not authentication: `curl -H "Host: localhost"` from
// another machine passes it and receives the full model listing.
//
// That was survivable while the server only ever bound to loopback. It stopped
// being survivable the moment it shipped in a container binding 0.0.0.0, where
// anything that can reach the port can browse and scan every mounted model.
//
// So the rule enforced here is: **a non-loopback bind requires authentication.**
// Not "should have" — the server refuses to start otherwise. An operator who
// genuinely wants an open port on a trusted network has to say so explicitly,
// because the difference between "I decided this" and "I did not realise" is
// the entire distance between a deployment and an incident.

// Auth is how a request proves who it is. The zero value means no
// authentication, which is only permitted on a loopback bind.
type Auth struct {
	// Token, when set, is a bearer token accepted in an Authorization header
	// or a session cookie. Suitable for CI, scripts and single-operator use.
	Token string

	// OIDC, when set, requires a signed-in user. It takes precedence over
	// Token for browser traffic; Token still works for programmatic callers so
	// a pipeline does not need an interactive login.
	OIDC *OIDCConfig

	// InsecureNoAuth allows a non-loopback bind with no authentication. It
	// exists so the refusal below can be overridden deliberately rather than
	// worked around by someone who does not understand what they are turning
	// off, and it says so on every start.
	InsecureNoAuth bool
}

// Enabled reports whether any authentication is configured.
func (a Auth) Enabled() bool { return a.Token != "" || a.OIDC != nil }

// CheckBind refuses a configuration that would expose an unauthenticated server
// beyond the machine it runs on.
//
// Returning an error rather than warning is the point. A warning on stderr in a
// container is a line nobody reads, and the failure it precedes is silent —
// the server works perfectly, for everyone.
func (a Auth) CheckBind(addr string) error {
	if a.Enabled() || a.InsecureNoAuth {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")

	// An empty host or 0.0.0.0 means every interface, which is the case that
	// matters most and the one a container produces by default.
	if host == "" || host == "0.0.0.0" || host == "::" {
		return fmt.Errorf(
			"refusing to listen on %s without authentication: this exposes every "+
				"model under the served directory to anything that can reach the port.\n"+
				"Set --auth-token (or TESSERA_AUTH_TOKEN), configure --oidc-issuer, "+
				"or pass --insecure-no-auth if the network is genuinely trusted", addr)
	}
	if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
		return fmt.Errorf(
			"refusing to listen on %s without authentication: %s is not a loopback "+
				"address.\nSet --auth-token (or TESSERA_AUTH_TOKEN), configure "+
				"--oidc-issuer, or pass --insecure-no-auth if the network is genuinely trusted",
			addr, host)
	}
	return nil
}

// sessionCookie is the browser's proof of a completed sign-in.
const sessionCookie = "tessera_session"

// require wraps a handler with whatever authentication is configured.
//
// Order is deliberate: a bearer token is checked before a session, so a script
// carrying a token is never redirected into an interactive login it cannot
// complete.
func (s *Server) require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Auth.Enabled() {
			next.ServeHTTP(w, r)
			return
		}

		// A token in the query string is accepted exactly once, exchanged for a
		// cookie, and then stripped by redirecting to the same URL without it.
		// Tokens in URLs end up in browser history, referrer headers and proxy
		// logs; carrying it for one request is the cost of a link somebody can
		// paste, and keeping it there afterwards is not.
		if s.Auth.Token != "" && r.URL.Query().Get("token") != "" {
			if subtleEqual(r.URL.Query().Get("token"), s.Auth.Token) {
				http.SetCookie(w, &http.Cookie{
					Name: sessionCookie, Value: s.Auth.Token, Path: "/",
					HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil,
				})
				q := r.URL.Query()
				q.Del("token")
				clean := r.URL.Path
				if e := q.Encode(); e != "" {
					clean += "?" + e
				}
				http.Redirect(w, r, clean, http.StatusFound)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="tessera"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		if s.Auth.Token != "" && tokenMatches(r, s.Auth.Token) {
			next.ServeHTTP(w, r)
			return
		}

		if s.Auth.OIDC != nil {
			if s.validSession(r) {
				next.ServeHTTP(w, r)
				return
			}
			// A browser navigating to a page gets sent to sign in; anything
			// else gets a status it can act on, because redirecting an API
			// client to an identity provider produces a confusing HTML body
			// where JSON was expected.
			if isBrowserNavigation(r) {
				s.startLogin(w, r)
				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Bearer realm="tessera"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
	})
}

// tokenMatches compares in constant time. A timing-variable comparison on a
// bearer token is a slow but real oracle, and the fix costs nothing.
func tokenMatches(r *http.Request, want string) bool {
	got := ""
	if h := r.Header.Get("Authorization"); h != "" {
		if after, ok := strings.CutPrefix(h, "Bearer "); ok {
			got = after
		}
	}
	if got == "" {
		if c, err := r.Cookie(sessionCookie); err == nil {
			got = c.Value
		}
	}
	if got == "" {
		return false
	}
	// Hash both sides first so the comparison is over fixed-length values and
	// cannot leak the token's length.
	a := sha256.Sum256([]byte(got))
	b := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// isBrowserNavigation distinguishes a person following a link from a script
// calling the API. Sec-Fetch-Mode is set by every current browser and cannot be
// set by fetch() from a page, which makes it a better signal than Accept.
func isBrowserNavigation(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Mode") == "navigate" {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html") &&
		!strings.HasPrefix(r.URL.Path, "/api/")
}

// randomToken generates a token for an operator who did not supply one.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "tss_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// fingerprint renders a short, non-reversible identifier for a token so logs
// and the interface can refer to a session without printing the secret.
func fingerprint(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:4])
}

// IsExposedBind reports whether an address reaches beyond this machine.
func IsExposedBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback()
	}
	// A hostname that is not obviously loopback is treated as exposed. Being
	// wrong in this direction costs a token nobody needed; being wrong the
	// other way costs the model directory.
	return host != "localhost"
}

// GenerateToken mints a random bearer token.
func GenerateToken() (string, error) { return randomToken() }

// Fingerprint renders a short non-reversible identifier for a token, so it can
// be referred to without being printed again.
func Fingerprint(tok string) string { return fingerprint(tok) }

// subtleEqual compares two secrets in constant time over fixed-length digests,
// so neither the value nor its length is leaked by timing.
func subtleEqual(got, want string) bool {
	a := sha256.Sum256([]byte(got))
	b := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
