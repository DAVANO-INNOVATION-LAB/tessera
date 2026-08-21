package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OIDC sign-in, implemented against the standard library.
//
// Authorization code with PKCE, which is the flow that does not depend on the
// client secret staying secret. The secret is still sent when one is
// configured, because confidential clients are the common enterprise
// registration, but the exchange is bound to a code verifier as well so an
// intercepted code is useless on its own.
//
// What is deliberately not here: local validation of the ID token's signature.
// This server exchanges the code at the token endpoint over TLS and then calls
// the userinfo endpoint, both directly with the provider. That is a weaker
// pattern than verifying a JWT offline in one respect — it costs a round trip —
// and a stronger one in another: there is no JWKS cache to go stale, no
// algorithm-confusion surface, and no way to accept a token signed with `none`.
// For a single-tenant local tool, the round trip is the better trade. If this
// ever fronts high-traffic multi-tenant use, revisit it deliberately rather
// than by drift.

// OIDCConfig is what an operator supplies to require a signed-in user.
type OIDCConfig struct {
	// Issuer is the provider's base URL. Its discovery document is fetched
	// once at startup, so a misconfigured issuer fails at boot rather than at
	// the first person's first login.
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURL must match what is registered with the provider exactly.
	RedirectURL string
	// Scopes defaults to openid, profile, email.
	Scopes []string
	// AllowedEmails, when non-empty, restricts access to these addresses.
	// Without it, anyone the provider will authenticate can sign in — which is
	// correct for a single-tenant deployment and wrong for a public issuer, so
	// the distinction is the operator's to make explicitly.
	AllowedEmails []string
	// AllowedDomains restricts by email domain, for the common case of "anyone
	// at our company".
	AllowedDomains []string

	discovery *oidcDiscovery
	states    sync.Map // state -> pendingLogin
	sessions  sync.Map // session id -> session
}

type oidcDiscovery struct {
	Issuer        string `json:"issuer"`
	AuthURL       string `json:"authorization_endpoint"`
	TokenURL      string `json:"token_endpoint"`
	UserInfoURL   string `json:"userinfo_endpoint"`
	JWKSURL       string `json:"jwks_uri"`
	EndSessionURL string `json:"end_session_endpoint"`
}

type pendingLogin struct {
	verifier string
	returnTo string
	created  time.Time
}

type session struct {
	Email   string
	Name    string
	Subject string
	Expires time.Time
}

// Discover fetches the provider's configuration. Called once at startup so a
// bad issuer is a boot failure rather than a runtime surprise for whoever tries
// to sign in first.
func (c *OIDCConfig) Discover(ctx context.Context) error {
	if c.Issuer == "" || c.ClientID == "" {
		return fmt.Errorf("oidc needs at least an issuer and a client id")
	}
	if c.RedirectURL == "" {
		return fmt.Errorf("oidc needs a redirect URL, and it must match the one registered with the provider")
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "profile", "email"}
	}

	u := strings.TrimSuffix(c.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("oidc discovery at %s: %w", u, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc discovery at %s returned %s", u, res.Status)
	}
	var d oidcDiscovery
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&d); err != nil {
		return fmt.Errorf("oidc discovery document: %w", err)
	}
	if d.AuthURL == "" || d.TokenURL == "" {
		return fmt.Errorf("oidc discovery document is missing an authorization or token endpoint")
	}
	// The issuer in the document must match what was configured. A mismatch is
	// how a redirect to an attacker-controlled provider goes unnoticed.
	if d.Issuer != "" && strings.TrimSuffix(d.Issuer, "/") != strings.TrimSuffix(c.Issuer, "/") {
		return fmt.Errorf("oidc discovery reports issuer %q but %q was configured", d.Issuer, c.Issuer)
	}
	c.discovery = &d
	return nil
}

// startLogin redirects the browser to the provider.
func (s *Server) startLogin(w http.ResponseWriter, r *http.Request) {
	c := s.Auth.OIDC
	if c == nil || c.discovery == nil {
		http.Error(w, "sign-in is not configured", http.StatusInternalServerError)
		return
	}
	state, err := randomURLSafe(24)
	if err != nil {
		http.Error(w, "could not start sign-in", http.StatusInternalServerError)
		return
	}
	verifier, err := randomURLSafe(48)
	if err != nil {
		http.Error(w, "could not start sign-in", http.StatusInternalServerError)
		return
	}
	c.states.Store(state, pendingLogin{
		verifier: verifier,
		returnTo: safeReturn(r.URL.RequestURI()),
		created:  time.Now(),
	})
	c.sweep()

	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.ClientID},
		"redirect_uri":          {c.RedirectURL},
		"scope":                 {strings.Join(c.Scopes, " ")},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, c.discovery.AuthURL+"?"+q.Encode(), http.StatusFound)
}

// handleCallback completes the exchange.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	c := s.Auth.OIDC
	if c == nil || c.discovery == nil {
		http.Error(w, "sign-in is not configured", http.StatusInternalServerError)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		// The provider's own message is shown, not invented, but it is escaped
		// on the way out because it is attacker-influenced text.
		http.Error(w, "sign-in failed: "+sanitize(e), http.StatusForbidden)
		return
	}
	state := r.URL.Query().Get("state")
	v, ok := c.states.LoadAndDelete(state)
	if !ok {
		// Single use. A replayed state is either a stale tab or an attempt.
		http.Error(w, "sign-in request is not recognised or has expired", http.StatusForbidden)
		return
	}
	pending := v.(pendingLogin)
	if time.Since(pending.created) > 10*time.Minute {
		http.Error(w, "sign-in request expired", http.StatusForbidden)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "no authorization code", http.StatusBadRequest)
		return
	}

	tok, err := c.exchange(r.Context(), code, pending.verifier)
	if err != nil {
		http.Error(w, "sign-in failed", http.StatusForbidden)
		return
	}
	info, err := c.userinfo(r.Context(), tok)
	if err != nil {
		http.Error(w, "sign-in failed", http.StatusForbidden)
		return
	}
	if err := c.permitted(info); err != nil {
		http.Error(w, sanitize(err.Error()), http.StatusForbidden)
		return
	}

	id, err := randomURLSafe(32)
	if err != nil {
		http.Error(w, "could not complete sign-in", http.StatusInternalServerError)
		return
	}
	c.sessions.Store(id, session{
		Email: info.Email, Name: info.Name, Subject: info.Subject,
		Expires: time.Now().Add(12 * time.Hour),
	})
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure:  r.TLS != nil,
		Expires: time.Now().Add(12 * time.Hour),
	})
	http.Redirect(w, r, pending.returnTo, http.StatusFound)
}

// handleLogout drops the session.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c := s.Auth.OIDC; c != nil {
		if ck, err := r.Cookie(sessionCookie); err == nil {
			c.sessions.Delete(ck.Value)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) validSession(r *http.Request) bool {
	c := s.Auth.OIDC
	if c == nil {
		return false
	}
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	v, ok := c.sessions.Load(ck.Value)
	if !ok {
		return false
	}
	sess := v.(session)
	if time.Now().After(sess.Expires) {
		c.sessions.Delete(ck.Value)
		return false
	}
	return true
}

type userinfo struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
}

func (c *OIDCConfig) exchange(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.RedirectURL},
		"client_id":     {c.ClientID},
		"code_verifier": {verifier},
	}
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.discovery.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %s", res.Status)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("token endpoint returned no access token")
	}
	return out.AccessToken, nil
}

func (c *OIDCConfig) userinfo(ctx context.Context, token string) (userinfo, error) {
	var u userinfo
	if c.discovery.UserInfoURL == "" {
		return u, fmt.Errorf("provider publishes no userinfo endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.discovery.UserInfoURL, nil)
	if err != nil {
		return u, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return u, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return u, fmt.Errorf("userinfo returned %s", res.Status)
	}
	err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&u)
	return u, err
}

// permitted applies the allow lists.
//
// An empty allow list means "anyone this provider authenticates", which is
// right for a company issuer and wrong for a public one. The choice is left to
// the operator rather than guessed, but the failure is explicit either way.
func (c *OIDCConfig) permitted(u userinfo) error {
	if len(c.AllowedEmails) == 0 && len(c.AllowedDomains) == 0 {
		return nil
	}
	email := strings.ToLower(strings.TrimSpace(u.Email))
	if email == "" {
		return fmt.Errorf("access is restricted by email and the provider returned none")
	}
	for _, a := range c.AllowedEmails {
		if strings.EqualFold(a, email) {
			return nil
		}
	}
	if at := strings.LastIndex(email, "@"); at >= 0 {
		domain := email[at+1:]
		for _, d := range c.AllowedDomains {
			if strings.EqualFold(strings.TrimPrefix(d, "@"), domain) {
				return nil
			}
		}
	}
	return fmt.Errorf("this account is not permitted to use this instance")
}

// sweep drops abandoned login attempts so a stream of unfinished sign-ins
// cannot grow without bound.
func (c *OIDCConfig) sweep() {
	cutoff := time.Now().Add(-15 * time.Minute)
	c.states.Range(func(k, v any) bool {
		if p, ok := v.(pendingLogin); ok && p.created.Before(cutoff) {
			c.states.Delete(k)
		}
		return true
	})
}

// safeReturn keeps a post-login redirect inside this server. An open redirect
// here would let a sign-in link deliver somebody to another site wearing this
// one's context.
func safeReturn(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "/"
	}
	return raw
}

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
