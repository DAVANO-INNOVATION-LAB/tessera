package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/studio/internal/store"
)

// Platform connections, authentication settings and backups, over HTTP.
//
// One rule governs this whole file: **a secret goes in and never comes out.**
// Every response is redacted, an edit form receives a blank secret field, and a
// blank field on save means "unchanged" rather than "cleared". Clearing is its
// own endpoint, because "leave it alone" and "delete it" must not be the same
// gesture performed by accident.
//
// The second rule concerns authentication, and it is the one that would be easy
// to get catastrophically wrong: **changing how the server authenticates
// requires being authenticated by the current settings.** A settings page that
// let an anonymous caller disable sign-in would be a hole with an administration
// interface attached. Where no authentication is configured, the server is
// loopback-only by the rule in auth.go, so the caller is already someone with an
// account on the machine — which is the same trust boundary.

const maxBodyBytes = 1 << 20

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, userErrf("no configuration store: start with --config to enable connections"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]any{
			"connections": s.Store.Connections(),
			"kinds":       store.Kinds(),
			"configPath":  s.Store.Path(),
		})
	case http.MethodPost:
		var c store.Connection
		if err := decodeBody(r, &c); err != nil {
			writeErr(w, http.StatusBadRequest, asUserError(err))
			return
		}
		saved, err := s.Store.Save(c)
		if err != nil {
			writeErr(w, http.StatusBadRequest, asUserError(err))
			return
		}
		writeJSON(w, saved)
	default:
		writeErr(w, http.StatusMethodNotAllowed, userErrf("method not allowed"))
	}
}

func (s *Server) handleConnection(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, userErrf("no configuration store"))
		return
	}
	id := r.PathValue("id")
	switch r.Method {
	case http.MethodDelete:
		if err := s.Store.Delete(id); err != nil {
			writeErr(w, http.StatusNotFound, asUserError(err))
			return
		}
		writeJSON(w, map[string]any{"deleted": id})
	default:
		writeErr(w, http.StatusMethodNotAllowed, userErrf("method not allowed"))
	}
}

func (s *Server) handleConnectionSecret(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, userErrf("no configuration store"))
		return
	}
	if err := s.Store.ClearSecret(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, asUserError(err))
		return
	}
	writeJSON(w, map[string]any{"cleared": true})
}

// handleConnectionTest reaches the configured endpoint and reports what
// happened.
//
// This exists because "saved" and "works" are different facts, and an interface
// that only ever shows the first sends people to debug a scan when the problem
// was a typo in a hostname. The result is stored, so the list can show whether a
// connection has ever actually succeeded rather than only that it exists.
func (s *Server) handleConnectionTest(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, userErrf("no configuration store"))
		return
	}
	id := r.PathValue("id")
	conn, ok := s.Store.Connection(id)
	if !ok {
		writeErr(w, http.StatusNotFound, userErrf("no connection with that id"))
		return
	}

	ctx, cancel := contextWithTimeout(r, 20*time.Second)
	defer cancel()

	ok, msg := probe(ctx, conn)
	if err := s.Store.RecordCheck(id, ok, msg); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"ok": ok, "message": msg})
}

// probe performs the cheapest request that distinguishes "reachable and
// authorised" from "not".
//
// Deliberately shallow. A connection test that pulled a model would take
// minutes and fail for reasons unrelated to the connection; what an operator
// needs to know here is whether the address is right and the credential is
// accepted.
func probe(ctx context.Context, c store.Connection) (bool, string) {
	switch c.Kind {
	case store.KindLocal:
		return true, "local paths need no connection test"

	case store.KindMLflow, store.KindKubeflow, store.KindHuggingFace, store.KindOCI:
		if c.Endpoint == "" {
			return false, "no endpoint configured"
		}
		u, err := url.Parse(c.Endpoint)
		if err != nil || u.Host == "" {
			return false, "endpoint is not a valid URL"
		}
		if u.Scheme == "http" && !c.Insecure {
			return false, "endpoint is plain HTTP; tick 'allow insecure' if that is intended"
		}
		return httpProbe(c)

	default:
		// The cloud kinds need their SDKs, which live in the fetch module rather
		// than here. Saying so is better than a green tick that means nothing.
		if c.Endpoint == "" && c.Region == "" {
			return false, "needs an endpoint or a region"
		}
		return true, "saved; this kind is verified when a scan first uses it"
	}
}

func httpProbe(c store.Connection) (bool, string) {
	req, err := http.NewRequest(http.MethodGet, c.Endpoint, nil)
	if err != nil {
		return false, "endpoint is not a valid URL"
	}
	if c.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.Secret)
	}
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		// The error text can contain the endpoint, which is not secret, but it
		// can also contain a proxy URL carrying credentials. Only the shape is
		// reported.
		return false, "could not reach the endpoint"
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))

	switch {
	case res.StatusCode == http.StatusUnauthorized, res.StatusCode == http.StatusForbidden:
		return false, fmt.Sprintf("reached the endpoint, but it refused the credential (%s)", res.Status)
	case res.StatusCode >= 500:
		return false, fmt.Sprintf("endpoint returned %s", res.Status)
	default:
		return true, fmt.Sprintf("reachable (%s)", res.Status)
	}
}

// handleAuthSettings reads and writes authentication configuration.
//
// The write path is the sensitive one. It is reachable only through the
// authenticated mux, so an anonymous caller cannot disable sign-in; where no
// authentication is configured the server is loopback-only, so the caller
// already has an account on the machine.
func (s *Server) handleAuthSettings(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, userErrf("no configuration store"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		cur := s.Store.Auth()
		writeJSON(w, map[string]any{
			"settings": cur.Redacted(),
			// Whether a secret is set is useful; its value is not.
			"oidcClientSecretSet": cur.OIDCClientSecret != "",
			"tokenSet":            cur.TokenHash != "" || s.Auth.Token != "",
			"activeMode":          s.activeAuthMode(),
			// Changing these needs a restart, and saying so beats somebody
			// wondering why the setting "did not take".
			"appliesOnRestart": true,
		})

	case http.MethodPut:
		var in store.AuthSettings
		if err := decodeBody(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, asUserError(err))
			return
		}
		if in.OIDCIssuer != "" {
			if err := validateOIDC(in); err != nil {
				writeErr(w, http.StatusBadRequest, asUserError(err))
				return
			}
		}
		if err := s.Store.SetAuth(in); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, map[string]any{"saved": true, "appliesOnRestart": true})

	default:
		writeErr(w, http.StatusMethodNotAllowed, userErrf("method not allowed"))
	}
}

// validateOIDC catches the mistakes that otherwise present as a broken login
// for everyone, after a restart, with no obvious cause.
func validateOIDC(a store.AuthSettings) error {
	if a.OIDCClientID == "" {
		return fmt.Errorf("an OIDC issuer needs a client id")
	}
	if a.OIDCRedirectURL == "" {
		return fmt.Errorf("an OIDC issuer needs a redirect URL, matching the one registered with the provider")
	}
	u, err := url.Parse(a.OIDCIssuer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("the issuer must be an absolute URL")
	}
	if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		return fmt.Errorf("the issuer must be https except on loopback: an OIDC exchange over plain HTTP is interceptable")
	}
	ru, err := url.Parse(a.OIDCRedirectURL)
	if err != nil || ru.Scheme == "" || ru.Host == "" {
		return fmt.Errorf("the redirect URL must be absolute")
	}
	if !strings.HasSuffix(ru.Path, "/auth/callback") {
		return fmt.Errorf("the redirect URL must end in /auth/callback, which is where this server listens")
	}
	return nil
}

func (s *Server) activeAuthMode() string {
	switch {
	case s.Auth.OIDC != nil:
		return "oidc"
	case s.Auth.Token != "":
		return "token"
	default:
		return "none"
	}
}

// handleSnapshot exports the configuration for backup.
//
// Secrets are excluded unless explicitly requested, and the response says which
// kind it is. A backup that silently contains registry credentials is a
// credential leak wearing the word "backup": it ends up in object storage, in a
// ticket, in a chat message, because nobody handles a backup like a secret
// unless told to.
func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, userErrf("no configuration store"))
		return
	}
	withSecrets := r.URL.Query().Get("secrets") == "include"
	snap := s.Store.Snapshot(withSecrets)

	name := "tessera-config"
	if withSecrets {
		name += "-with-secrets"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", name+"-"+time.Now().UTC().Format("20060102")+".json"))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(snap)
}

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, userErrf("no configuration store"))
		return
	}
	var cfg store.Config
	if err := decodeBody(r, &cfg); err != nil {
		writeErr(w, http.StatusBadRequest, asUserError(err))
		return
	}
	missing, err := s.Store.Restore(cfg)
	if err != nil {
		writeErr(w, http.StatusBadRequest, asUserError(err))
		return
	}
	writeJSON(w, map[string]any{
		"restored": len(cfg.Connections),
		// Named, not counted. A restored connection that fails at the first
		// scan looks like an outage and is a missing credential.
		"missingSecrets": missing,
	})
}

func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("request body: %w", err)
	}
	return nil
}

// contextWithTimeout bounds a probe so a hung endpoint cannot occupy a request
// slot indefinitely.
func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}
