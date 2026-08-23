// Package store persists what an operator configures through the interface:
// platform connections, authentication, and the settings that outlive a restart.
//
// Three rules shape everything here.
//
// **A secret that has been written is never read back out.** The API returns a
// fingerprint, never the value. An interface that redisplays a stored password
// so the user can "check it" turns every XSS, every shoulder-surf and every
// screenshot into credential disclosure, and it buys nothing — nobody verifies a
// secret by looking at it.
//
// **Writes are atomic.** Configuration is written to a temporary file in the
// same directory and renamed over the target. A half-written config that a tool
// still parses is worse than none, because it fails somewhere further away.
//
// **The file is 0600 and says why.** This holds registry credentials. On a
// shared host, mode alone is the boundary, and it is worth being explicit that
// nothing here is encrypted at rest: an operator who needs that should mount a
// secret rather than believe a claim this package cannot make.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FormatVersion guards the file. A reader that does not recognise it refuses
// rather than guessing, because guessing at the shape of a credential store is
// how a connection silently points somewhere else.
const FormatVersion = 1

// Kind names a platform a connection reaches.
type Kind string

const (
	KindMLflow      Kind = "mlflow"
	KindHuggingFace Kind = "huggingface"
	KindS3          Kind = "s3"
	KindGCS         Kind = "gcs"
	KindAzureBlob   Kind = "azure-blob"
	KindOCI         Kind = "oci"
	KindKubeflow    Kind = "kubeflow"
	KindSageMaker   Kind = "sagemaker"
	KindVertex      Kind = "vertex"
	KindLocal       Kind = "local"
)

// Kinds lists what the interface offers, in the order it should present them.
func Kinds() []Kind {
	return []Kind{
		KindLocal, KindOCI, KindS3, KindHuggingFace, KindMLflow,
		KindKubeflow, KindGCS, KindAzureBlob, KindSageMaker, KindVertex,
	}
}

// Connection is one configured platform.
type Connection struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind Kind   `json:"kind"`
	// Endpoint is the registry or bucket URL, when the kind needs one.
	Endpoint string `json:"endpoint,omitempty"`
	// Path is the prefix or repository within the endpoint.
	Path string `json:"path,omitempty"`
	// Region for the cloud kinds.
	Region string `json:"region,omitempty"`
	// Username, and any non-secret identifier.
	Username string `json:"username,omitempty"`

	// Secret is write-only. It is present in the file and never in a response;
	// see the package comment.
	Secret string `json:"secret,omitempty"`

	// Insecure permits plain HTTP to the endpoint. Recorded so a connection
	// that skips TLS is visible as a decision rather than a default.
	Insecure bool `json:"insecure,omitempty"`

	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`

	// LastCheck records the outcome of the most recent connection test, so the
	// interface can show whether a connection has ever actually worked rather
	// than only that somebody saved it.
	LastCheck *Check `json:"lastCheck,omitempty"`
}

// Check is the result of testing a connection.
type Check struct {
	At      string `json:"at"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

// Redacted returns a copy safe to send to a browser.
func (c Connection) Redacted() Connection {
	out := c
	out.Secret = ""
	return out
}

// SecretFingerprint identifies a stored secret without disclosing it, so the
// interface can show that one is set and whether it changed.
func (c Connection) SecretFingerprint() string {
	if c.Secret == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(c.Secret))
	return hex.EncodeToString(sum[:4])
}

// AuthSettings is authentication as configured through the interface. It
// mirrors the command-line flags; whichever is set last wins, and the file is
// only consulted when the flags left something unset.
type AuthSettings struct {
	// TokenHash stores a bearer token as a digest. The token itself is shown
	// once, when generated, and never again — the same discipline the CLI
	// applies, for the same reason.
	TokenHash string `json:"tokenHash,omitempty"`

	OIDCIssuer       string   `json:"oidcIssuer,omitempty"`
	OIDCClientID     string   `json:"oidcClientId,omitempty"`
	OIDCClientSecret string   `json:"oidcClientSecret,omitempty"`
	OIDCRedirectURL  string   `json:"oidcRedirectUrl,omitempty"`
	AllowedEmails    []string `json:"allowedEmails,omitempty"`
	AllowedDomains   []string `json:"allowedDomains,omitempty"`
}

// Redacted returns a copy safe to send to a browser.
func (a AuthSettings) Redacted() AuthSettings {
	out := a
	out.OIDCClientSecret = ""
	out.TokenHash = ""
	return out
}

// Config is everything persisted.
type Config struct {
	FormatVersion int           `json:"formatVersion"`
	Connections   []Connection  `json:"connections"`
	Auth          AuthSettings  `json:"auth"`
	Suppressions  []Suppression `json:"suppressions,omitempty"`
	Signing       Signing       `json:"signing,omitempty"`
	UpdatedAt     string        `json:"updatedAt"`
}

// Signing configures attestation.
//
// The key is named by path and never held in the config file. A private signing
// key inside a document people export as a "backup", mail to each other and
// paste into tickets is a key that has already leaked; keeping it out of band
// means the snapshot endpoint cannot spill it however it is called.
type Signing struct {
	// KeyPath is a private key PEM on the same host, in the format
	// tessera-sign generates.
	KeyPath string `json:"keyPath,omitempty"`
	// Identity is recorded in attestations so a reader can tell whose key this
	// was without holding the public half.
	Identity string `json:"identity,omitempty"`
}

// Store owns the file. Every mutation writes the whole document, which is
// simple and correct at this size; a connection list is tens of entries, not
// thousands.
type Store struct {
	path string
	mu   sync.RWMutex
	cfg  Config
}

// Open loads the config, creating an empty one if the file does not exist.
func Open(path string) (*Store, error) {
	s := &Store{path: path, cfg: Config{FormatVersion: FormatVersion}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if cfg.FormatVersion != FormatVersion {
		return nil, fmt.Errorf(
			"%s is format version %d; this build reads %d",
			path, cfg.FormatVersion, FormatVersion)
	}
	s.cfg = cfg
	return s, nil
}

// Path is where the config lives, so the interface can tell an operator which
// file to back up or mount.
func (s *Store) Path() string { return s.path }

// Connections returns every connection with secrets removed.
func (s *Store) Connections() []Connection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Connection, 0, len(s.cfg.Connections))
	for _, c := range s.cfg.Connections {
		out = append(out, c.Redacted())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Connection returns one by id, secret included. Used internally when a scan
// needs to reach the platform; never returned to a browser.
func (s *Store) Connection(id string) (Connection, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.cfg.Connections {
		if c.ID == id {
			return c, true
		}
	}
	return Connection{}, false
}

// Save inserts or updates a connection.
//
// An empty Secret on an update keeps whatever was stored. That is what makes an
// edit form workable without ever sending the secret to the browser: the field
// arrives blank, and blank means unchanged rather than cleared. Clearing is an
// explicit act, which is what ClearSecret is for.
func (s *Store) Save(c Connection) (Connection, error) {
	if strings.TrimSpace(c.Name) == "" {
		return Connection{}, fmt.Errorf("a connection needs a name")
	}
	if c.Kind == "" {
		return Connection{}, fmt.Errorf("a connection needs a kind")
	}
	known := false
	for _, k := range Kinds() {
		if k == c.Kind {
			known = true
		}
	}
	if !known {
		return Connection{}, fmt.Errorf("unknown connection kind %q", c.Kind)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	if c.ID == "" {
		c.ID = newID()
		c.CreatedAt = now
		c.UpdatedAt = now
		s.cfg.Connections = append(s.cfg.Connections, c)
		return c.Redacted(), s.writeLocked()
	}

	for i, existing := range s.cfg.Connections {
		if existing.ID != c.ID {
			continue
		}
		if c.Secret == "" {
			c.Secret = existing.Secret
		}
		c.CreatedAt = existing.CreatedAt
		c.UpdatedAt = now
		c.LastCheck = existing.LastCheck
		s.cfg.Connections[i] = c
		return c.Redacted(), s.writeLocked()
	}
	return Connection{}, fmt.Errorf("no connection with id %q", c.ID)
}

// ClearSecret removes a stored secret. Separate from Save because "leave it
// alone" and "delete it" must not be the same gesture.
func (s *Store) ClearSecret(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.cfg.Connections {
		if c.ID == id {
			s.cfg.Connections[i].Secret = ""
			s.cfg.Connections[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			return s.writeLocked()
		}
	}
	return fmt.Errorf("no connection with id %q", id)
}

// Delete removes a connection.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.cfg.Connections {
		if c.ID == id {
			s.cfg.Connections = append(s.cfg.Connections[:i], s.cfg.Connections[i+1:]...)
			return s.writeLocked()
		}
	}
	return fmt.Errorf("no connection with id %q", id)
}

// RecordCheck stores the outcome of a connection test.
func (s *Store) RecordCheck(id string, ok bool, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.cfg.Connections {
		if c.ID == id {
			s.cfg.Connections[i].LastCheck = &Check{
				At: time.Now().UTC().Format(time.RFC3339), OK: ok, Message: message,
			}
			return s.writeLocked()
		}
	}
	return fmt.Errorf("no connection with id %q", id)
}

// Auth returns the stored authentication settings, secrets included. Callers
// that hand this to a browser must Redact it first.
func (s *Store) Auth() AuthSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Auth
}

// SetAuth replaces the authentication settings.
//
// An empty OIDCClientSecret keeps the stored one, for the same reason Save
// does: the edit form never receives it and blank must mean unchanged.
func (s *Store) SetAuth(a AuthSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.OIDCClientSecret == "" {
		a.OIDCClientSecret = s.cfg.Auth.OIDCClientSecret
	}
	if a.TokenHash == "" {
		a.TokenHash = s.cfg.Auth.TokenHash
	}
	s.cfg.Auth = a
	return s.writeLocked()
}

// Snapshot returns the whole configuration for backup.
//
// Secrets are excluded unless withSecrets is set, and the caller has to ask.
// A backup that silently contains registry credentials is a credential leak
// wearing the word "backup" — it ends up in object storage, in a ticket, in a
// chat message, because nobody treats a backup as a secret unless told.
func (s *Store) Snapshot(withSecrets bool) Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.cfg
	out.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	conns := make([]Connection, 0, len(s.cfg.Connections))
	for _, c := range s.cfg.Connections {
		if !withSecrets {
			c = c.Redacted()
		}
		conns = append(conns, c)
	}
	out.Connections = conns
	if !withSecrets {
		out.Auth = out.Auth.Redacted()
	}
	return out
}

// Restore replaces the configuration from a snapshot.
//
// A snapshot taken without secrets restores connections that cannot
// authenticate. That is reported rather than hidden, because a restored
// connection which fails at the first scan looks like an outage and is a
// missing credential.
func (s *Store) Restore(cfg Config) (missingSecrets []string, err error) {
	if cfg.FormatVersion != FormatVersion {
		return nil, fmt.Errorf(
			"snapshot is format version %d; this build reads %d",
			cfg.FormatVersion, FormatVersion)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range cfg.Connections {
		if c.Secret == "" && needsSecret(c.Kind) {
			missingSecrets = append(missingSecrets, c.Name)
		}
	}
	cfg.FormatVersion = FormatVersion
	s.cfg = cfg
	return missingSecrets, s.writeLocked()
}

// needsSecret reports whether a kind normally requires a credential. Used only
// to warn on restore, never to block one.
func needsSecret(k Kind) bool {
	switch k {
	case KindLocal, KindOCI, KindHuggingFace:
		return false // public registries and local paths often need nothing
	}
	return true
}

// writeLocked persists the config. The caller holds the lock.
func (s *Store) writeLocked() error {
	if s.path == "" {
		return nil // in-memory, used by tests
	}
	s.cfg.FormatVersion = FormatVersion
	s.cfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	data, err := json.MarshalIndent(&s.cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	// Written beside the target so the rename is atomic — a rename across
	// filesystems is a copy, and a copy can be interrupted half way.
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".tessera-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	// Flushed before the rename, or a crash leaves the new name pointing at an
	// empty file — which parses as no configuration at all.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func newID() string {
	b := make([]byte, 8)
	if _, err := cryptoRead(b); err != nil {
		return fmt.Sprintf("c%d", time.Now().UnixNano())
	}
	return "c" + hex.EncodeToString(b)
}

// cryptoRead is crypto/rand.Read, wrapped so the import stays local to the one
// place that needs it.
func cryptoRead(b []byte) (int, error) { return rand.Read(b) }

// SigningConfig returns the signing settings.
func (s *Store) SigningConfig() Signing {
	if s == nil {
		return Signing{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Signing
}

// SetSigning records where the signing key lives.
//
// The path is stored, not the key. Validation that it parses happens at use,
// not here: a key can be mounted after configuration, which is the normal shape
// of a deployment where the key comes from a secret store.
func (s *Store) SetSigning(in Signing) error {
	if s == nil {
		return fmt.Errorf("no configuration store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.Signing = in
	return s.writeLocked()
}
