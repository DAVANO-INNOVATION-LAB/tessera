package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "cfg", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The rule the whole package exists to keep. A secret that has been written is
// never read back out: an interface that redisplays a stored credential turns
// every screenshot and every XSS into disclosure, and verifies nothing.
func TestSecretsNeverLeaveTheStore(t *testing.T) {
	s := open(t)
	saved, err := s.Save(Connection{Name: "prod", Kind: KindS3, Secret: "AKIA-of-doom"})
	if err != nil {
		t.Fatal(err)
	}
	if saved.Secret != "" {
		t.Error("Save returned the secret it was given")
	}
	for _, c := range s.Connections() {
		if c.Secret != "" {
			t.Errorf("Connections() disclosed a secret for %q", c.Name)
		}
	}
	// Internally it is still available, or a scan could not authenticate.
	full, ok := s.Connection(saved.ID)
	if !ok || full.Secret != "AKIA-of-doom" {
		t.Error("the secret was not retained for internal use")
	}
}

// An edit form never receives the secret, so a blank field means unchanged.
// Getting this wrong silently wipes a credential on every save.
func TestBlankSecretOnUpdateKeepsTheStoredOne(t *testing.T) {
	s := open(t)
	saved, _ := s.Save(Connection{Name: "reg", Kind: KindS3, Secret: "keep-me"})

	saved.Name = "renamed"
	saved.Secret = "" // what an edit form sends back
	if _, err := s.Save(saved); err != nil {
		t.Fatal(err)
	}
	full, _ := s.Connection(saved.ID)
	if full.Secret != "keep-me" {
		t.Errorf("secret is now %q; a rename wiped the credential", full.Secret)
	}
	if full.Name != "renamed" {
		t.Error("the rename did not apply")
	}
}

// Clearing has to be a separate gesture from leaving alone.
func TestClearSecretIsExplicit(t *testing.T) {
	s := open(t)
	saved, _ := s.Save(Connection{Name: "reg", Kind: KindS3, Secret: "gone-soon"})
	if err := s.ClearSecret(saved.ID); err != nil {
		t.Fatal(err)
	}
	full, _ := s.Connection(saved.ID)
	if full.Secret != "" {
		t.Error("ClearSecret left the secret in place")
	}
}

// A backup containing credentials is a credential leak wearing the word
// "backup" — it ends up in object storage and in tickets. The caller has to ask.
func TestSnapshotOmitsSecretsUnlessAsked(t *testing.T) {
	s := open(t)
	s.Save(Connection{Name: "reg", Kind: KindS3, Secret: "top-secret"})
	s.SetAuth(AuthSettings{OIDCIssuer: "https://idp", OIDCClientSecret: "oidc-secret"})

	plain := s.Snapshot(false)
	blob, _ := json.Marshal(plain)
	if strings.Contains(string(blob), "top-secret") || strings.Contains(string(blob), "oidc-secret") {
		t.Error("a default snapshot contained secrets")
	}

	full := s.Snapshot(true)
	blob, _ = json.Marshal(full)
	if !strings.Contains(string(blob), "top-secret") {
		t.Error("an explicit secret-bearing snapshot omitted them, so it cannot restore")
	}
}

// Restoring a redacted snapshot produces connections that cannot authenticate.
// That has to be reported, or it surfaces later as an outage.
func TestRestoreReportsMissingSecrets(t *testing.T) {
	src := open(t)
	src.Save(Connection{Name: "prod-s3", Kind: KindS3, Secret: "x"})
	src.Save(Connection{Name: "public-oci", Kind: KindOCI})

	dst := open(t)
	missing, err := dst.Restore(src.Snapshot(false))
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0] != "prod-s3" {
		t.Errorf("missing = %v, want just prod-s3: OCI and local often need no credential", missing)
	}
}

func TestRestoreRefusesAnUnknownFormat(t *testing.T) {
	s := open(t)
	if _, err := s.Restore(Config{FormatVersion: FormatVersion + 1}); err == nil {
		t.Error("a newer snapshot format was accepted rather than refused")
	}
}

// The file holds registry credentials. Mode is the boundary on a shared host.
func TestConfigFileIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "config.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(Connection{Name: "x", Kind: KindLocal}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config file mode is %04o, want 0600: it holds credentials", perm)
	}
}

// Config survives a restart, or none of this is persistence.
func TestConfigRoundTripsThroughTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	first, _ := Open(path)
	saved, err := first.Save(Connection{
		Name: "hub", Kind: KindHuggingFace, Endpoint: "https://huggingface.co", Secret: "hf_x",
	})
	if err != nil {
		t.Fatal(err)
	}

	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := second.Connection(saved.ID)
	if !ok {
		t.Fatal("the connection did not survive a reopen")
	}
	if got.Secret != "hf_x" || got.Endpoint != "https://huggingface.co" {
		t.Errorf("round trip lost data: %+v", got)
	}
}

func TestUnknownKindIsRejected(t *testing.T) {
	s := open(t)
	if _, err := s.Save(Connection{Name: "x", Kind: "not-a-platform"}); err == nil {
		t.Error("an unknown connection kind was accepted")
	}
	if _, err := s.Save(Connection{Name: "", Kind: KindLocal}); err == nil {
		t.Error("a nameless connection was accepted; it cannot be identified in the interface")
	}
}
