// Command tessera-studio serves a local interface over the tessera analyser:
// browse a directory of models, analyse one, read its findings, and download
// its bill of materials in either standard.
//
//	tessera-studio /path/to/models
//	tessera-studio --addr 127.0.0.1:8080 /path/to/models
//
// The server binds to loopback by default and confines every analysis to the
// directory named on the command line. Both are deliberate: this is a viewer
// for untrusted artifacts, so it should not be reachable from the network and
// should not become a way to read arbitrary files off the host.
//
// It is a separate program from the tessera library and CLI, and depends on
// tessera the same way any other consumer would — by importing it. Nothing in
// the analyser knows this exists.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/studio/internal/store"
	"github.com/DAVANO-INNOVATION-LAB/tessera/studio/internal/web"
)

// version is stamped by the linker: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	addr := flag.String("addr", "127.0.0.1:7777", "address to listen on (loopback by default)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	configPath := flag.String("config", os.Getenv("TESSERA_CONFIG"),
		"where to persist connections and settings (default: none, nothing is stored)")

	authToken := flag.String("auth-token", os.Getenv("TESSERA_AUTH_TOKEN"),
		"bearer token required on every request (or TESSERA_AUTH_TOKEN)")
	insecure := flag.Bool("insecure-no-auth", false,
		"allow a non-loopback bind with no authentication (say this deliberately)")
	oidcIssuer := flag.String("oidc-issuer", os.Getenv("TESSERA_OIDC_ISSUER"), "OIDC provider base URL")
	oidcClientID := flag.String("oidc-client-id", os.Getenv("TESSERA_OIDC_CLIENT_ID"), "OIDC client id")
	oidcSecret := flag.String("oidc-client-secret", os.Getenv("TESSERA_OIDC_CLIENT_SECRET"), "OIDC client secret")
	oidcRedirect := flag.String("oidc-redirect-url", os.Getenv("TESSERA_OIDC_REDIRECT_URL"),
		"OIDC redirect URL, exactly as registered with the provider")
	oidcEmails := flag.String("oidc-allowed-emails", os.Getenv("TESSERA_OIDC_ALLOWED_EMAILS"),
		"comma list of permitted email addresses")
	oidcDomains := flag.String("oidc-allowed-domains", os.Getenv("TESSERA_OIDC_ALLOWED_DOMAINS"),
		"comma list of permitted email domains")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, `tessera-studio - local interface for model bills of materials

Usage:
  tessera-studio [--addr HOST:PORT] <models-directory>
  tessera-studio --version

Browse a directory of models, analyse one, read the findings its metadata
discloses, and download a bill of materials as CycloneDX 1.6 or 1.7, SPDX 3.0.1
or SARIF 2.1.0.

Every analysis is confined to the directory given here, and the server listens
on loopback unless told otherwise.
`)
	}
	flag.Parse()

	// Answered before anything else, and without needing a models directory.
	// A container that cannot say what version it is running is not auditable,
	// and requiring an argument to find out makes the answer awkward to reach
	// from a health check or a build script.
	if *showVersion {
		fmt.Println(version)
		return
	}

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	root, err := filepath.Abs(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-studio: %v\n", err)
		os.Exit(1)
	}
	info, err := os.Stat(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-studio: %v\n", err)
		os.Exit(1)
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "tessera-studio: %s is not a directory\n", root)
		os.Exit(1)
	}

	auth := web.Auth{Token: *authToken, InsecureNoAuth: *insecure}
	var generated string
	if *oidcIssuer != "" {
		auth.OIDC = &web.OIDCConfig{
			Issuer: *oidcIssuer, ClientID: *oidcClientID,
			ClientSecret: *oidcSecret, RedirectURL: *oidcRedirect,
			AllowedEmails:  splitList(*oidcEmails),
			AllowedDomains: splitList(*oidcDomains),
		}
		// Discovery happens now so a bad issuer is a boot failure rather than a
		// surprise for whoever tries to sign in first.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := auth.OIDC.Discover(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "tessera-studio: %v\n", err)
			os.Exit(1)
		}
	}

	// A non-loopback bind with nothing configured gets a generated token rather
	// than a refusal. Refusing would be safe and useless: the container binds
	// every interface by definition, so the documented `docker run` would fail
	// for everyone and the first thing anybody reached for would be the flag
	// that turns the protection off.
	//
	// Generating one is the same trade Jupyter makes. It is secure by default,
	// needs no configuration, and the operator sees the token because it is the
	// only way in. Whoever wants no authentication still has to say so.
	if !auth.Enabled() && !auth.InsecureNoAuth && web.IsExposedBind(*addr) {
		tok, err := web.GenerateToken()
		if err != nil {
			fmt.Fprintf(os.Stderr, "tessera-studio: could not generate a token: %v\n", err)
			os.Exit(1)
		}
		auth.Token = tok
		generated = tok
	}

	// Belt and braces: if anything above failed to produce a credential for an
	// exposed bind, refuse rather than serve.
	if err := auth.CheckBind(*addr); err != nil {
		fmt.Fprintf(os.Stderr, "tessera-studio: %v\n", err)
		os.Exit(1)
	}

	// No --config means nothing is persisted, which is the right default for a
	// one-off scan: a tool that silently starts writing credentials to disk
	// because it was run once is not a tool anyone should trust.
	var cfgStore *store.Store
	if *configPath != "" {
		cfgStore, err = store.Open(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tessera-studio: %v\n", err)
			os.Exit(1)
		}
		// Stored settings fill in only what the flags left unset, so a flag is
		// always the stronger statement and a restart cannot be surprised by
		// something typed into a browser weeks ago.
		if sa := cfgStore.Auth(); auth.OIDC == nil && sa.OIDCIssuer != "" {
			auth.OIDC = &web.OIDCConfig{
				Issuer: sa.OIDCIssuer, ClientID: sa.OIDCClientID,
				ClientSecret: sa.OIDCClientSecret, RedirectURL: sa.OIDCRedirectURL,
				AllowedEmails: sa.AllowedEmails, AllowedDomains: sa.AllowedDomains,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if derr := auth.OIDC.Discover(ctx); derr != nil {
				fmt.Fprintf(os.Stderr, "tessera-studio: stored OIDC settings: %v\n", derr)
				os.Exit(1)
			}
		}
	}

	srv := &web.Server{Root: root, Version: version, Auth: auth, Store: cfgStore}
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-studio: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("tessera-studio %s\n  serving %s\n  http://%s\n", version, root, ln.Addr())

	// How to get in, printed once, where the operator is already looking.
	switch {
	case generated != "":
		fmt.Printf("\n  This port is reachable beyond this machine, so a token was generated.\n"+
			"  Open:  http://%s/?token=%s\n"+
			"  Or:    Authorization: Bearer %s\n\n"+
			"  Set --auth-token or TESSERA_AUTH_TOKEN to choose your own.\n",
			ln.Addr(), generated, generated)
	case auth.OIDC != nil:
		fmt.Printf("  sign-in: OIDC via %s\n", auth.OIDC.Issuer)
	case auth.Token != "":
		fmt.Printf("  auth:    bearer token (fingerprint %s)\n", web.Fingerprint(auth.Token))
	case auth.InsecureNoAuth && web.IsExposedBind(*addr):
		fmt.Printf("\n  WARNING: serving without authentication on a port reachable beyond\n" +
			"  this machine. Anything that can reach it can read every model here.\n\n")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Shutdown runs in its own goroutine, so main has to wait for it to finish
	// rather than exiting the moment Serve returns. Serve returns as soon as
	// Shutdown is called, while in-flight analyses are still draining; leaving
	// then would kill them, which is not what "graceful" means.
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutCtx); err != nil {
			fmt.Fprintf(os.Stderr, "tessera-studio: shutdown: %v\n", err)
		}
	}()

	if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "tessera-studio: %v\n", err)
		os.Exit(1)
	}
	<-shutdownDone
}

// splitList parses a comma-separated flag, dropping blanks so a trailing comma
// does not silently create an entry that matches nothing.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
