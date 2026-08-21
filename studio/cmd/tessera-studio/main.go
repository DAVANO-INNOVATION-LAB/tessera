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
	"syscall"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/studio/internal/web"
)

// version is stamped by the linker: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	addr := flag.String("addr", "127.0.0.1:7777", "address to listen on (loopback by default)")
	showVersion := flag.Bool("version", false, "print the version and exit")
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

	srv := &web.Server{Root: root, Version: version}
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
