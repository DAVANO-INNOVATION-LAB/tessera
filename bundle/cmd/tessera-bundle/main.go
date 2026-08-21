// Command tessera-bundle builds, signs and verifies offline data bundles.
//
// It exists because three things a scanner needs cannot be computed from the
// artifact in front of it: which vulnerabilities are known, which byte patterns
// are malware, and whatever rules were published after the binary shipped.
// Every tool in this space fetches those from a service. An enclave that
// forbids egress cannot, and so gets a scanner that silently checks less than
// it appears to.
//
// A bundle is how that data crosses the gap: one file, self-describing, with
// every part digested and the whole thing signed. Signing is hybrid
// post-quantum, because data that will sit inside a classified enclave for
// years should not be authenticated by a signature that a later decade breaks.
//
//	tessera-bundle create ./osv-snapshot --out osv.tsb --name osv --kind vulnerability-database \
//	    --source osv.dev --source-url https://osv.dev --retrieved 2026-08-20T00:00:00Z
//	tessera-bundle sign   osv.tsb --key signer.pem
//	tessera-bundle verify osv.tsb --public signer.pub.pem
//	tessera-bundle extract osv.tsb --dest /var/lib/tessera/db --public signer.pub.pem
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	sign "github.com/DAVANO-INNOVATION-LAB/tessera/sign"

	"github.com/DAVANO-INNOVATION-LAB/tessera/bundle/internal/pack"
)

var version = "dev"

const (
	exitOK      = 0
	exitError   = 1
	exitUnsafe  = 3
	exitUsage   = 64
	sigSuffix   = ".sig"
	defaultPerm = 0o644
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return exitUsage
	}
	switch args[0] {
	case "create":
		return runCreate(args[1:])
	case "sign":
		return runSign(args[1:])
	case "verify":
		return runVerify(args[1:])
	case "extract":
		return runExtract(args[1:])
	case "inspect":
		return runInspect(args[1:])
	case "version":
		fmt.Println(version)
		return exitOK
	case "-h", "--help", "help":
		usage()
		return exitOK
	}
	fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", args[0])
	usage()
	return exitUsage
}

func usage() {
	fmt.Fprint(os.Stderr, `tessera-bundle — signed offline data bundles

Reference data a scanner cannot compute locally — vulnerability databases,
malware signatures, rule packs — packaged so it can cross an air gap and still
be checked on the far side.

  tessera-bundle create  <dir> --out FILE --name NAME [--kind KIND] [--source ...]
  tessera-bundle sign    <bundle> --key PRIVATE.pem
  tessera-bundle verify  <bundle> [--public PUBLIC.pem]
  tessera-bundle extract <bundle> --dest DIR [--public PUBLIC.pem]
  tessera-bundle inspect <bundle>
  tessera-bundle version

kinds: vulnerability-database, malware-signatures, rule-pack, mixed

Verification always re-derives every digest from the bytes actually received.
Passing --public additionally requires a valid hybrid signature over the whole
bundle; without it the contents are checked for internal consistency but nothing
establishes who produced them.

exit codes: 0 ok, 1 error, 3 verification failed, 64 usage
`)
}

func runCreate(args []string) int {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	out := fs.String("out", "", "bundle file to write")
	name := fs.String("name", "", "bundle name")
	kind := fs.String("kind", string(pack.KindMixed), "vulnerability-database, malware-signatures, rule-pack, mixed")
	ver := fs.String("version", "", "bundle version")
	desc := fs.String("description", "", "what this bundle is")
	src := fs.String("source", "", "upstream data set name")
	srcURL := fs.String("source-url", "", "where it was obtained")
	srcVer := fs.String("source-version", "", "upstream version or snapshot id")
	retrieved := fs.String("retrieved", "", "RFC3339 time the upstream data was fetched")
	at := fs.String("created", "", "RFC3339 creation time (default: now)")
	dir, err := positional(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Usage: tessera-bundle create <dir> --out FILE --name NAME")
		return exitUsage
	}
	if *out == "" || *name == "" {
		fmt.Fprintln(os.Stderr, "create needs --out and --name")
		return exitUsage
	}

	created := time.Now().UTC().Format(time.RFC3339)
	if *at != "" {
		if _, err := time.Parse(time.RFC3339, *at); err != nil {
			fmt.Fprintf(os.Stderr, "--created: %v\n", err)
			return exitUsage
		}
		created = *at
	}

	meta := pack.Manifest{
		Kind: pack.Kind(*kind), Name: *name, Version: *ver,
		Description: *desc, CreatedAt: created,
	}
	if *src != "" {
		if *retrieved == "" {
			fmt.Fprintln(os.Stderr,
				"--source needs --retrieved: a data bundle whose age cannot be established is not reviewable")
			return exitUsage
		}
		if _, err := time.Parse(time.RFC3339, *retrieved); err != nil {
			fmt.Fprintf(os.Stderr, "--retrieved: %v\n", err)
			return exitUsage
		}
		meta.Sources = []pack.Source{{
			Name: *src, URL: *srcURL, Version: *srcVer, RetrievedAt: *retrieved,
		}}
	}

	f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, defaultPerm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return exitError
	}
	manifest, err := pack.Create(dir, meta, f)
	if err != nil {
		f.Close()
		os.Remove(*out)
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return exitError
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return exitError
	}
	fmt.Fprintf(os.Stderr, "wrote %s — %d entries, %s\n",
		*out, len(manifest.Entries), human(manifest.TotalSize()))
	fmt.Fprintln(os.Stderr, "not signed; run `tessera-bundle sign` before shipping it across a gap")
	return exitOK
}

func runSign(args []string) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	key := fs.String("key", "", "private key PEM")
	bundle, err := positional(fs, args)
	if err != nil || *key == "" {
		fmt.Fprintln(os.Stderr, "Usage: tessera-bundle sign <bundle> --key PRIVATE.pem")
		return exitUsage
	}

	keyData, err := os.ReadFile(*key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return exitError
	}
	kp, err := sign.ParsePrivate(keyData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return exitError
	}

	// The signature covers the whole bundle file, not just the manifest. The
	// manifest's digests already bind the contents; signing the file binds the
	// manifest itself, so the two layers together mean no byte can change
	// without one of them noticing.
	body, err := os.ReadFile(bundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return exitError
	}
	b, err := sign.Sign(kp, body, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return exitError
	}
	enc, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return exitError
	}
	sigPath := bundle + sigSuffix
	if err := os.WriteFile(sigPath, append(enc, '\n'), defaultPerm); err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return exitError
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%s)\n", sigPath, b.Suite)
	return exitOK
}

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pub := fs.String("public", "", "public key PEM; when given, a valid signature is required")
	bundle, err := positional(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Usage: tessera-bundle verify <bundle> [--public PUBLIC.pem]")
		return exitUsage
	}
	m, code := verifyAll(bundle, *pub)
	if code != exitOK {
		return code
	}
	fmt.Fprintf(os.Stderr, "verified %s — %s %q, %d entries, %s\n",
		bundle, m.Kind, m.Name, len(m.Entries), human(m.TotalSize()))
	if *pub == "" {
		fmt.Fprintln(os.Stderr,
			"contents are internally consistent, but no signature was checked: "+
				"nothing here establishes who produced this bundle")
	}
	return exitOK
}

func runExtract(args []string) int {
	fs := flag.NewFlagSet("extract", flag.ContinueOnError)
	dest := fs.String("dest", "", "directory to write into")
	pub := fs.String("public", "", "public key PEM; when given, a valid signature is required")
	bundle, err := positional(fs, args)
	if err != nil || *dest == "" {
		fmt.Fprintln(os.Stderr, "Usage: tessera-bundle extract <bundle> --dest DIR [--public PUBLIC.pem]")
		return exitUsage
	}
	if _, code := verifyAll(bundle, *pub); code != exitOK {
		return code
	}

	f, err := os.Open(bundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return exitError
	}
	defer f.Close()
	m, err := pack.Extract(f, *dest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return exitUnsafe
	}
	fmt.Fprintf(os.Stderr, "extracted %d entries into %s\n", len(m.Entries), *dest)
	return exitOK
}

func runInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the manifest as JSON")
	bundle, err := positional(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Usage: tessera-bundle inspect <bundle> [--json]")
		return exitUsage
	}
	f, err := os.Open(bundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return exitError
	}
	defer f.Close()
	m, err := pack.Verify(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return exitUnsafe
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(m); err != nil {
			return exitError
		}
		return exitOK
	}
	fmt.Printf("%s %q\n", m.Kind, m.Name)
	if m.Version != "" {
		fmt.Printf("  version      %s\n", m.Version)
	}
	fmt.Printf("  created      %s\n", m.CreatedAt)
	fmt.Printf("  entries      %d (%s)\n", len(m.Entries), human(m.TotalSize()))
	for _, s := range m.Sources {
		fmt.Printf("  source       %s", s.Name)
		if s.Version != "" {
			fmt.Printf(" %s", s.Version)
		}
		fmt.Printf(" retrieved %s\n", s.RetrievedAt)
		if s.URL != "" {
			fmt.Printf("               %s\n", s.URL)
		}
	}
	if m.Description != "" {
		fmt.Printf("  description  %s\n", m.Description)
	}
	return exitOK
}

// verifyAll checks the signature when a key is supplied, then the contents.
//
// Order matters. The signature is checked first because it establishes that the
// bytes are the ones the signer produced; verifying contents first would mean
// parsing an archive of unknown origin before anything vouched for it.
func verifyAll(bundle, pubPath string) (*pack.Manifest, int) {
	body, err := os.ReadFile(bundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return nil, exitError
	}

	if pubPath != "" {
		sigData, err := os.ReadFile(bundle + sigSuffix)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"tessera-bundle: a public key was given but %s%s is missing\n", bundle, sigSuffix)
			return nil, exitUnsafe
		}
		var b sign.Bundle
		if err := json.Unmarshal(sigData, &b); err != nil {
			fmt.Fprintf(os.Stderr, "tessera-bundle: signature: %v\n", err)
			return nil, exitUnsafe
		}
		pubData, err := os.ReadFile(pubPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
			return nil, exitError
		}
		// The expected keys come from the file the operator named, never from
		// the signature itself. A verifier that trusts the key travelling
		// inside the thing it is verifying is not verifying anything.
		pq, ec, err := sign.ParsePublic(pubData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
			return nil, exitError
		}
		if err := sign.Verify(&b, body, pq, ec); err != nil {
			fmt.Fprintf(os.Stderr, "tessera-bundle: signature does not verify: %v\n", err)
			return nil, exitUnsafe
		}
	}

	f, err := os.Open(bundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return nil, exitError
	}
	defer f.Close()
	m, err := pack.Verify(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tessera-bundle: %v\n", err)
		return nil, exitUnsafe
	}
	return m, exitOK
}

// positional accepts the target either before or after the flags, because both
// orders are what people actually type.
func positional(fs *flag.FlagSet, args []string) (string, error) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		if err := fs.Parse(args[1:]); err != nil {
			return "", err
		}
		return args[0], nil
	}
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() != 1 {
		return "", fmt.Errorf("expected exactly one path")
	}
	return fs.Arg(0), nil
}

func human(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
