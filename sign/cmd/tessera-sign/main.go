// Command tessera-sign signs a bill of materials with a hybrid post-quantum
// signature, and verifies one.
//
//	tessera-sign keygen [--out DIR] [--conservative]
//	tessera-sign sign   --key signing.key <document>
//	tessera-sign verify --pub signing.pub <document> <signature>
//
// A signature proves the document has not changed and that it came from the
// holder of the key. It does not prove the document is true — for that the
// document has to be checked against the artifact, which is `tessera verify`.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera/sign/internal/bundle"
)

// version is stamped by the linker: -ldflags "-X main.version=v0.1.0".
var version = "dev"

const (
	exitOK    = 0
	exitError = 1
	// A signature that does not verify is a failed gate, distinct from the tool
	// failing to run. A pipeline must be able to tell those apart.
	exitUnverified = 3
	exitUsage      = 64
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitUsage)
	}
	switch os.Args[1] {
	case "keygen":
		os.Exit(runKeygen(os.Args[2:]))
	case "sign":
		os.Exit(runSign(os.Args[2:]))
	case "attest":
		os.Exit(runAttest(os.Args[2:]))
	case "verify-attestation":
		os.Exit(runVerifyAttestation(os.Args[2:]))
	case "verify":
		os.Exit(runVerify(os.Args[2:]))
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(exitUsage)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `tessera-sign - hybrid post-quantum signatures for bills of materials

Usage:
  tessera-sign keygen [--out DIR] [--conservative]
  tessera-sign sign   --key signing.key <document>
  tessera-sign verify --pub signing.pub <document> <signature>

  tessera-sign attest <model> --key signing.key [--out DIR]
  tessera-sign verify-attestation <doc.att.json> --public signing.pub --artifact PATH

  tessera-sign version

Every document is signed twice and both signatures must verify: ML-DSA-87
(FIPS 204) with ECDSA P-384, over SHA-384. If either algorithm is later broken
the other still holds, and the pair satisfies CNSA 2.0, ANSSI and BSI at once
rather than any one of them alone.

attest goes further than sign: it produces the AI bill of materials, signs it,
and records the artifact digest the document was derived from. Verification then
checks both halves — the signature against the key you name, and every claim
against the bytes on disk. A signed document that has drifted from its artifact
is a cryptographically impeccable lie, and only the second check catches it.

  --conservative  use SLH-DSA-SHA2-256s (FIPS 205) instead of ML-DSA-87. It is
                  hash-based, so it rests on weaker assumptions than a lattice;
                  signatures are far larger.

Exit codes: 0 verified, 3 not verified, 1 error, 64 bad command line.
`)
}

func runKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", ".", "directory to write signing.key and signing.pub into")
	conservative := fs.Bool("conservative", false, "use SLH-DSA-SHA2-256s instead of ML-DSA-87")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	suite := bundle.SuiteHybridMLDSA87
	if *conservative {
		suite = bundle.SuiteHybridSLHDSA
	}
	kp, err := bundle.Generate(suite)
	if err != nil {
		return fail(err)
	}

	priv, err := bundle.MarshalPrivate(kp)
	if err != nil {
		return fail(err)
	}
	pub, err := bundle.MarshalPublic(kp)
	if err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return fail(err)
	}
	keyPath := filepath.Join(*out, "signing.key")
	// 0600: a private key readable by anyone else on the host is not private.
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		return fail(err)
	}
	pubPath := filepath.Join(*out, "signing.pub")
	if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
		return fail(err)
	}

	fmt.Printf("suite  %s\n", suite)
	fmt.Printf("secret %s (keep this; anyone holding it can sign as you)\n", keyPath)
	fmt.Printf("public %s (distribute this; verifiers need it)\n", pubPath)
	return exitOK
}

func runSign(args []string) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := fs.String("key", "", "private key file from keygen")
	outPath := fs.String("out", "", "signature file (default: <document>.sig)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *keyPath == "" || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Usage: tessera-sign sign --key signing.key <document>")
		return exitUsage
	}
	docPath := fs.Arg(0)

	keyData, err := os.ReadFile(*keyPath)
	if err != nil {
		return fail(err)
	}
	kp, err := bundle.ParsePrivate(keyData)
	if err != nil {
		return fail(err)
	}
	doc, err := os.ReadFile(docPath)
	if err != nil {
		return fail(err)
	}

	b, err := bundle.Sign(kp, doc, time.Now())
	if err != nil {
		return fail(err)
	}
	data, err := marshalBundle(b)
	if err != nil {
		return fail(err)
	}

	target := *outPath
	if target == "" {
		target = docPath + ".sig"
	}
	if err := os.WriteFile(target, data, 0o644); err != nil {
		return fail(err)
	}
	fmt.Printf("signed %s\n  suite     %s\n  signature %s\n", docPath, b.Suite, target)
	return exitOK
}

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubPath := fs.String("pub", "", "public key file from keygen")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *pubPath == "" || fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "Usage: tessera-sign verify --pub signing.pub <document> <signature>")
		return exitUsage
	}
	docPath, sigPath := fs.Arg(0), fs.Arg(1)

	pubData, err := os.ReadFile(*pubPath)
	if err != nil {
		return fail(err)
	}
	pqPub, ecPub, err := bundle.ParsePublic(pubData)
	if err != nil {
		return fail(err)
	}
	doc, err := os.ReadFile(docPath)
	if err != nil {
		return fail(err)
	}
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		return fail(err)
	}
	b, err := unmarshalBundle(sigData)
	if err != nil {
		return fail(err)
	}

	if err := bundle.Verify(b, doc, pqPub, ecPub); err != nil {
		fmt.Fprintf(os.Stderr, "NOT VERIFIED: %v\n", err)
		return exitUnverified
	}
	fmt.Printf("verified %s\n  suite     %s\n  signed at %s\n"+
		"  both the post-quantum and the classical signature hold\n",
		docPath, b.Suite, b.SignedAt)
	return exitOK
}

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "tessera-sign: %v\n", err)
	return exitError
}
