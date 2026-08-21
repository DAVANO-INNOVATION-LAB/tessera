# Continuous integration

The action downloads a released binary, verifies its Sigstore signature against
the checksum manifest before running it, and uploads the SARIF to code scanning
so findings land as annotations on the pull request.

```yaml
permissions:
  contents: read
  security-events: write   # required to upload SARIF

steps:
  - uses: actions/checkout@v7
  - uses: DAVANO-INNOVATION-LAB/tessera@v1
    with:
      path: ./models/llama3
      fail-on: critical            # or high, medium, low, never
      cyclonedx-version: "1.7"
```

Every published release is covered by a `checksums.txt` signed with Sigstore.
Signing is keyless, so there is no key to distribute — the certificate names the
repository and the workflow that built the binary:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/DAVANO-INNOVATION-LAB/tessera/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```
