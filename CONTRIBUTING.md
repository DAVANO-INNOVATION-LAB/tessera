# Contributing

Thanks for taking the time. Issues and pull requests are both welcome.

## Before you open a PR

```bash
make test    # gofmt, go vet, and the suite under -race
```

Everything must be formatted with `gofmt`, pass `go vet`, and pass the tests
with the race detector on. CI runs the same commands, plus `staticcheck` and
`govulncheck`.

## What a change needs

**A test that fails without it.** For a bug fix, write the test first and watch
it fail against the current code — that is the only way to know the test covers
the bug rather than the fix.

**Security fixes need a regression test in `internal/parse/security_test.go`**
(or the Studio equivalent), with a comment saying what the original failure was.
Those tests exist so a future refactor cannot quietly reopen a closed hole.

## Things worth knowing

- **The library has no third-party dependencies, and must not gain any.** Other
  programs import it; an empty dependency tree is a promise made to them, and
  `TestNoThirdPartyDependencies` enforces it. Test-only tooling that lives
  outside the module (see `scripts/`) is the way around this.
- **Nothing may write to stdout or stderr from library code.** The caller owns
  all output; `TestAnalysisWritesNothingToStdoutOrStderr` enforces it.
- **Never trust a length or count read from a file.** Every allocation derived
  from file bytes needs a bound, and a breach should become a finding rather
  than an allocation.
- **Absence of evidence is not evidence of absence.** If the parser could not
  examine something, say so with a finding. Returning a clean result for an
  artifact you failed to read is the worst bug this project can have.

## Commit messages

Explain why the change is needed, not just what changed. If it fixes a security
issue, say what an attacker could do before the fix.
