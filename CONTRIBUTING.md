# Contributing to lockssh

Thanks for your interest. Bug reports, fixes and new test cases are welcome.
For security issues, follow [SECURITY.md](SECURITY.md) instead of opening an
issue.

## Before you start

- For anything beyond a small fix, open an issue first to agree on the
  approach. lockssh is a security tool: features that loosen a default, add a
  way around the console, run a command outside the allow rules, or
  add a dependency need a clear case.
- Code, comments, docs and commit messages are in English.
- lockssh is built on [lockkit](https://github.com/DavidGodefroid/lockkit):
  the console, approvals, configuration review, IPC, secrets and PII
  primitives live there. A change to them is a lockkit pull request.
- By contributing you agree that your work is licensed under the Apache
  License 2.0.

## Build

```sh
CGO_ENABLED=0 go build ./cmd/lockssh
```

Requires Go 1.26 or later. Every target builds with `CGO_ENABLED=0`; keep
dependencies pure Go.

To work on lockssh and lockkit together, use an uncommitted `go.work`:

```
go 1.26.0

use (
	.
	../lockkit
)
```

## Tests

```sh
go vet ./...
go test ./...
```

Unit tests need no server: an in-process SSH server runs fake programs
and records the command lines it receives.

### Integration tests

The integration test runs a real OpenSSH server in Docker, bound to
`127.0.0.1` and removed at the end:

```sh
go test -tags integration -run TestOpenSSH ./internal/sshconsole/
```

`python3 test/docker/e2e.py lockssh` follows docs/docker.md with the image
(`docker build -t lockssh .` first). Never point a test at a real or
remote server.

### Fuzzing

Fuzz targets run nightly in CI; run one locally with
`go test -run '^$' -fuzz '^FuzzLineRoundTrip$' -fuzztime 30s ./internal/command/`.
A failing input is written under the package's `testdata/fuzz/`; commit it
with the fix, so `go test` replays it from then on.

## Pull requests

- Write the failing test first, then the fix.
- Keep `gofmt`, `go vet`, `staticcheck` and `govulncheck` clean.
- Keep the security invariants: no secret in argv, environment, files, logs,
  the socket protocol or error strings; no protocol method that loosens the
  policy; no command run outside the allow rules without a decision; fail closed on anything
  ambiguous.
- One logical change per pull request, with a commit message that explains
  why.

Pull requests target `main`. The CI checks (`test`, `lint`, `integration`)
must pass. Pull requests are squash-merged: the title becomes the commit
subject and the description its body. Use a conventional prefix (`feat:`,
`fix:`, `docs:`, `chore:`, ...).

Docs are published at [lockfamily.dev/docs](https://lockfamily.dev/docs/)
from this repo's Markdown. Adding a file under `docs/`, or renaming or
removing a README H2 section, needs a matching change to
[lockfamily's `docs-site/nav.toml`](https://github.com/DavidGodefroid/lockfamily/blob/main/docs-site/nav.toml):
open a lockfamily PR, or the nightly docs build fails.

Participation is governed by the [code of conduct](CODE_OF_CONDUCT.md).

## Releases

Releases are built by GoReleaser (`.goreleaser.yaml`) when a `v*` tag is
pushed: `.github/workflows/release.yml` runs the unit tests, then builds
linux and darwin on amd64 and arm64, signs `checksums.txt` with cosign
(keyless), attaches an SBOM per archive and the Linux packages. A tag
with a semver pre-release suffix (`v0.3.0-rc.1`) is published as a GitHub
pre-release; any other tag (`v0.3.0`) is a full release, marked Latest
(GoReleaser's `prerelease: auto`). To check the configuration locally
without signing or publishing:

```sh
goreleaser check
goreleaser release --snapshot --clean --skip=sign
```

The output goes to `dist/`, which is ignored by git.

Once the archives and the images are published and signed, the workflow's last
job (`tap`) asks the [Homebrew tap](https://github.com/DavidGodefroid/homebrew-tap)
to bump the `lockssh` formula to the tag (a `repository_dispatch` of type
`bump`); the tap verifies the release with cosign before rewriting the
formula. It needs the secret `TAP_DISPATCH_TOKEN`, a fine-grained token
limited to DavidGodefroid/homebrew-tap (Contents: read and write); without
it the step is skipped.
