# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub security advisories:
open <https://github.com/DavidGodefroid/lockssh/security/advisories/new>
(the "Report a vulnerability" button on the repository's Security tab).

Do not open a public issue, pull request or discussion for a suspected
vulnerability.

Please include:

- the lockssh version (`lockssh version`: the launcher's and the image's) and your OS;
- the SSH server's version, if relevant;
- the steps or input needed to reproduce the issue, and its impact.

Never include real credentials or real personal data in a report.

You will get an acknowledgement within a week. Fixes are released as soon as
possible, and the advisory is published with credit to the reporter unless
you ask otherwise.

## Scope

The threat model is in [docs/security-model.md](docs/security-model.md).
Issues of interest include, among others:

- a way for a client (CLI or MCP) to run a command no allow rule of the
  approved policy matches without a human's decision, to run a decided
  ticket twice or with another argv, or to loosen the policy without
  confirmation;
- an argv that the server's shell reads as more than one simple command
  (quoting), or any way to open a PTY, a shell, a forward or a subsystem;
- the SSH key, a passphrase or a password reaching the agent's side, argv,
  the environment, a file outside the console's home, a log, the socket or
  an error message;
- an unknown or changed host key accepted without the human;
- unmasked personal data or a secret in a result where a detector should
  apply;
- client- or server-controlled text that can spoof the console's approval
  screen.

Attacks that require running code as the same OS user as the console are out
of scope, as documented in the threat model.

## Verifying a release

`scripts/install.sh` and `lockssh update` check the cosign signatures of
`checksums.txt` and of the image `ghcr.io/davidgodefroid/lockssh:X.Y.Z`
against the release workflow run for that tag, then pin the launcher to the
verified image digest. To check the image by hand:

```sh
cosign verify \
  --certificate-identity 'https://github.com/DavidGodefroid/lockssh/.github/workflows/release.yml@refs/tags/vX.Y.Z' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/davidgodefroid/lockssh:X.Y.Z
```

## Supported versions

Only the latest release receives security fixes.
