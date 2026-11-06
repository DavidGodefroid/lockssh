# lockssh

**Harness security for AI agents, for SSH: a Lock of the
[Lock Family](https://github.com/DavidGodefroid/lockfamily).**
Your AI runs the command. You hold the key.

[![CI](https://github.com/DavidGodefroid/lockssh/actions/workflows/ci.yml/badge.svg)](https://github.com/DavidGodefroid/lockssh/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/DavidGodefroid/lockssh?include_prereleases&color=0EA5E9)](https://github.com/DavidGodefroid/lockssh/releases)
![Go 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)
[![Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-0EA5E9)](LICENSE)

lockssh lets Claude Code, Codex, Cursor or Gemini CLI run commands on your
servers over SSH **without ever holding the key**. A console held by a human,
in its own account and container, holds the SSH key or password and the
only SSH connection. The agent asks it, over MCP or the `lockssh` CLI, to run
an argv:

- a command an **allow rule** of the profile matches (`systemctl status *`,
  `journalctl -u * -n * --no-pager`) runs at once;
- any other command is refused, or, on a profile with `exec = true`, waits
  for the human's decision on the approval hub (`lox run`);
- there is **no shell**: every argument is quoted, so `;`, `|`, `$(...)`
  stay literal;
- the output comes back **masked**: emails, public IPs, card numbers and the
  other values lockkit detects become pseudonyms (`⟦email:7F3KQ2M9ZD4X⟧`),
  secrets become `⟦secret⟧`.

> [!NOTE]
> **Pre-release.** v0.1.0 is the first release. lockssh is not yet a
> `lox add` type nor in lea, the Homebrew tap or the Lock Family installer:
> those land next. Built on [lockkit](https://github.com/DavidGodefroid/lockkit).

## Why lockssh?

| | Agent runs `ssh` itself | lockssh |
|---|:---:|:---:|
| The agent can check a service, read recent logs, see the disk | ✅ | ✅ |
| The agent never holds the key or the password | ❌ | ✅ |
| Only the commands you allowed run without asking you | ❌ | ✅ |
| No shell injection through the agent's arguments | ❌ | ✅ |
| Personal values and secrets masked before the model | ❌ | ✅ |
| Every command audited, without its output | ❌ | ✅ |

## Quick start

```sh
lockssh profile add          # host, login, key file, allow rules; never a secret
lockssh init claude          # wire Claude Code in this project
lockssh doctor               # check the setup
lox up                       # start the console with its hub (Lock Family)
```

Then ask your agent: *"Is nginx running on web1? Show the last errors."* It
calls `lockssh_status`, then `lockssh_run` with
`["systemctl", "status", "nginx"]` and
`["journalctl", "-u", "nginx", "-n", "50", "--no-pager"]`.

A profile, in `.lockssh/config.toml`:

```toml
[profiles.web]
host  = "web1.example.com"
user  = "lockssh-ro"
key   = "~/.ssh/id_ed25519"          # in the console account, never the agent's
allow = ["uptime", "df -h", "systemctl status *", "journalctl -u * -n * --no-pager"]
```

## How it works

1. `lox up` starts the console in its own container, as the `lockssh`
   account. It shows the profile's policy for approval, logs in over SSH
   (trusting the host key only on your answer), and checks the account.
2. The agent's `lockssh mcp` (or CLI) runs as another account and reaches
   the console only through its socket.
3. Each request is an argv. The console matches it against the approved
   allow rules: a match runs at once; anything else is refused or becomes a
   signed ticket on lockhub, which you decide with `lox approve`, the lea
   deck or a paired phone.
4. The console runs the command in an SSH session of its own (no PTY, no
   stdin), bounded in time and output, masks stdout and stderr, and audits
   the request.

## Safety model

What lockssh enforces and what it does not, in
[docs/security-model.md](docs/security-model.md). In short: the key, the
connection and the policy are the human's; a rule allows a program with
arguments but cannot know what the program does with them (never allow
`find -exec`, `sh -c`, `sudo`, editors or pagers with globs); masking
covers what the detectors recognise, not every personal datum.

## Docs

- [docs/usage.md](docs/usage.md): profiles, allow rules, output, auto
  rules, commands, refusal codes
- [docs/docker.md](docs/docker.md): the image, the launcher, the setup
- [docs/security-model.md](docs/security-model.md)

## Install

lockssh runs in Docker. `scripts/install.sh` (from a release: see
[docs/docker.md](docs/docker.md#install)) installs the `lockssh` launcher
(the Homebrew tap and the Lock Family installer follow),
which runs every command in `ghcr.io/davidgodefroid/lockssh:X.Y.Z`; the
release's `-vault` image adds the pinned Vault CLI for
`credentials = "vault"` (`LOCKSSH_VAULT=1`). `lockssh version` prints the
launcher's and the image's versions; `lockssh update` updates both. See
[docs/docker.md](docs/docker.md), including your own build and migrating
from a host install.

## Build

```sh
CGO_ENABLED=0 go build ./cmd/lockssh
go test ./...
go test -tags integration -run TestOpenSSH ./internal/sshconsole/   # OpenSSH in Docker
```

Requires Go 1.26 or later.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
