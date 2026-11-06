<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/banner-dark.svg">
    <img alt="lockssh — Your AI runs the command. You hold the key." src="docs/assets/banner-light.svg" width="600">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/DavidGodefroid/lockssh/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/DavidGodefroid/lockssh/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/DavidGodefroid/lockssh/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/DavidGodefroid/lockssh?include_prereleases&color=0EA5E9"></a>
  <img alt="Go 1.26+" src="https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white">
  <img alt="Console: Linux (Docker)" src="https://img.shields.io/badge/console-docker-475569">
  <img alt="CGO_ENABLED=0" src="https://img.shields.io/badge/cgo-off-8B5CF6">
  <a href="LICENSE"><img alt="Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-14B8A6"></a>
</p>

<p align="center">
  <b>Let Claude Code, Codex, Cursor or Gemini CLI run commands on your servers<br>
  without ever handing them the SSH key.</b>
</p>

<p align="center">
  <img src="docs/assets/demo.svg" alt="Claude Code checks nginx on web1 through lockssh. systemctl status and journalctl match allow rules and run at once; the client address in the log comes back masked. The restart matches no allow rule: lox run shows the ticket, the human types y, and the agent runs it once. The SSH key stays in the lockssh console." width="900">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#what-the-agent-gets">What the agent gets</a> ·
  <a href="#safety-model">Safety model</a> ·
  <a href="docs/usage.md">Docs</a>
</p>

---

lockssh is a Lock of the [Lock Family](https://github.com/DavidGodefroid/lockfamily),
harness security for AI agents. A console held by a human, in its own
account and container, holds the SSH key or password and the only SSH
connection. The agent asks it, over MCP or the `lockssh` CLI, to run an argv.

> [!NOTE]
> **Pre-release.** v0.1.0 is the first release. lockssh is not yet a
> `lox add` type nor in lea, the Homebrew tap or the Lock Family installer:
> those land next. Built on [lockkit](https://github.com/DavidGodefroid/lockkit).

## Highlights

<table>
<tr>
<td width="50%" valign="top">

**🔑 One key holder**<br>
The key or password lives in the console's account (mode 0600); a
passphrase or password is asked at start or read from Vault. Never in
the agent's account, the socket, a result, an error or the audit log.

</td>
<td width="50%" valign="top">

**✅ Allow rules, no prompt**<br>
`systemctl status *`, `journalctl -u * -n * --no-pager`: a command an allow
rule of the approved policy matches runs at once. Globs never cross `/`;
the program is always literal.

</td>
</tr>
<tr>
<td valign="top">

**👤 The rest, approved**<br>
Anything else is refused or, with `exec = true`, becomes a signed ticket on
lockhub that you decide in `lox run`, the lea deck or on a paired phone. It
runs once, for that agent, that argv, that policy.

</td>
<td valign="top">

**🚫 No shell, masked output**<br>
Every argument is quoted: `;`, `|`, `$(...)` stay literal. No PTY, no
stdin, no forwarding. stdout and stderr are capped, then masked: emails,
public IPs, cards, IBANs, phones, secrets.

</td>
</tr>
</table>

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

## What the agent gets

`lockssh_run` with `["journalctl", "-u", "nginx", "-n", "2", "--no-pager"]`:

```json
{
  "command": "journalctl -u nginx -n 2 --no-pager",
  "rule": "journalctl -u * -n * --no-pager",
  "action": "run",
  "exit_status": 0,
  "stdout": "[alert] worker process 812 exited on signal 9\n[error] upstream timed out, client: ⟦ip:9K2QF7XM3RDA⟧\n",
  "stderr": "",
  "duration_ms": 41,
  "masked": {"ip": 1}
}
```

The same value gets the same pseudonym for the whole console run, so the
agent can still correlate; the next run draws new ones. Clear output needs
your switch in the console and a decided ticket, never an auto rule.

## Safety model

What lockssh enforces and what it does not, in
[docs/security-model.md](docs/security-model.md). In short: the key, the
connection and the policy are the human's; a rule allows a program with
arguments but cannot know what the program does with them (never allow
`find -exec`, `sh -c`, `sudo`, editors or pagers with globs); masking
covers what the detectors recognise, not every personal datum.

## The Lock Family

lockssh is one of a family of human-gated tools for AI agents, built on the
same console, separation and approval model:

| Project | Gates access to |
|---|---|
| [locksql](https://github.com/DavidGodefroid/locksql) | databases: MariaDB, MySQL, PostgreSQL, SQLite |
| [lockmq](https://github.com/DavidGodefroid/lockmq) | message queues: RabbitMQ |
| [lockfile](https://github.com/DavidGodefroid/lockfile) | files: yes/no answers about a file the agent never reads |
| [lockhttp](https://github.com/DavidGodefroid/lockhttp) | outbound HTTP(S) |
| **lockssh** | servers: commands over SSH (pre-release) |
| [lockhub](https://github.com/DavidGodefroid/lockhub) | the approval hub: `lox up`, `lox run` |
| [lockkit](https://github.com/DavidGodefroid/lockkit) | the shared Go framework: console, separation, approval, masking, audit, MCP |

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

Requires Go 1.26 or later. The animated demo above is generated:
`python3 scripts/brand/demo.py > docs/assets/demo.svg`.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
