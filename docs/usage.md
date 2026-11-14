# Using lockssh

lockssh lets an AI agent run commands on a server over SSH without ever
holding the key. A console, held by a human in its own account and
container, holds the SSH key or password and the only SSH connection. The
agent asks it, over MCP or the `lockssh` CLI, to run an argv; the console
runs it when a rule of the profile allows it, asks the human otherwise (on
lockhub, through `lox run`), and returns the exit status and the output,
masked.

- [Profiles](#profiles)
- [Allow rules](#allow-rules)
- [What runs, what waits, what is refused](#what-runs-what-waits-what-is-refused)
- [Output](#output)
- [Auto rules](#auto-rules)
- [The console](#the-console)
- [Client commands and MCP tools](#client-commands-and-mcp-tools)
- [Launcher verbs](#launcher-verbs)
- [Refusal codes](#refusal-codes)

## Profiles

A profile is one SSH host, in `.lockssh/config.toml` (the project) or
`~/.config/lockssh/config.toml` (your account). It never holds a secret.

```toml
[profiles.web]
host        = "web1.example.com"   # a name or an address, no user, port or scheme ("[::1]" for IPv6)
port        = 22                   # default 22
user        = "deploy"             # the SSH login (required)
auth        = "key"                # key (default) | password
key         = "~/.ssh/id_ed25519"  # with auth = "key"; in the console account ("~/" is its home)
credentials = "none"               # key: none (unencrypted, the default) | ask | keychain | vault
                                   # password: ask (the default) | keychain | vault
vault_path  = ""                   # with credentials = "vault"
known_hosts = ""                   # "" = the console account's ~/.ssh/known_hosts
production  = false
unconfined  = false                # true: serve an agent that does not run confined (never on production)
exec        = false                # true: a command outside allow may be asked
allow       = ["uptime", "df -h", "systemctl status *", "journalctl -u * -n * --no-pager"]
detectors   = ["card", "email", "iban", "ip", "phone", "secret"]   # the default

[profiles.web.limits]
request_timeout  = "30s"           # a command running longer is killed (ceiling 10m)
max_output_bytes = 65536           # per stream, before masking (ceiling 512 KiB)
idle_timeout     = "20m"
max_session      = "4h"

[profiles.web.auto]                # lox run's auto rules (below)
connect = "ask"
run     = "auto"
exec    = "ask"
unmask  = "ask"
```

The secret is the key's passphrase or the SSH password. `ask` is asked by
the console at its start (masked), `keychain` read from the OS keychain
(not in a container), `vault` read from Vault at `vault_path` with the
Vault token the console asks at its start.

**Host key.** With no `known_hosts`, the console checks the host key
against its own account's `~/.ssh/known_hosts`; a key it has never seen is
shown on the console and trusted only on the human's answer (`yes`, or on
production the last 8 characters of its fingerprint), then recorded. With a
`known_hosts` file, a key the file does not hold is refused. A changed key
is always refused.

**Confined agents.** The console serves only an agent that runs confined:
every lockssh client reports it in its handshake (in a container, no host
container runtime socket it can reach, no Lock Family state, the project's
`.lockfamily/` read-only), and an agent that does not, or that holds the
group of the host's Docker socket, is refused with the reasons
(`CodeUnconfined`, audited `refused-unconfined`). Agents run by lea are
confined; an agent run on the host is not. `unconfined = true` on a
non-production profile serves it anyway: turning it on is a loosening the
human approves, the console shows a red banner, and every audit record and
hub ticket of the connection is marked unconfined. A production profile
with `unconfined = true` does not start, and a managed
`require_confined_agent = true` refuses an unconfined agent whatever the
profile says. The client and the console must be of the same lockssh
version.

**Policy.** Every security-relevant field is part of the profile's policy.
The console shows it at its first start and asks the human to approve it;
afterwards a change that tightens applies at once, and a change that
loosens (a new allow rule, exec turned on, another host, user, key or
known_hosts, unconfined turned on, a removed detector, a larger limit, a
looser auto rule) waits
for the human in the console (`:review`). An agent that edits the file
loosens nothing.

## Allow rules

An allow rule is an argv pattern, its tokens separated by spaces:

| Token | Matches |
|---|---|
| `status` | exactly that argument |
| `*`, `nginx*`, `*.service`, `[ab]?` | one argument, as a glob ([path.Match](https://pkg.go.dev/path#Match)): `*` and `?` never match `/` |
| `**` (last token only) | zero or more remaining arguments |

The first token, the program, is always literal, and never a shell builtin
or keyword (`eval`, `exec`, `command`, `.`, `source`, `trap`, `let`,
`alias`, `declare`, `cd`, `if`…): such a rule is refused when the policy
loads. Two more rules hold for every glob and for `**`:

1. **No options.** A glob never matches an argument that starts with `-` or
   `+`, unless the glob itself starts with the same character
   (`--since=*` matches `--since=today`, `+%*` matches `+%F`). `**` never
   matches one. After a literal `--` in the rule, globs and `**` match
   operands, which may then start with `-` or `+`.
2. **No climbing.** A `.` or `..` path segment a glob covers is refused
   (`*` matches `.hidden`, not `..`); a segment the rule spells literally is
   yours (`cat ../x` allows `../x`).

Examples:

| Rule | Allows | Not |
|---|---|---|
| `uptime` | `uptime` | `uptime -p` |
| `systemctl status *` | `systemctl status nginx` | `systemctl restart nginx`, `systemctl status a b` |
| `cat /var/log/*` | `cat /var/log/syslog` | `cat /var/log/../../etc/shadow`, `cat /var/log/nginx/error.log` |
| `cat /var/log/*/*/*` | `cat /var/log/nginx/old/error.log` | `cat /var/log/../../etc/shadow` |
| `ls *` | `ls src` | `ls ..`, `ls -la` |
| `git log *` | `git log main` | `git log --output=/home/u/.bashrc` |
| `journalctl *` | `journalctl nginx.service` | `journalctl --vacuum-time=1s` |
| `journalctl --since=*` | `journalctl --since=today` | `journalctl --until=now` |
| `less *` | `less notes.txt` | `less +!id` |
| `journalctl -u * -n * --no-pager` | `journalctl -u nginx -n 50 --no-pager` | `journalctl -u nginx` |
| `echo **` | `echo`, `echo a b c` | `echo -e a`, `echo ../x` |
| `grep -- * app.log` | `grep -- -v app.log` | `grep -v x app.log` |

A rule allows a program with the arguments it names; it cannot know what
the program does with them. Some programs run other programs or write
files from their own arguments (`find -exec`, `awk`, `sed`, `vim`, `less`,
`tar --to-command`, `sudo`, `env`, `sh -c`, `python3`, `dd`, `tee`):
never allow them with a glob or `**`. The policy review warns on a rule
that names one of them (its base name, version suffix stripped:
`python3.11` is `python`) with a glob or `**`, on a glob that chooses an
option (`-*`, `--*`, `-[a-z]`), and on a glob after a literal `--`. The
table of programs is in
[decisions.md](decisions.md#programs-that-run-code-from-their-arguments);
it is a safety net, not a complete list: a program missing from it is not
safe for that.

## What runs, what waits, what is refused

The agent sends an argv: the program and its arguments, one string each.
There is no shell: the console quotes every argument for the server's login
shell, so `;`, `|`, `>`, `$VAR`, `$(...)`, `*.log` and `~` are passed as
literal arguments. An argv holds 1 to 64 arguments, each at most 4 KiB, at
most 16 KiB in all, with no control or invisible character but tab.

| Request | What happens |
|---|---|
| an allow rule matches | runs at once (rule `run = "auto"`, the default); with `run = "ask"`, a ticket |
| no rule matches, `exec = false` | refused, `E_NOT_ALLOWED`; nothing runs |
| no rule matches, `exec = true` | a ticket (risk `write`, `prod-write` on production), decided by the human |
| `unmask` (output in clear) | only once the human allowed it in the console (`:unmask` or `--allow-unmask`); then a ticket (risk `read-pii`), never decided by an auto rule |

On a production profile, `auto.exec = "auto"` (and `auto = "full-auto"`)
is refused when the policy loads: a command outside the allow list is a
write, and a write on production is always a human's decision.

The remote line is `exec` followed by the quoted argv (`exec 'systemctl'
'status' 'nginx'`): `exec` runs argv[0] as a file on the host's `PATH`,
never as a shell builtin, keyword, alias or function, and nothing after it
in the line can run. An argv[0] that starts with `-` or `+` is refused
(`E_BAD_ARGV`).

A ticket goes to lockhub: the agent gets `pending` with the ticket id, ends
its turn, and runs the same argv again with `ticket` once told it is
decided. The decided ticket runs the stored request once, for the agent
that asked it, under the policy it was asked under (`E_STALE` otherwise).

The first request of each SSH session, and the first after the approved
policy changed, also waits for a connect ticket (`connect = "ask"`: the
first of each console run is a human's).

## Output

The result holds `exit_status` (or `signal`, or `timed_out`), `stdout`,
`stderr`, `stdout_truncated` / `stderr_truncated` (cut at
`max_output_bytes` before masking), `duration_ms`, and `masked`, the count
of masked values by kind.

What the profile's detectors find becomes a keyed pseudonym:
`⟦email:7F3KQ2M9ZD4X⟧`, the same for the same value during one console
run, another in the next run. Secrets (`password=...`, tokens, PEM keys,
URL userinfo...) become `⟦secret⟧`. Invalid UTF-8 becomes U+FFFD. What
the detectors do not recognise (names, addresses in free text, file
contents of unknown shapes) is **not** masked: choose the allow list
accordingly. See [docs/security-model.md](security-model.md).

### PII rules

`.lockssh/pii.toml` (or `pii.toml` next to the user config) adds rules of
the project's own, through the reviewed policy:

```toml
# Masked in every output, whatever the detectors say (RE2; must not match "").
[[mask]]
pattern = 'cust-[0-9]{6}'

# A detected value kept in clear: a detector's kind (never secret) and the value.
[[allow]]
kind = "email"
value = "support@example.com"
```

What a mask rule matches becomes `⟦mask:…⟧`. Mask rules run on the output
once the detectors have masked it, and never change a detector's
placeholder: a rule only sees what is already shown, so it cannot tell
anything about a masked value. The agent may add a mask rule
(`lockssh_pii_add`, `lockssh pii add`): it masks more, so it applies at
once and is appended to the file. A new allow rule, or a removed mask
rule, shows more: it waits for the human in the console (`:review`).

## Auto rules

`lox run`'s auto mode decides tickets by rule. Each action takes `auto`,
`ask` or `deny`; `auto = "full-auto"` sets them all to `auto`.

| Action | Default | Meaning |
|---|---|---|
| `connect` | ask | use the SSH session (the first connection of each console run is always a human's under `ask`) |
| `run` | auto | an allow-listed command; `auto` runs it without a ticket |
| `exec` | ask | a command outside the allow list (exec on) |
| `unmask` | ask | clear output; never approved by an auto rule, only `deny` changes it |

`deny` is enforced by the console whatever the decider does; `ask` signs
the ticket `never_auto`. `lockssh profile rules --json` prints the rules
`lox run` applies (the approved policy's).

## The console

`lox run` starts the console (`lox add lockssh` declares it), from lockhub
v0.11.0 or later, the first with the lockssh lock type
([lockhub#133](https://github.com/DavidGodefroid/lockhub/issues/133)); an older
`lox` starts none. `lox run` launches `lockssh console --hub URL --hub-key-file FILE
--instance NAME [--profile P] [--project DIR] [--allow-unmask]
[--show-results] [--allowed-uids UID,...]`. It refuses to start without its
hub. At its start it shows the policy for approval, asks the secret, logs
in, trusts or checks the host key, runs `id -u` (a root login is refused on
production and asks a typed `continue` elsewhere), then serves the socket
until logout, `:quit`, the idle timeout or the maximum session. Its keys:
`:review`, `:status`, `:results` / Ctrl-O (clear output on the console
only), `:unmask`, `:quit`. Every request, decision and run is in its
append-only, hash-chained audit log, with the command masked and never its
output.

## Client commands and MCP tools

| CLI | MCP tool | |
|---|---|---|
| `lockssh status` | `lockssh_status` | the console of each profile, its allow rules, exec, the SSH account |
| `lockssh run [--intent T] [--dry-run] [--ticket T] [--unmask] [--] PROGRAM [ARG]...` | `lockssh_run` (`argv`, `intent`, `dry_run`, `ticket`, `unmask`) | run a command; flags come before the program |
| `lockssh pii list` | `lockssh_pii_list` | the PII mask and allow rules in force |
| `lockssh pii add "REGEXP"` | `lockssh_pii_add` (`pattern`) | add a mask rule: masks more, applied at once |
| `lockssh request "CHANGE"` | `lockssh_request_change` | queue a policy change for the human |
| `lockssh logout` | | end the console session |
| `lockssh mcp` | | the MCP server on stdin/stdout |

All take `--profile P` (when several are configured) and `--instance NAME`
(when lea mounts several lockssh locks). Exit codes: 0 ok, 1 refused,
denied or failed, 2 no console, 3 usage or configuration error.

## Launcher verbs

What `lox add` calls (the lockkit verbs contract):

```
lockssh profile add --non-interactive --json --profile NAME [--production] [--credentials none|ask|vault --vault-path P]
                    --host HOST [--port N] --user USER [--auth key|password] [--key FILE] [--known-hosts FILE]
                    [--allow "RULE"]... [--exec]
lockssh init claude
lockssh doctor --fix --yes --json
```

`lockssh version --json` prints `{"name":"lockssh","version":"…","protocol_major":1}`:
the console protocol's major, which lea's `locks.lock` and lockhub's
contract tests read.

`profile add` never takes, asks for or writes a secret; an existing
profile is never rewritten (`exists`). `init <agent>` wires Claude Code,
Codex, Cursor or Gemini CLI in the project. `doctor` checks the config,
the separated setup, the consoles, the project's `.lockssh` and the agent
wiring.

## Refusal codes

| Code | Meaning | What to do |
|---|---|---|
| `E_BAD_ARGV` | empty program or one starting with `-`/`+`, control character, too many or too long arguments | rewrite the argv |
| `E_NOT_ALLOWED` | no allow rule matches and exec is off | use an allowed command, or ask the user for a rule |
| `E_AUTO_DENIED` | the profile's auto rules deny this action | only the user changes them |
| `E_UNMASK_OFF` | clear output is off in this console | work with the masked output, or ask the user |
| `E_STALE` | the profile changed after the approval | ask again |
| `E_POLICY` | no policy in force, or it does not parse | ask the user |
