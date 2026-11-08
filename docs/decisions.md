# Decisions

What lockssh guards, what the agent may do over SSH, and why. These are
the answers to the design questions of issue #1. Most of them shipped in
v0.1.0 (#8); the few that change v0.1.0 are marked **change** and are
tracked in the issue named next to them. [security-model.md](security-model.md)
states the resulting promise; [usage.md](usage.md) the configuration.

## Requirements (not negotiable)

| Requirement | Where it lives |
|---|---|
| The console runs **apart from the agent**: its own account (`lockssh`, uid 10041) and container, started by `lox run` only (hub-attached, as every lock since lockkit v0.13). The agent reaches it through a socket in a read-only volume, as `lockssh-clients` (gid 10040), the image's `agent` (uid 10042) or an `--allowed-uids` uid; the kernel's peer credentials say who asks. | `Dockerfile`, `scripts/lockssh`, `cmd/lockssh/console.go` (lockkit `console.Run`) |
| **The agent never holds the credential or the connection.** The key or password lives in the console account only; nothing the agent reads (socket volume, project, result, error, audit) carries it. | `internal/sshconsole/connect.go`, lockkit `tunnel`, `secrets`, `sanitize` |
| **No shell from the agent.** An argv, never a command string; every argument quoted for a POSIX shell and the line run through `exec`, so argv[0] is always a program on the host's `PATH`, never a shell builtin, keyword or function; control and invisible characters refused. | `internal/command` |
| **Fail closed.** No approved policy, an unknown action, a host key that does not match, a server that closes without an exit status: refused. | `internal/config/auto.go` (`Rule`), `internal/sshconsole` |
| **Every byte the agent reads is masked**, unless a human decided a clear-output ticket on a console where clear output is switched on. | `internal/outmask`, `internal/sshconsole/handlers.go` |

## The agent's surface

| Question | Decision | Rationale |
|---|---|---|
| What runs on the host | **One argv per request**, in an SSH session of its own: no PTY, no stdin, no environment from the agent, no port, agent or X11 forwarding, no subsystem. Never an interactive shell. | A session per command keeps each run bounded and audited on its own; without PTY and stdin nothing can turn it into a shell. |
| Free reads | **The profile's allow list.** A command an allow rule matches runs at once when `auto.run = "auto"` (the default): the human approved the list in the policy review. A rule is a literal program and one pattern per argument (`*`, `?`, `[`; `*` and `?` never match `/`), a last `**` for the rest. **Change (#4):** a glob never matches an option (an argument starting with `-`) or a `.`/`..` path segment; see [Allow-rule globs](#allow-rule-globs). | Free reads are what makes the lock useful (status, logs, counts); the list is the human's and the program is never a glob. |
| Other commands | **Refused (`E_NOT_ALLOWED`)**, or on a profile with `exec = true` a ticket for the human (`lox run`), bound to the argv, the agent and the policy fingerprint, run once. `exec` is off by default. | A command outside the list may change the host: it is a write. |
| File transfer (scp, sftp) | **Out of scope.** lockssh opens no subsystem and has no upload or download verb. SFTP reads are lockfile's (an `sftp` source); a file the agent needs to write goes through a command on an `exec` ticket. | lockfile already masks and gates file reads; a second path would need its own rules for paths and sizes. |
| MCP tools | `lockssh_status`, `lockssh_run` (with `unmask` for a clear-output ticket), `lockssh_request_change`; **add** `lockssh_pii_list` and `lockssh_pii_add` (#4). No separate host or unmask tool: status lists the profiles, unmask is a property of a run. | As the sibling locks; the PII allow list is the one piece of locksql's surface lockssh still lacks. |

## Output

| Question | Decision | Rationale |
|---|---|---|
| Masking | stdout and stderr, in full, go through lockkit's detectors (default `card`, `email`, `iban`, `ip`, `phone`, `secret`) before they leave the console: keyed pseudonyms, `⟦secret⟧` for credentials. The command is masked on screens and in the audit. | Command output can hold anything; masking happens where the agent cannot read. |
| Bounds | Per command: `request_timeout` 30 s (ceiling 10 min; then SIGKILL and the session closed), `max_output_bytes` 64 KiB per stream (ceiling 512 KiB), kept from the start, the rest counted and flagged truncated. Per session: `idle_timeout` 20 min, `max_session` 4 h. | A command that never ends or floods its output must not hold the console. |
| Non-zero exit | **A result, not an error**: `exit_status`, or `signal`, or `timed_out`, with the masked stdout and stderr and their truncation flags. Errors are for refusals and failures of the lock itself. | The agent needs a failing command's stderr to do its job; it is masked like stdout. |
| Streaming | **None.** Output is buffered, masked whole, returned when the command ends. Commands that never end (`tail -f`) are out of scope. | A detector needs the whole value; chunking would split a secret across two pieces. lockkit needs nothing new for this. |

## Credentials and host keys

| Question | Decision | Rationale |
|---|---|---|
| Where the credential is | A private key in the console account's home volume (0600, refused otherwise), unencrypted (`credentials = "none"`) or with a passphrase; or a password. Passphrase or password asked at start (`ask`), read from the keychain or from Vault; wiped after use. | The siblings' `credentials` modes; the agent never sees a prompt. |
| Forwarding | **No agent forwarding, ever**, nor port or X11 forwarding. | A forwarded agent socket on the server is a credential the server's other users can use. |
| Host keys | Pinned per profile: with a `known_hosts` file the profile names, an unknown key is **refused**; with the console account's default file, an unknown key is trusted **only by the human on the console** (`yes`, or on production the last 8 characters of the fingerprint typed), never by a ticket or a chat facade. A changed key is **always refused**. | The human must be able to start on a new host; nothing the agent or a remote approver does can trust a key. |
| The login | `id -u` at login; a root login is refused on production and asks a typed `continue` elsewhere. The account's login shell must be a POSIX shell (sh, dash, bash, ksh, zsh): another one may read the quoted arguments differently (never as a second command). | What a command can do is what the account can do. |

## Egress

One profile is one `host:port`. The lock's egress gateway (lockhub#123,
closed) allows only the endpoints of the reviewed profiles: each profile's
SSH `host:port`, and the Vault address for a profile with
`credentials = "vault"`. Bastions (`ProxyJump`) are out of scope. The
lockssh lock type in lox, its compose and its egress are lockhub#133.

## Approvals and routing

| Request | Ticket | Risk | Auto rule (`lox run`) |
|---|---|---|---|
| First use of an SSH session (each login, each new approved policy) | connect | read-pii | `auto.connect`, default `ask`: the first one of each console run and policy fingerprint is `never_auto` (a human), the reconnections after it may be auto |
| An allow-listed command, masked | action, verb `run` | read | `auto.run`, default `auto` |
| A command outside the allow list (`exec = true`) | action, verb `exec` | write; **prod-write** on production | `auto.exec`, default `ask` |
| Output in clear | action, verb `unmask` | read-pii | **never auto**, whatever `auto.unmask` says; only `deny` changes anything |
| A looser policy | lockkit's policy review, on the console | policy-loosen | never |

- `deny` refuses before any ticket (`E_AUTO_DENIED`) in auto and manual
  mode. The rules are the approved policy's, never the files the agent can
  edit; `lockssh profile rules --json` gives them to `lox run`.
- A chat facade (Slack, Telegram) never answers prod-write, policy-loosen
  or unlock, and never sees a clear value: lockhub's routing table, which a
  workspace can narrow only.
- **Production defaults**: `exec` off (no writes), clear output off (the
  console's switch, `:unmask` or `--allow-unmask`), root login refused,
  host key typed.
- **Change (#4): on a production profile, `auto.exec = "auto"` (and the
  `full-auto` preset) is refused when the policy loads.** v0.1.0 accepts it,
  so `lox run`'s auto mode could approve a prod-write ticket. A write on
  production is always a human's decision.

## Injection

- The agent sends a JSON array of strings. At most 64 arguments, 4 KiB
  each, 16 KiB in all; valid UTF-8; no NUL, control or format character
  (tab excepted), no U+2028/U+2029; refusals name the argument's position,
  never its text (`E_BAD_ARGV`).
- The remote command line is every argument in POSIX single quotes (`'`
  written `'\''`): `;`, `|`, `$(…)`, `*` stay literal arguments of argv[0].
- **Change (#4): argv[0] is a literal program, never a shell builtin.**
  The server's login shell reads the line, and quoting does not stop it
  from running a builtin named by argv[0]: in v0.1.0 a rule `eval *` lets
  the agent send `["eval", "id;rm x"]`, the line `'eval' 'id;rm x'`, and
  `eval` runs `id` then `rm x`. The same goes for `exec`, `command`,
  `builtin`, `.`, `source`, `trap`, `fc`, `enable`, `let`, `alias`,
  `typeset`/`declare` and every other builtin that evaluates a string or
  binds a name. So, in `internal/command`:
  - `Line` writes `exec` before the quoted argv: `exec 'eval' 'id;rm x'`.
    `exec` looks argv[0] up on the `PATH` and runs that file; it never runs
    a builtin, keyword, alias or function of that name (there is no
    `/usr/bin/eval`: the command fails, `exit_status` 127). The shell is
    replaced by the program, so nothing after it in the line can run.
  - `Validate` refuses an argv[0] that starts with `-` or `+`
    (`E_BAD_ARGV`), so it is never read as an option of `exec` itself
    (`exec -c`, `exec -a`).
  - An allow rule whose program is a builtin-only name (the list above,
    tested) is **refused when the policy loads**: under `exec` it could
    only fail, and the human should see why.

  What `exec` does not cover: the account's startup files (sshd's bash
  reads `~/.bashrc`), its `PATH` and the files on it are the host's
  configuration, outside the lock's reach.
- An allow rule matches the argv, not the line, so a quoted `;` never
  makes a second command match.
- What a program does with its arguments is outside the lock's reach.
  The two rules below take the generic routes away (an option the human
  never wrote, a path that climbs out); the warning after them covers the
  programs whose plain operands are code.

## Allow-rule globs

In v0.1.0 a glob token is [path.Match](https://pkg.go.dev/path#Match) on
the whole argument: `*` and `?` stop at `/`, nothing else. That lets a
"free read" (`auto.run = "auto"`) write or climb out:

| Rule | Argument the agent sends | Effect |
|---|---|---|
| `git log *` | `--output=/home/u/.bashrc` | writes a file |
| `journalctl *` | `--vacuum-time=1s` | deletes the journal |
| `tar -tf *` | `--to-command=sh` | runs a command |
| `cat /var/log/*/*/*` | `/var/log/../../etc/shadow` | each `*` matches one `..` |
| `ls *` | `..` | lists the parent |
| `less *` | `+!id` | runs a command |

**Change (#4), both in `internal/command` (`Rule.Match`), for every glob
token (`*`, `?`, `[…]`) and for every argument a last `**` covers:**

1. **No options.** A glob never matches an argument that starts with `-`
   or `+`, unless the token itself starts with the same character
   (`--since=*` matches `--since=today`, `+%*` matches `+%F`; `-*` matches
   any option, and the policy review warns on it, below). `+` is in the
   rule for every program, not for a list of them: `less +!id`,
   `more +cmd`, `vim +'!id'` and `ex +cmd` run a command, and a rule that
   wants one (`date +*`) is easy to write. An option the agent may set is
   one the human wrote.
   Exception: after a literal `--` token in the rule, globs and `**` match
   operands, and an operand may start with `-` or `+` (the program reads
   everything after `--` as an operand). `**` without a literal `--`
   before it matches no option either: `echo **` allows `echo a b`, not
   `echo -e a`.
2. **No `.` or `..` segments.** A glob-matched argument, split on `/`, is
   refused when a segment the glob covers is `.` or `..`. A segment the
   rule spells literally is the human's (`cat ../x` allows `../x`).
   `cat /var/log/*/*/*` then allows `/var/log/nginx/old/error.log`, never
   `/var/log/../../etc`. Symlinks on the host are outside the lock's
   reach: a link under `/var/log` reads wherever it points (the security
   model says so).

A refusal is the usual `E_NOT_ALLOWED`; with `exec = true` the command
becomes an `exec` ticket like any other unlisted command. The policy
review shows the rules unchanged. The comment in `Rule.Match` said `*`
keeps `/var/log/*` from reaching `/var/log/../../etc/shadow`: true for one
`*`, not for `/var/log/*/*/*`; this PR corrects the comment, #4 the
behaviour. #4 updates
[usage.md](usage.md)'s glob table and examples with the two rules and adds
their tests (a table of the arguments above, each refused).

## Programs that run code from their arguments

The two rules close options and climbing; they cannot close a program
whose plain operand is a program or a script (`sed -n * f` with `1e id`,
`awk *` with `BEGIN{system("id")}`, `env *` with `sh`). **Change (#4): the
policy review warns on an allow rule that names one of these programs
with any glob or `**`**, and on any rule, whatever its program, that
lets a glob choose an option: a token starting with `-` whose glob
character comes before any `=` (`-*`, `--*`, `-[a-z]`), or a glob or `**`
after a literal `--`. It is a
warning, the human's call, as v0.1.0's documentation already says; the
list is a fixed table in `internal/command`, matched on the program's base
name (`/usr/bin/sed` is `sed`) with a version suffix stripped: a last run
of digits, `.`, `-` and `_` that starts with a digit (`python3.11`,
`perl5.36`, `php8.2`, `node18`, `lua5.4`, `sqlite3` match `python`,
`perl`, `php`, `node`, `lua`, `sqlite`). It is not a prefix match: `sh`
must not match `shred`, nor `at` `attr`. Tested with those names.

**The table is a safety net, not a complete list.** No list of programs
can be: a host has its own interpreters, wrappers and tools, under names
nobody can predict. A program missing from the table gets no warning, and
that says nothing about it being safe. For every program in the table,
and for any program whose arguments can be code, the rule stays **literals
only**: the human writes each argument, no glob and no `**`. The warning
reminds; it does not decide.

| Kind | Programs | Route |
|---|---|---|
| Shells and interpreters | `sh`, `bash`, `dash`, `ksh`, `mksh`, `zsh`, `fish`, `csh`, `tcsh`, `busybox`, `perl`, `python`, `pypy`, `ruby`, `irb`, `node`, `nodejs`, `deno`, `bun`, `php`, `lua`, `luajit`, `tclsh`, `wish`, `expect`, `Rscript`, `R` | `-c`/`-e` or a script operand |
| Database clients | `sqlite` (`sqlite3`: `.shell`, `.system`, `.output`), `mysql`, `mariadb` (`\!`, `system`), `psql` (`\!`, `\o \|`) | a statement or meta-command operand |
| Text tools with a command or write verb | `sed` (`e`, `w`, `s///e`), `awk`, `gawk`, `mawk`, `nawk` (`system()`, `print >`), `ed`, `ex` | the script operand |
| Runners of another argv | `env`, `sudo`, `su`, `runuser`, `sg`, `newgrp`, `doas`, `pkexec`, `systemd-run`, `xargs`, `parallel`, `nice`, `chrt`, `nohup`, `timeout`, `stdbuf`, `time`, `watch`, `setsid`, `flock`, `chroot`, `nsenter`, `unshare`, `bwrap`, `firejail`, `ionice`, `taskset`, `strace`, `ltrace`, `gdb`, `script` | the rest of the argv |
| Find and archive | `find` (`-exec`, `-execdir`, `-ok`, `-fprint`, `-delete`), `tar` (`--to-command`, `--checkpoint-action`, `-I`/`--use-compress-program`), `zip` (`-TT`), `rsync` (`-e`, `--rsync-path`) | options (closed by rule 1, unless a token starts with `-`) and actions |
| Network clients | `ssh`, `scp`, `sftp` (`-oProxyCommand=…`, `LocalCommand`; `*` matches spaces), `curl`, `wget` (`-o`/`-O` write) | options and URLs |
| Version control and builds | `git` (`-c core.pager=…`, `core.sshCommand`, `--upload-pack`, aliases, hooks), `make`, `npm`, `pip` | configuration and the project's own scripts |
| Pagers, editors, viewers | `less`, `more`, `most`, `man` (`-P`), `vi`, `vim`, `nvim`, `emacs`, `nano`, `view` | `+cmd` (closed by rule 1), `!` and editor commands, `LESSOPEN` |
| Orchestrators | `docker`, `podman`, `kubectl`, `systemctl`, `crontab`, `at`, `tcpdump` (`-z`) | `exec`, `run`, unit or job definitions |

Rule 1 closes most of the option routes in the table by itself; the
warning stays for the ones it cannot (operands that are code, a rule that
writes `-*` or a literal `--` before a glob).

## Image ids

Console `lockssh` uid 10041, group `lockssh-clients` gid 10040, image
agent uid 10042; free in lockhub's `Kinds` and lea's image. Shipped in
v0.1.0.

## lockkit

Nothing missing for lockssh: lockkit v0.14 has the SSH tunnel with
sessions (`tunnel.Tunnel.NewSession`), host-key confirmation, the PII
pipeline, hub tickets with `never_auto`, the policy review and the audit.
Streaming is not needed (above). What lockssh still needs is lox support
(lockhub#133).

## Left to do, by issue

| Issue | State after v0.1.0 | Left |
|---|---|---|
| #3 Console | Shipped (`internal/config`, `internal/sshconsole`, hub mode, audit; `hub_test.go`, `integration_test.go`) | nothing beyond #4's changes |
| #4 Agent surface | Shipped but for the items marked change | `lockssh_pii_list` / `lockssh_pii_add` and `.lockssh/pii.toml` through the reviewed policy; production `auto.exec` refusal; `exec` before the remote line, an argv[0] starting with `-`/`+` refused, builtin-only rule programs refused at load; globs that match no `-`/`+` option and no `.`/`..` segment; the policy-review warning on code-running programs (version suffixes stripped) and option globs; leak, injection and equivalence suites named as locklog#63 |
| #5 Launcher verbs | Shipped | `lockssh version --json` with the protocol number lea's `locks.lock` and lockhub's contract tests read; none of the injection or glob rules |
| #6 Release | v0.1.0 tagged and published, image signed, tap dispatched | the next pre-release with #4 and #5 |
| #7 Docs and site | README, security model, usage, Docker, demo, banners | `site/`, `pages.yml`, `scripts/check-site.py`, domain |
| #11 lox | Docs say what is true | the quick start once lockhub#133 ships |

Recommended order: #4 (the production refusal first), #5, a pre-release
(#6, #11), then lockhub#133, then #7's site and the `lox add lockssh` quick
start.
