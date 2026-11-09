# Running lockssh in Docker

lockssh runs in Docker, with nothing on your machine but Docker and the
`lockssh` launcher. The launcher is a short shell script
([`scripts/lockssh`](../scripts/lockssh)): every command you type,
`lockssh console`, `lockssh version`, `lockssh mcp` and the others, runs in
the lockssh image, never in a binary of its own on your machine. The image
holds the separated setup that keeps the console apart from the agent:

- the console runs as `lockssh` (uid 10041), the only account that holds the
  SSH key or password, in its home volume (`/home/lockssh`);
- the agent's MCP server and CLI run as `agent` (uid 10042), a member of
  `lockssh-clients` (gid 10040);
- `/etc/lockssh/system.toml` is owned by root and the binary by root; the
  image has no `sudo`;
- the socket directory `/run/lockssh` (mode 2710, `lockssh:lockssh-clients`)
  is a named volume, shared by the console container and the agent's
  containers (read-only there): `lox run`'s socket volume of the lock
  (`lockfamily-<hash>_<instance>-run`, named in `.lockfamily/up.json`). The
  kernel checks every peer on the socket as on a host.

The ids differ from the other locks' images, so that one agent image can be
a client of all of them.

## Install

Download the install script from the release you install, read it, then
run it with that release:

```sh
V=vX.Y.Z
curl -fsSLO "https://raw.githubusercontent.com/DavidGodefroid/lockssh/$V/scripts/install.sh"
less install.sh
LOCKSSH_VERSION=$V sh install.sh
```

It checks the release's cosign signature and checksum, and installs the
launcher as `/usr/local/bin/lockssh` (with `sudo` when needed; set
`LOCKSSH_INSTALL_DIR` for another directory). The launcher runs the image of
its own release, `ghcr.io/davidgodefroid/lockssh:X.Y.Z`, which Docker pulls
on first use: `install.sh` checks the image's cosign signature too (and its
`-vault` variant's) and writes the verified digests into the launcher, which
runs the image by digest, never by a tag that could be moved. Linux and
macOS (Docker Desktop); on Windows, install it in WSL 2 with Docker
Desktop's WSL integration and run it there.

```sh
lockssh version    # the launcher's version and its image's
lockssh update     # the latest release: a new launcher, then docker pull
lockssh update vX.Y.Z
```

`lockssh update` checks the signatures and the checksum as `install.sh`
does, and needs cosign the same way. With `LOCKSSH_SKIP_COSIGN=1` nothing is
verified and the launcher runs the image by its tag.

### What runs where

The launcher mounts the project (the nearest directory up from where you
are that holds `.lockssh/`, or that directory itself) at its own path, and
runs each command with the account it needs:

| Command | Runs as | Volumes |
|---|---|---|
| `console` | `lockssh`, in a container of its own per project (`lockssh-console-<n>`; `LOCKSSH_CONSOLE_NAME` names it), with `--add-host=host.docker.internal:host-gateway`, no log driver, no capability, `no-new-privileges`, a read-only root with a 64 MB `/tmp`, at most 256 processes and 1 GB of memory | `lockssh-run`, `lockssh-home` |
| `init` | you (your uid and gid), with your home mounted: it writes the agents' files | |
| `profile add` | you, with `HOME=/tmp` | |
| the agent commands: `mcp`, `status`, `run`, `request`, `doctor`... | `agent` | the socket volume of the workspace's lockssh lock that `lox run` runs, read-only ([below](#the-socket-of-lox-runs-lock)) |
| `doctor --fix` | root for its repairs only, then `agent` for every check, as `doctor` | as `doctor` |
| everything else: `help`... | `agent` | none |

The socket name is derived from the project path, so the console and the
agent see the same one, and the console's hints name real paths. The agent
account must enter the project directory, the only one of the path that
keeps its host mode in the container: mode 0755, the usual, does it
(`lockssh doctor` reports a project it cannot enter). `doctor` checks
`.lockssh/` for your uid, which the launcher passes as `LOCKSSH_HOST_UID`.

The launcher reads:

- `LOCKSSH_IMAGE`: the image to run instead of the release's, for example
  your own build (below);
- `LOCKSSH_VAULT=1`: the image with the `vault` CLI
  ([Credentials from Vault](#credentials-from-vault));
- `LOCKSSH_DOCKER_ARGS`: more `docker run` arguments, split on spaces, for
  example `LOCKSSH_DOCKER_ARGS="--network lockssh-net" lockssh console`;
- `LOCKSSH_READONLY_PROJECT=1`: the console mounts the project read-only and
  only `.lockssh/` writable (it must then be a directory, not a link), for a
  project your agents write;
- `VAULT_ADDR`, `VAULT_NAMESPACE`: passed to the console; `VAULT_CACERT`
  too, with its file mounted read-only at its own path.

The launcher never mounts the Docker socket.

### The socket of lox run's lock

The consoles run hub-attached only, started by `lox run` (lockhub): each
under compose, with its socket in the volume
`lockfamily-<8 hex of sha256(workspace)>_<instance>-run`, which `lox run`
names in `<workspace>/.lockfamily/up.json` (lockhub's `docs/lox-run.md`).
The agent commands mount that volume on `/run/lockssh`, read-only
(connecting to a socket needs no write), and no other: without it they stop
(exit 2) and say why, and what to do (`lox run`), never falling back to the
fixed `lockssh-run`. The launcher takes the volume only after the checks
lea makes for its own agents:

- `up.json` is found in the nearest directory up from here whose
  `.lockfamily` holds one (that directory is the workspace); the
  `.lockfamily` directory and `up.json` are no link, are yours, and
  neither group nor others may write them; `up.json` is lox run's state
  (version 1, as `lox run` writes it: two-space indented JSON, the values
  the launcher reads unescaped) of this very workspace (its `workspace`,
  and its `project` `lockfamily-<8 hex of sha256(workspace)>`);
- the lock is the workspace's only lockssh lock, or the one `--instance
  NAME` names (the launcher's own option, taken out of the command line;
  with several and no `--instance`, the error names them). In
  `.mcp.json`, add it to the arguments: `"args": ["mcp", "--instance",
  "NAME"]`;
- its socket volume is the one `lox run` names for it, its clients group
  the image's (10040);
- Docker confirms the volume: lox run's labels (compose's project and
  volume, `dev.lockfamily.role=socket`, its instance, type and workspace),
  read as JSON and compared whole; and every container that mounts it is
  lox run's own (compose ran it from lox run's state directory: its
  `project.working_dir` is `$XDG_STATE_HOME/lockfamily/<project>` or
  `~/.local/state/lockfamily/<project>`, its `config_files` `-` or that
  directory's `compose.yaml`) or mounts it read-only (the agents', as the
  launcher's own). A compose file written in the workspace, with lox run's
  project name and volume, or any container mounting the volume
  read-write, could serve the socket from an image of its own: the
  launcher then trusts none of that socket.

`up.json` only names the lock: what is mounted is what Docker's labels
prove. Anything else fails closed.

What these checks are for: mistakes (a stale or copied `up.json`, another
workspace's lock, a volume or compose file of the same name) and files
others than you can write. They are no boundary against an agent that
runs as you on the host with Docker access (Claude Code started in a
terminal usually does): it can write `up.json`, make volumes and
containers with any labels, or `docker exec` into lox run's containers.
Even then it holds none of the console's credentials and cannot sign a
decision (the hub signs them, the console checks the hub's key), but it
could serve an impostor socket to another agent. To contain the agent
itself, run it in lea, whose containers have no Docker access.

The socket's name derives from the project (`.lockssh/config.toml` up from
the working directory) and the profile: run the agent from the workspace,
whose `.lockssh` lox run's console serves.

### Paths

A project path, `$HOME` (for `init`) or a `VAULT_CACERT` path holding `:` is
refused: docker `-v` separates on it. `LOCKSSH_DOCKER_ARGS` is split on
spaces and never globbed. With `LOCKSSH_READONLY_PROJECT=1`, `.lockssh/` must
be a directory whose physical path is itself; the launcher checks it twice,
the second time right before `docker run`, but cannot close the instant
between that check and Docker's own mount: an agent that can replace
`.lockssh` in that instant could redirect the console's writable mount.
Mount `.lockssh` read-only in the agents' containers to close it.

On macOS (Docker Desktop), `lockssh doctor --fix` giving back to you a
`.lockssh/` an older release gave to uid 10041 (a `chown` through Docker
Desktop's file sharing) is untested so far.

### Your own build

From a clone, or without cloning:

```sh
docker build -t lockssh .
docker build -t lockssh https://github.com/DavidGodefroid/lockssh.git
```

then `LOCKSSH_IMAGE=lockssh lockssh ...`. The launcher of a clone
(`sh scripts/lockssh ...`) runs the image tagged `lockssh` by default.
`--build-arg VERSION=vX.Y.Z` sets the version that `lockssh version` prints.
The base images are pinned by digest in the `Dockerfile`.

### Migrating

From the former Docker guide: its `docker run ... lockssh ...` commands keep
working, but the launcher replaces them. Install it, then
use `lockssh console`, `lockssh init`, `lockssh profile add` (formerly
`lockssh setup`, removed); the `lockssh-run` and
`lockssh-home` volumes are the same. An agent entry that runs
`sh -c 'exec docker run ... lockssh mcp'` keeps working; `lockssh init` now
writes `lockssh mcp`, which goes through the launcher.

From a host install (the release archives and packages of v0.1.0, then
`sudo lockssh install`): `install.sh` replaces the binary with the launcher,
and the image refuses `lockssh install` and `lockssh update`. What the host
install created stays until you remove it: the `lockssh` account and the
`lockssh-clients` group, `/etc/lockssh/`, the socket directory (`/run/lockssh`,
`/etc/tmpfiles.d/lockssh.conf` on Linux), and the console account's state in
its home (approved policy, audit log). Remove a `.deb`, `.rpm` or `.apk`
package with your package manager first: releases no longer publish any.

## Set up a project

In the project directory, `init` writes `.lockssh/config.toml` with a
commented example profile, and the agent files (here Claude Code's):

```sh
lockssh init claude
```

The MCP command it writes, `lockssh mcp`, is the launcher: the agent starts
the MCP server in a throwaway container ([Wire the agent](#wire-the-agent)).

Add an SSH host profile:

```sh
lockssh profile add
```

It asks for the host, the port, the login, the authentication (`key` or
`password`), the key file in the console account, where a passphrase or a
password comes from (never for it), the allow rules and whether the agent
may ask for other commands, and appends the profile to
`.lockssh/config.toml`. Flags give the answers instead, and
`--non-interactive` never asks
(`lockssh profile add --non-interactive --host web1.example.com --user deploy --key "~/.ssh/id_ed25519" --allow uptime`;
[usage](usage.md#profiles)). Then:

- put the private key in the console's home volume, owned by `lockssh` and
  mode 0600, at the path the profile names (`~/` is `/home/lockssh`):
  `docker run --rm -i --user lockssh --entrypoint sh -v lockssh-home:/home/lockssh ghcr.io/davidgodefroid/lockssh -c 'umask 077; mkdir -p ~/.ssh; cat > ~/.ssh/id_ed25519' < key`
  (under `lox run`, the lock's own home volume);
- a host on your machine is `host.docker.internal`, which the launcher maps
  to your machine; a host in another container is its name on a network
  shared with the console's container;
- `credentials = "keychain"` needs an OS keychain, which the container does
  not have: use `none` (an unencrypted key), `ask`, or `vault` with the
  image below;
- the host key: with no `known_hosts`, the console asks you to trust the
  key it is shown on its first connection (typed on production) and records
  it in its home volume; with a `known_hosts` file you checked, it refuses
  any key the file does not hold.

Then check the setup:

```sh
lockssh doctor --fix --yes
```

`.lockssh/` stays yours: `lox run` reads it as you and copies only your own
regular files and directories that neither group nor others can write
(lockhub's `docs/lox-run.md`, "Profiles: a reviewed copy"); the console reads
that copy, never the project, and `lox run` shows you every line of its
TOML files before the copy. `doctor` reports what `lox run` would refuse;
`--fix` takes group and others' write away from your files and
directories there, and gives back to you what an older `lockssh doctor
--fix` gave the console account (uid 10041: `.lockssh/` itself and a copy of
`pii.toml`). Those repairs run as root (the launcher starts `doctor --fix`
as root); every check then runs as `agent`, as a `doctor` without `--fix`
does. A link, or a file of another account, is never repaired: replace it
with your own. The repair enters each directory and never follows a
symbolic link. On a fresh setup `doctor` exits 0: the console's line is a
warning while `lox run` starts none.

## Run the console

The console runs hub-attached only: lockhub's `lox run` starts it, with its
hub flags (`lockssh console` on its own refuses to start: "launched by `lox
run` only"). That takes lockhub's release after v0.10.1, the first with the
lockssh lock type ([lockhub#133](https://github.com/DavidGodefroid/lockhub/issues/133));
an older `lox` starts no lockssh console. From the workspace:

```sh
lox add lockssh events   # its questions: host, port, login, key file, allow rules
lox run                  # keep it open: it starts the console and serves the decisions
lox attach events        # the console's own questions: policy review, host key, passphrase (detach: Ctrl-P Ctrl-Q)
lox approve              # the agent's commands outside the allow list
```

The rest of this page describes the launcher's own console container
(`lockssh console` with the hub flags `lox run` writes): its options,
`--profile P`, `--show-results` or `--allow-unmask`, and
`LOCKSSH_DOCKER_ARGS="--network NAME"` for an SSH host in a container. The
`lockssh-home` volume keeps the console account's state from one run to the
next: the approved policy, the audit log and `~/.ssh/known_hosts` for an
`ssh` profile. A key for an `ssh` tunnel must be in that volume, owned by
`lockssh` with mode 0600.

## Credentials from Vault

`credentials = "vault"` runs the `vault` CLI in the console's container. The
default image leaves it out (it adds some 550 MB); the release's `-vault`
image has it (`ghcr.io/davidgodefroid/lockssh:X.Y.Z-vault`, checked against
the pinned Vault release sums), which `LOCKSSH_VAULT=1` selects. For your own
build, `docker build --target vault -t lockssh:vault .` and
`LOCKSSH_IMAGE=lockssh:vault`.

The console reads `VAULT_ADDR` and `VAULT_NAMESPACE` from its environment,
which the launcher passes on:

```sh
LOCKSSH_VAULT=1 VAULT_ADDR=https://vault.example.com lockssh console
```

`VAULT_CACERT` names a file on your machine: the launcher mounts it
read-only in the console's container, at the same path.

The console account needs no `vault login`: at start the console asks
`Vault token for <VAULT_ADDR>:` in its terminal (no echo) and keeps the
token in memory for the session, never in `lockssh-home` or anywhere on
disk.

Get the token without storing it, then paste it at the prompt:

```sh
vault login -method=oidc -no-store -token-only
```

`-no-store -token-only` prints the token and writes no `~/.vault-token`.
A plain `vault login` would store the token in your account, where the
agent runs: the agent could read it and fetch the login from Vault itself,
bypassing the console. The console does not read a stored token (`VAULT_TOKEN`
wins), so a stored one can be deleted. For the same reason,
do not leave `VAULT_TOKEN` set in that shell. When Vault refuses a read
(`not authenticated or not allowed`: the token is expired or revoked, or
its policy may not read `vault_path`), the console asks for a token again;
three refusals in a row stop the connection.

## Wire the agent

`lockssh init claude` wrote `lockssh mcp` as the MCP command in `.mcp.json`:
the agent runs the launcher, which starts the MCP server in a throwaway
container, as `agent`, with the socket volume and the project mounted. Start
the agent at the project root, or below it.

```json
{
  "mcpServers": {
    "lockssh": {
      "type": "stdio",
      "command": "lockssh",
      "args": ["mcp"]
    }
  }
}
```

For every project instead, `claude mcp add --scope user lockssh -- lockssh
mcp`. Gemini CLI and Cursor take the same `command` and `args` in the files
`lockssh init` writes for them (`.gemini/settings.json`, `.cursor/mcp.json`),
and Codex in the `[mcp_servers.lockssh]` table `lockssh init codex` prints for
`~/.codex/config.toml`. Keep the timeouts there (`timeout`,
`tool_timeout_sec`): the console waits up to 5 minutes for an approval.

The client commands run the same way: `lockssh status`, `lockssh run`...

`lockssh doctor` runs as `agent` (`--fix` makes its repairs as root first); `docker run --rm --user lockssh -v
lockssh-run:/run/lockssh -v lockssh-home:/home/lockssh
ghcr.io/davidgodefroid/lockssh:X.Y.Z doctor` checks the console account.

## Agent in its own container

When the agent itself runs in a container that cannot reach the Docker
socket, the launcher cannot start the MCP server: the agent runs the
`lockssh` binary inside its own container instead, as a client of the
console container. The two containers share only the socket volume.

The console checks every peer by uid against its own container's accounts,
where the agent's uid has none: name it when you start the console, with
the release image as it is:

```sh
lockssh console --allowed-uids 1000
```

or at build time, in an image of your own:

```sh
docker build -t lockssh --build-arg ALLOWED_UIDS=1000 .
LOCKSSH_IMAGE=lockssh lockssh console
```

`--allowed-uids` and `ALLOWED_UIDS` are comma-separated lists of uids: the
build writes them to `allowed_uids` in the image's `/etc/lockssh/system.toml`,
the flag adds them to it for that console only (the console prints them at
start). Both refuse root (0), the console's own uid (10041) and 65534
(nobody, the kernel's overflow uid). Only whoever starts the console sets
them: the human, through the launcher (which passes the flag on) or
through `lox run` (lockhub v0.2.4 or later: a lock's `allowed_uids` in the
lockfamily.yaml `lox run` reviews with you); no client can. It is the uid the kernel reports
for the agent's process, as the console sees it: the agent container's uid
when neither container remaps user namespaces. Every process of that uid,
in any container that mounts the socket volume, may then use the console:
name only the agent's.

The agent's image needs what a client host has:

- the `lockssh` binary, not the launcher: the one in the release archive
  (`lockssh_X.Y.Z_linux_ARCH.tar.gz`, checked as `install.sh` checks it),
  the same version as the console's image;
- `/etc/lockssh/system.toml`, owned by root, mode 0644, with the image's
  `service_user`, `client_group` and `socket_dir`: without it the client looks
  for the socket in the user's runtime directory;
- an account `lockssh` with uid 10041: the client refuses a socket served by
  any uid but `service_user`'s;
- a group `lockssh-clients` with gid 10040 that holds the agent's account:
  the socket directory is mode 2710 and the socket 0660, group
  `lockssh-clients`.

Start the agent's container with the socket volume and the project at the
same path as the console's, for example:

```sh
docker run … -v lockssh-run:/run/lockssh -v "$PWD:$PWD" -w "$PWD" agent-image
```

`lockssh init claude` then needs no change: the `lockssh mcp` it writes in
`.mcp.json` runs inside the agent's container. Check from there with
`lockssh status`.

## An SSH host in a container

Put the host and the console on one network, and name the host by its
container name in the profile:

```sh
docker network create lockssh-net
docker run -d --name web1 --network lockssh-net -e PUBLIC_KEY="$(cat key.pub)" -e USER_NAME=deploy lscr.io/linuxserver/openssh-server
```

```toml
[profiles.dev]
host = "web1"
port = 2222
user = "deploy"
key  = "~/.ssh/id_ed25519"
```

and start the console on it: `LOCKSSH_DOCKER_ARGS="--network lockssh-net"`.

Give the SSH account only the rights the allow list needs: a user of its
own, no `sudo`, read access to the logs it must read. Never give the agent
`docker exec` on that container: it is a shell with the container's own
rights.

## What Docker does and does not separate

Inside Docker the boundary is the same as on a host: the agent's container
holds no key, has no SSH connection and reaches the console only
through the socket; a process that is neither the console account nor in
`lockssh-clients` (nor in `ALLOWED_UIDS` or `--allowed-uids`) is refused.

Your own account is another matter. Whoever can run `docker` commands can
`docker attach` to the console and type an approval, `docker exec` into it
and read its memory, or open the `lockssh-home` volume. An agent that runs
shell commands in your account usually can: the launcher it runs for the
MCP server is itself a `docker run`. The console cannot see this (its terminal belongs to the
container), so treat Docker mode like the in-agent approval it improves on:
it keeps credentials out of the agent's reach and the approval in your
terminal, but it does not stop an agent determined to go around it. For that
boundary, run the agent itself in a container with no access to the Docker
socket ([Agent in its own container](#agent-in-its-own-container)).
