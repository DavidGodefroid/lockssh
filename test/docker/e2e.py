#!/usr/bin/env python3
"""End-to-end test of the lockssh image, following docs/docker.md.

An SSH server container and the console container share a network; the
console runs in a pseudo-terminal this script answers (policy, host key),
holds the SSH key in its home volume, and is attached to a hub as
`lox up` starts it (the hub flags are required; the hub named here is not
running, so the first command waits for its connect ticket: the decision
on a real hub is lockhub's own end-to-end test); the agent's commands run in
throwaway containers that share only the socket volume and the project.
It also checks the image's accounts and modes, that the console refuses to
start without its hub, and that it refuses a peer that is neither lockssh
nor in lockssh-clients.

    python3 test/docker/e2e.py IMAGE

Needs docker and ssh-keygen; uses the names lockssh-e2e-* and removes them.
Standard library only.
"""

import base64
import json
import os
import pty
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

IMAGE = sys.argv[1] if len(sys.argv) > 1 else "lockssh"
NET, SSHD, CONSOLE = "lockssh-e2e-net", "lockssh-e2e-sshd", "lockssh-e2e-console"
RUN_VOL, HOME_VOL = "lockssh-e2e-run", "lockssh-e2e-home"
SSH_IMAGE = "lscr.io/linuxserver/openssh-server:latest"
SSH_USER = "deploy"
HUB_URL, INSTANCE = "http://lockssh-e2e-hub:8443", "web-e2e"
KEYDIR = tempfile.mkdtemp(prefix="lockssh-e2e-key-")

failures = []


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what, flush=True)
    if not ok:
        failures.append(what)


def sh(*args, check_=True, **kw):
    r = subprocess.run(args, capture_output=True, text=True, **kw)
    if check_ and r.returncode != 0:
        raise SystemExit(f"{' '.join(args)}: exit {r.returncode}\n{r.stdout}{r.stderr}")
    return r


def cleanup():
    sh("docker", "rm", "-f", CONSOLE, SSHD, check_=False)
    sh("docker", "volume", "rm", "-f", RUN_VOL, HOME_VOL, check_=False)
    sh("docker", "network", "rm", NET, check_=False)


def image_checks():
    def in_image(script):
        return sh("docker", "run", "--rm", "--user", "0", "--entrypoint", "sh", IMAGE, "-c", script).stdout.strip()

    who = sh("docker", "run", "--rm", "--entrypoint", "id", IMAGE, "-un").stdout.strip()
    check(who == "agent", f"default user is agent ({who})")
    check(in_image("stat -c '%a %U:%G' /run/lockssh") == "2710 lockssh:lockssh-clients", "socket dir 2710 lockssh:lockssh-clients")
    check(in_image("stat -c '%a %U' /home/lockssh") == "700 lockssh", "console home 0700")
    check(in_image("stat -c '%a %U:%G' /usr/local/bin/lockssh /etc/lockssh/system.toml") == "755 root:root\n644 root:root",
          "binary and system.toml root-owned")
    check(in_image("id -Gn lockssh") == "lockssh", "console account not in lockssh-clients")
    check(in_image("id -Gn agent | tr ' ' '\\n' | grep -x lockssh-clients") == "lockssh-clients", "agent in lockssh-clients")
    check(in_image("command -v sudo su-exec doas || true") == "", "no sudo in the image")
    check(in_image("grep -c allowed_uids /etc/lockssh/system.toml || true") == "0", "no allowed_uids by default")


def start_sshd():
    """An SSH server that accepts the e2e key for SSH_USER, and the key
    copied into the console account's home volume."""
    key = os.path.join(KEYDIR, "id_e2e")
    sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
    with open(key + ".pub") as f:
        pub = f.read().strip()
    sh("docker", "network", "create", NET)
    sh("docker", "run", "-d", "--name", SSHD, "--network", NET, "-e", f"PUBLIC_KEY={pub}",
       "-e", f"USER_NAME={SSH_USER}", "-e", "PUID=1000", "-e", "PGID=1000", SSH_IMAGE)
    ip = sh("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", SSHD).stdout.strip()
    deadline = time.time() + 120
    while True:
        try:
            with socket.create_connection((ip, 2222), timeout=2) as c:
                if c.recv(64).startswith(b"SSH-2.0"):
                    break
        except OSError:
            pass
        if time.time() > deadline:
            raise SystemExit("sshd not ready:\n" + sh("docker", "logs", SSHD, check_=False).stdout[-3000:])
        time.sleep(2)
    os.chmod(KEYDIR, 0o755)
    os.chmod(key, 0o644)
    sh("docker", "run", "--rm", "--user", "0", "--entrypoint", "sh", "-v", f"{HOME_VOL}:/home/lockssh", "-v", f"{KEYDIR}:/k:ro", IMAGE,
       "-c", "install -d -m 0700 -o lockssh -g lockssh /home/lockssh/.ssh && install -m 0600 -o lockssh -g lockssh /k/id_e2e /home/lockssh/.ssh/id_e2e")


class Console:
    """The console in a pseudo-terminal, answering its prompts."""

    def __init__(self, project, *extra):
        hub = ["--hub", HUB_URL, "--hub-plain-http", "--hub-key-file", os.path.join(project, "hub.pub"), "--instance", INSTANCE]
        self.out = b""
        self.lock = threading.Lock()
        self.answered = {}
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execvp("docker", ["docker", "run", "-it", "--rm", "--name", CONSOLE, "--user", "lockssh",
                                 "--network", NET, "-v", f"{project}:{project}",
                                 "-v", f"{RUN_VOL}:/run/lockssh", "-v", f"{HOME_VOL}:/home/lockssh",
                                 IMAGE, "console", "--project", project, *hub, *extra])
        threading.Thread(target=self.pump, daemon=True).start()

    def pump(self):
        answers = [("Apply these changes? [y/N]", b"y\r"), ("Trust this key and add it to", b"yes\r"),
                   ('Type "continue" to proceed', b"continue\r")]
        while True:
            try:
                r, _, _ = select.select([self.fd], [], [], 0.2)
                if not r:
                    continue
                chunk = os.read(self.fd, 4096)
            except OSError:
                return
            if not chunk:
                return
            with self.lock:
                self.out += chunk
                text = self.out.decode("utf-8", "replace")
                for prompt, answer in answers:
                    n = text.count(prompt)
                    if n > self.answered.get(prompt, 0):
                        self.answered[prompt] = n
                        os.write(self.fd, answer)

    def text(self):
        with self.lock:
            return self.out.decode("utf-8", "replace")

    def stop(self):
        sh("docker", "rm", "-f", CONSOLE, check_=False)


def agent(project, *args, user=None, extra=()):
    cmd = ["docker", "run", "--rm", "-v", f"{project}:{project}", "-w", project, "-v", f"{RUN_VOL}:/run/lockssh"]
    if user:
        cmd += ["--user", user]
    cmd += list(extra) + [IMAGE] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=360)


def main():
    cleanup()
    try:
        image_checks()
        start_sshd()
        project = tempfile.mkdtemp(prefix="lockssh-e2e-")
        os.chmod(project, 0o755)  # the console account enters the project
        me = f"{os.getuid()}:{os.getgid()}"
        mount = ["-v", f"{project}:{project}", "-w", project]

        # Set up a project (docs/docker.md).
        r = sh("docker", "run", "--rm", "--user", me, "-e", "HOME=/tmp", *mount, IMAGE, "init", "claude")
        check(os.path.exists(os.path.join(project, ".lockssh", "config.toml")), "init writes .lockssh/config.toml")
        check(os.stat(os.path.join(project, ".lockssh")).st_uid == os.getuid(), "init files belong to the caller")
        # lox add's calls: profile add --non-interactive --json, doctor --fix --yes --json.
        target = ["--host", SSHD, "--port", "2222", "--user", SSH_USER, "--key", "~/.ssh/id_e2e"]
        r = sh("docker", "run", "--rm", "--user", me, "-e", "HOME=/tmp", *mount, IMAGE, "profile", "add",
               "--non-interactive", "--json", "--profile", "dev", *target, "--allow", "uname -s", "--allow", "id -un")
        prof = json.loads(r.stdout)
        check(prof.get("profile") == "dev" and prof.get("credentials") == "none" and prof.get("lock") == "lockssh",
              f"profile add --non-interactive --json writes the profile\n{r.stdout}{r.stderr}")
        r = sh("docker", "run", "--rm", "--user", me, "-e", "HOME=/tmp", *mount, IMAGE, "profile", "add",
               "--non-interactive", "--json", "--profile", "dev", *target, check_=False)
        check(r.returncode != 0 and json.loads(r.stdout).get("code") == "exists", f"profile add keeps an existing profile\n{r.stdout}{r.stderr}")
        # As the launcher runs it: root for the repairs, your uid for the
        # checks of .lockssh, which then run as the agent account.
        host_uid = ["-e", f"LOCKSSH_HOST_UID={os.getuid()}"]
        r = sh("docker", "run", "--rm", "--user", "0", *host_uid, *mount, IMAGE, "doctor", "--fix", "--yes", "--json", check_=False)
        doc = json.loads(r.stdout)
        check(r.returncode == 0 and doc.get("ok") is True, f"doctor --fix --yes --json passes on a fresh setup\n{r.stdout}{r.stderr}")

        def lox_up_copies(why):
            # lox up copies only your own files and directories that no one
            # else can write (lockhub's docs/lox-up.md).
            bad = []
            for d, dirs, files in os.walk(os.path.join(project, ".lockssh")):
                for p in [d] + [os.path.join(d, f) for f in files]:
                    st = os.lstat(p)
                    if st.st_uid != os.getuid() or st.st_mode & 0o022:
                        bad.append(f"{p} uid {st.st_uid} mode {st.st_mode & 0o777:04o}")
            check(not bad, f"{why}: .lockssh is yours, written by you only {bad}\n{r.stdout}{r.stderr}")

        lox_up_copies("doctor --fix")
        # What an older doctor --fix left (.lockssh and pii.toml given to the
        # console account) is given back to you.
        with open(os.path.join(project, ".lockssh", "pii.toml"), "w") as f:
            f.write("[[mask]]\n")
        sh("docker", "run", "--rm", "--user", "0", "--entrypoint", "chown", *mount, IMAGE, "10041",
           os.path.join(project, ".lockssh"), os.path.join(project, ".lockssh", "pii.toml"))
        r = sh("docker", "run", "--rm", *host_uid, *mount, IMAGE, "doctor", "--json", check_=False)
        check(r.returncode == 1 and "as an older lockssh doctor --fix left it" in r.stdout, f"doctor reports the console account's .lockssh\n{r.stdout}{r.stderr}")
        r = sh("docker", "run", "--rm", "--user", "0", *host_uid, *mount, IMAGE, "doctor", "--fix", "--yes", "--json", check_=False)
        doc = json.loads(r.stdout)
        check(r.returncode == 0 and doc.get("ok") is True and doc.get("fixed"), f"doctor --fix gives it back\n{r.stdout}{r.stderr}")
        lox_up_copies("doctor --fix after an older one")
        os.remove(os.path.join(project, ".lockssh", "pii.toml"))

        # Without its hub the console refuses to start: launched by lox up only.
        r = sh("docker", "run", "--rm", "--user", "lockssh", "-v", f"{project}:{project}",
               IMAGE, "console", "--project", project, check_=False)
        check(r.returncode != 0 and "launched by `lox up` only" in r.stdout + r.stderr, f"console without --hub refused\n{r.stdout}{r.stderr}")

        # Run the console, attached to a hub (its pinned key; the hub itself
        # is not running).
        with open(os.path.join(project, "hub.pub"), "w") as f:
            f.write(base64.b64encode(os.urandom(32)).decode() + "\n")
        os.chmod(os.path.join(project, "hub.pub"), 0o644)
        con = Console(project)
        deadline, up = time.time() + 120, False
        while time.time() < deadline:
            if agent(project, "status").returncode == 0:
                up = True
                break
            time.sleep(2)
        check(up, "lockssh status from the agent's container")
        if not up:
            print(con.text()[-4000:])
            raise SystemExit("the console did not come up")

        check("can't be established" in con.text(), "the console asks to trust the host key")
        check("uid" in agent(project, "status", "--json").stdout, "status reports the SSH account")

        # The SSH session serves the agent only once its connect ticket is
        # approved on the hub, which is not running: the first command waits
        # for the decision (fail closed) and runs nothing.
        r = agent(project, "8", "lockssh", "run", "--json", "uname", "-s", extra=["--entrypoint", "timeout"])
        check(r.returncode != 0 and "context canceled" in r.stderr and "Linux" not in r.stdout, f"a command waits for its connect ticket, nothing ran\n{r.stdout}{r.stderr}")
        check("waits for its connect ticket" in con.text() and "auto.connect=ask" in con.text(), "the console names the connect ticket and its rule")
        # Outside the allow list (exec off): refused at once, nothing asked.
        r = agent(project, "run", "--json", "rm", "-rf", "/tmp/x")
        check(r.returncode == 1 and "E_NOT_ALLOWED" in r.stderr, f"a command outside the allow list is refused\n{r.stdout}{r.stderr}")
        check("Approve? [y/N]" not in con.text(), "no command is ever asked in the console")
        check(f"Requests are decided on lockhub at {HUB_URL} as {INSTANCE}" in con.text(), "the console names its hub")

        # Peers outside the setup.
        r = agent(project, "status", user="4242")
        check(r.returncode != 0, f"uid 4242, no group: refused (exit {r.returncode})")
        r = agent(project, "status", user="4242", extra=["--group-add", "10040"])
        check(r.returncode != 0, f"uid 4242 with gid 10040 but no account: refused by the console (exit {r.returncode}) {r.stderr.strip()}")
        # The console's own account may connect (lockkit's peer check: it
        # already holds the credentials); no other account outside the group.
        r = agent(project, "status", user="10041")
        check(r.returncode == 0, f"the console's own uid is accepted, as lockkit allows (exit {r.returncode})")
        check(agent(project, "status").returncode == 0, "console still serves the agent")

        # The key never reaches the agent's side.
        r = agent(project, "sh", "-c", "grep -rl 'PRIVATE KEY' /run/lockssh . 2>/dev/null; true", extra=["--entrypoint", ""])
        check(r.stdout.strip() == "", "no private key in the socket volume or the project")
        con.stop()
        if failures:
            print(con.text()[-4000:])

        # --allowed-uids: the release image as it is serves the uid of an
        # agent in a container of its own (no account in the image), for
        # this console only; no other such uid.
        sh("docker", "wait", CONSOLE, check_=False)
        con = Console(project, "--allowed-uids", "4242")
        out4242 = None
        deadline = time.time() + 120
        while time.time() < deadline:
            r = agent(project, "status", user="4242", extra=["--group-add", "10040"])
            if r.returncode == 0:
                out4242 = r
                break
            time.sleep(2)
        check(out4242 is not None, "--allowed-uids 4242: uid 4242 with gid 10040 served")
        check("allowed uids besides lockssh-clients (--allowed-uids): 4242" in con.text(), "the console prints the allowed uids")
        r = agent(project, "status", user="4243", extra=["--group-add", "10040"])
        check(r.returncode != 0, f"--allowed-uids 4242: uid 4243 still refused (exit {r.returncode})")
        check(agent(project, "status").returncode == 0, "--allowed-uids: the image's agent still served")
        con.stop()
        if failures:
            print(con.text()[-4000:])
        r = sh("docker", "run", "--rm", "--user", "lockssh", "-v", f"{RUN_VOL}:/run/lockssh", "-v", f"{HOME_VOL}:/home/lockssh",
               IMAGE, "console", "--allowed-uids", "0", check_=False)
        check(r.returncode != 0 and "leading zero" in r.stdout + r.stderr, f"--allowed-uids 0 refused\n{r.stdout}{r.stderr}")
    finally:
        cleanup()
    if failures:
        print(f"\n{len(failures)} failure(s)")
        sys.exit(1)
    print("\nall ok")


if __name__ == "__main__":
    main()
