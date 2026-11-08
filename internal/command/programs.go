package command

import (
	"path"
	"slices"
	"strings"
)

// builtinOnly are the names a POSIX shell, bash, ksh or zsh reads as a
// builtin, keyword or reserved word, with no program of that name on a
// usual PATH (or one that only calls the builtin). Under exec (Line) a
// rule naming one could only fail, so ParseRule refuses it when the
// policy loads: the human sees why. Programs that are also builtins
// (echo, printf, test, [, kill, pwd, true, false, time) are not here.
var builtinOnly = setOf(
	// Builtins that evaluate a string, run a file in the shell or bind a name.
	".", ":", "source", "eval", "exec", "command", "builtin", "trap", "fc", "enable", "let",
	"alias", "unalias", "typeset", "declare", "local", "readonly", "export", "set", "unset",
	"shopt", "setopt", "unsetopt", "emulate", "autoload", "zmodload", "noglob", "bind",
	"complete", "compgen", "compopt", "mapfile", "readarray", "read", "hash", "type",
	"caller", "coproc", "function", "shift", "return", "exit", "break", "continue", "times",
	"getopts", "ulimit", "umask", "cd", "pushd", "popd", "dirs", "jobs", "fg", "bg", "wait",
	"disown", "suspend", "logout", "history", "print", "whence", "functions",
	// Keywords and reserved words.
	"if", "then", "else", "elif", "fi", "case", "esac", "for", "select", "while", "until",
	"do", "done", "in", "[[", "]]", "{", "}", "!", "repeat", "foreach", "end",
)

// codePrograms are the programs whose plain operands or options can be
// code, a write or another argv (docs/decisions.md, "Programs that run
// code from their arguments"): the policy review warns on a rule that
// names one with a glob or **. A safety net, not a complete list: a
// program missing from it gets no warning, and that says nothing about it
// being safe.
var codePrograms = []string{
	// Shells and interpreters.
	"sh", "ash", "bash", "dash", "ksh", "mksh", "yash", "zsh", "fish", "csh", "tcsh", "busybox",
	"perl", "python", "pypy", "ruby", "irb", "node", "nodejs", "deno", "bun", "php", "lua",
	"luajit", "tclsh", "wish", "expect", "Rscript", "R", "java", "jshell",
	// Database clients.
	"sqlite", "mysql", "mariadb", "psql",
	// Text tools with a command or write verb.
	"sed", "awk", "gawk", "mawk", "nawk", "ed", "ex", "dd", "tee",
	// Runners of another argv.
	"env", "sudo", "sudoedit", "su", "runuser", "sg", "newgrp", "doas", "pkexec", "systemd-run",
	"xargs", "parallel", "nice", "chrt", "nohup", "timeout", "stdbuf", "time", "watch", "setsid",
	"flock", "chroot", "nsenter", "unshare", "bwrap", "firejail", "ionice", "taskset", "strace",
	"ltrace", "gdb", "script",
	// Find and archive.
	"find", "tar", "zip", "rsync",
	// Network clients.
	"ssh", "scp", "sftp", "curl", "wget",
	// Version control, builds and package runners.
	"git", "make", "npm", "npx", "yarn", "pip",
	// Pagers, editors, viewers.
	"less", "more", "most", "man", "vi", "vim", "nvim", "emacs", "nano", "view",
	// Orchestrators.
	"docker", "podman", "kubectl", "systemctl", "crontab", "at", "tcpdump",
}

var codeProgram = setOf(codePrograms...)

func setOf(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// ProgramName is the name a program is looked up by in codePrograms: its
// base name with a version suffix stripped, a last run of digits, '.',
// '-' and '_' that starts with a digit (python3.11 is python, sqlite3
// sqlite). A name that is all suffix is kept. Not a prefix match: shred
// is not sh.
func ProgramName(p string) string {
	b := path.Base(p)
	i := len(b)
	for i > 0 && strings.IndexByte("0123456789._-", b[i-1]) >= 0 {
		i--
	}
	// The run starts at its first digit.
	for i < len(b) && (b[i] < '0' || b[i] > '9') {
		i++
	}
	if i == 0 || i == len(b) {
		return b
	}
	return b[:i]
}

// Warnings are the policy review's warnings on the rule (each line names
// it): a program of codePrograms given a glob or **, a token starting
// with '-' whose first glob character comes before any '=' (a glob that
// chooses an option: -*, --*, -[a-z]), and a glob or ** after a literal
// "--". The human decides; the rule stays valid.
func (r Rule) Warnings() []string {
	var out []string
	warn := func(s string) { out = append(out, "allow rule "+r.text+": "+s) }
	globs, operands, optGlob, afterDD := r.rest, false, false, r.rest && slices.Contains(r.tokens, "--")
	for _, t := range r.tokens[1:] {
		if t == "--" {
			operands = true
			continue
		}
		if !isGlob(t) {
			continue
		}
		globs = true
		if operands {
			afterDD = true
		}
		if t[0] == '-' {
			eq := strings.IndexByte(t, '=')
			if g := strings.IndexAny(t, "*?["); eq < 0 || g < eq {
				optGlob = true
			}
		}
	}
	if globs && codeProgram[ProgramName(r.tokens[0])] {
		warn(ProgramName(r.tokens[0]) + " can run code, write or start another command from its arguments: write each argument literally, no glob and no **")
	}
	if optGlob {
		warn("a glob chooses the option: the agent may pass any option the program has")
	}
	if afterDD {
		warn(`a glob after "--" matches operands that start with '-' or '+': check what the program does with them`)
	}
	return out
}
