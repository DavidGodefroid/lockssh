package command

import (
	"strings"
	"testing"
)

// The bypasses of docs/decisions.md ("Allow-rule globs"): each one is
// refused, and the arguments the rules are written for still match.
func TestGlobBypassesRefused(t *testing.T) {
	cases := []struct {
		rule string
		argv []string
		want bool
	}{
		// The table of decisions.md, each refused.
		{"git log *", []string{"git", "log", "--output=/home/u/.bashrc"}, false},
		{"journalctl *", []string{"journalctl", "--vacuum-time=1s"}, false},
		{"tar -tf *", []string{"tar", "-tf", "--to-command=sh"}, false},
		{"cat /var/log/*/*/*", []string{"cat", "/var/log/../../etc/shadow"}, false},
		{"ls *", []string{"ls", ".."}, false},
		{"less *", []string{"less", "+!id"}, false},
		// And what they are written for.
		{"git log *", []string{"git", "log", "main"}, true},
		{"tar -tf *", []string{"tar", "-tf", "backup.tar"}, true},
		{"cat /var/log/*/*/*", []string{"cat", "/var/log/nginx/old/error.log"}, true},
		{"ls *", []string{"ls", "src"}, true},
		{"less *", []string{"less", "notes.txt"}, true},

		// Rule 1: no option the human never wrote.
		{"ls *", []string{"ls", "-la"}, false},
		{"ls *", []string{"ls", "-"}, false},
		{"ls *", []string{"ls", "+"}, false},
		{"ls ?", []string{"ls", "-"}, false},
		{"ls [^b]", []string{"ls", "-"}, false},
		{"ls [+a]", []string{"ls", "+"}, false},
		{"ls *", []string{"ls", "a-b"}, true},
		{"journalctl --since=*", []string{"journalctl", "--since=today"}, true},
		{"journalctl --since=*", []string{"journalctl", "--since=--x"}, true},
		{"date +*", []string{"date", "+%F"}, true},
		{"date +*", []string{"date", "-u"}, false},
		{"ls -*", []string{"ls", "-la"}, true},
		{"ls -*", []string{"ls", "+x"}, false},
		{"echo **", []string{"echo", "a", "b"}, true},
		{"echo **", []string{"echo", "-e", "a"}, false},
		{"echo **", []string{"echo", "a", "-e"}, false},
		{"echo **", []string{"echo", "--", "-e"}, false},
		{"echo **", []string{"echo", "+x"}, false},
		// After a literal "--", operands may start with - or +.
		{"grep -- * file", []string{"grep", "--", "-v", "file"}, true},
		{"grep -- *", []string{"grep", "--", "+x"}, true},
		{"rm -- **", []string{"rm", "--", "-rf", "+x"}, true},
		{"grep * -- *", []string{"grep", "-v", "--", "x"}, false},
		{"grep * -- *", []string{"grep", "x", "--", "-v"}, true},

		// Rule 2: no . or .. segment a glob covers.
		{"cat *", []string{"cat", "."}, false},
		{"cat *", []string{"cat", "..."}, true},
		{"cat /var/log/*", []string{"cat", "/var/log/.."}, false},
		{"cat /var/log/*", []string{"cat", "/var/log/."}, false},
		{"cat /var/log/*", []string{"cat", "/var/log/.hidden"}, true},
		{"cat /var/log/*/x", []string{"cat", "/var/log/../x"}, false},
		{"cat ?/x", []string{"cat", "./x"}, false},
		{"cat ??/x", []string{"cat", "../x"}, false},
		{"cat [.][.]/x", []string{"cat", "../x"}, false},
		{"cat ../*", []string{"cat", "../x"}, true},
		{"cat ../*", []string{"cat", "../.."}, false},
		{"cat ../x", []string{"cat", "../x"}, true},
		{"cat x/*", []string{"cat", "x/"}, true},
		{"echo **", []string{"echo", "a/../b"}, false},
		{"echo **", []string{"echo", "./a"}, false},
		{"echo **", []string{"echo", ".."}, false},
		{"echo **", []string{"echo", "a/b.c"}, true},
		{"cat -- **", []string{"cat", "--", "../x"}, false},
		{"cat -- *", []string{"cat", "--", ".."}, false},
	}
	for _, c := range cases {
		r, err := ParseRule(c.rule)
		if err != nil {
			t.Fatalf("%q: %v", c.rule, err)
		}
		if got := r.Match(c.argv); got != c.want {
			t.Errorf("%q %q: %t, want %t", c.rule, c.argv, got, c.want)
		}
	}
}

func TestLineExec(t *testing.T) {
	if got := Line([]string{"eval", "id;rm x"}); got != `exec 'eval' 'id;rm x'` {
		t.Errorf("Line = %q", got)
	}
}

func TestCheckProgramOption(t *testing.T) {
	for _, a := range [][]string{{"-c", "id"}, {"+x"}, {"-"}, {"--"}} {
		if err := Check(a); err == nil {
			t.Errorf("%q accepted", a)
		} else if !strings.Contains(err.Error(), "argument 1") {
			t.Errorf("%q: %v", a, err)
		}
	}
	if err := Check([]string{"ls", "-l", "+x"}); err != nil {
		t.Error(err)
	}
}

func TestBuiltinRuleRefused(t *testing.T) {
	for _, b := range []string{"eval *", "exec ls", "command -v *", "builtin echo", ". /etc/profile", "source x",
		"trap *", "fc -s", "enable -f x", "let *", "alias *", "typeset *", "declare *", "read x", "set -x", "export *",
		"unset x", "local x", "readonly x", "cd /", "if", "for", "{", "!", "time"} {
		if b == "time" {
			// time is a program too (/usr/bin/time).
			if _, err := ParseRule(b); err != nil {
				t.Errorf("%q: %v", b, err)
			}
			continue
		}
		_, err := ParseRule(b)
		if err == nil {
			t.Errorf("%q accepted", b)
			continue
		}
		if !strings.Contains(err.Error(), "builtin") {
			t.Errorf("%q: %v", b, err)
		}
	}
	for _, ok := range []string{"echo *", "test -f x", "printf x", "true", "kill -0 *", "pwd", "/usr/bin/eval", "evaluate"} {
		if _, err := ParseRule(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
}

func TestProgramName(t *testing.T) {
	for in, want := range map[string]string{
		"python3.11": "python", "perl5.36": "perl", "php8.2": "php", "node18": "node", "lua5.4": "lua",
		"sqlite3": "sqlite", "/usr/bin/sed": "sed", "/usr/local/bin/python3": "python", "gawk": "gawk",
		"sh": "sh", "shred": "shred", "attr": "attr", "R": "R", "42": "42", "x-1.2": "x-", "py_3": "py_",
	} {
		if got := ProgramName(in); got != want {
			t.Errorf("ProgramName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWarnings(t *testing.T) {
	cases := []struct {
		rule string
		warn bool
	}{
		{"sed -n * f", true},
		{"awk *", true},
		{"env **", true},
		{"/usr/bin/python3.11 *", true},
		{"python3 -c *", true},
		{"python3 --version", false},
		{"sqlite3 *", true},
		{"sh **", true},
		{"shred *", false},
		{"attr *", false},
		{"at *", true},
		{"dd *", true},
		{"tee *", true},
		{"ash **", true},
		{"yash *", true},
		{"sudoedit *", true},
		{"npx *", true},
		{"yarn *", true},
		{"java *", true},
		{"jshell *", true},
		{"systemctl status nginx", false},
		{"systemctl status *", true},
		{"cat /var/log/*", false},
		{"ls -*", true},
		{"ls --*", true},
		{"ls -[a-z]", true},
		{"journalctl --since=*", false},
		{"journalctl --since=-*", false},
		{"grep -- *", true},
		{"rm -- **", true},
		{"cat --", false},
		{"echo **", false},
	}
	for _, c := range cases {
		r, err := ParseRule(c.rule)
		if err != nil {
			t.Fatalf("%q: %v", c.rule, err)
		}
		w := r.Warnings()
		if (len(w) > 0) != c.warn {
			t.Errorf("%q: warnings %q, want any: %t", c.rule, w, c.warn)
		}
		for _, s := range w {
			if !strings.HasPrefix(s, "allow rule "+r.String()+": ") {
				t.Errorf("%q: warning %q does not name the rule", c.rule, s)
			}
		}
	}
	// Every program of the table is a base name, already stripped.
	for _, p := range codePrograms {
		if ProgramName(p) != p {
			t.Errorf("table entry %q is not a stripped base name", p)
		}
	}
}
