package command

import (
	"strings"
	"testing"
)

func TestQuoteAndLine(t *testing.T) {
	for in, want := range map[string]string{"": "''", "a b": "'a b'", "it's": `'it'\''s'`, "$(id)": "'$(id)'"} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %q, want %q", in, got, want)
		}
	}
	if got := Line([]string{"echo", "a;b", "'"}); got != `'echo' 'a;b' ''\'''` {
		t.Errorf("Line = %q", got)
	}
	if got := Display([]string{"journalctl", "-u", "nginx", "a b", ""}); got != "journalctl -u nginx 'a b' ''" {
		t.Errorf("Display = %q", got)
	}
}

func TestCheck(t *testing.T) {
	ok := [][]string{{"uptime"}, {"echo", "tab\there", "unicode é"}}
	for _, a := range ok {
		if err := Check(a); err != nil {
			t.Errorf("%q: %v", a, err)
		}
	}
	long := strings.Repeat("x", MaxArgBytes+1)
	many := make([]string, MaxArgs+1)
	for i := range many {
		many[i] = "a"
	}
	for _, a := range [][]string{nil, {""}, {"a\nb"}, {"a\x00"}, {"\x1b[31m"}, {"a\u200bb"}, {"a\u2028"}, {long}, many, {string([]byte{0xff})}} {
		if err := Check(a); err == nil {
			t.Errorf("%q accepted", a)
		} else if strings.Contains(err.Error(), "\x1b") || strings.Contains(err.Error(), long) {
			t.Errorf("error quotes the argument: %v", err)
		}
	}
}

func TestRules(t *testing.T) {
	cases := []struct {
		rule string
		argv []string
		want bool
	}{
		{"uptime", []string{"uptime"}, true},
		{"uptime", []string{"uptime", "-p"}, false},
		{"df -h", []string{"df", "-h"}, true},
		{"systemctl status *", []string{"systemctl", "status", "nginx"}, true},
		{"systemctl status *", []string{"systemctl", "status"}, false},
		{"systemctl status *", []string{"systemctl", "restart", "nginx"}, false},
		{"journalctl -u *.service", []string{"journalctl", "-u", "nginx.service"}, true},
		{"cat /var/log/*", []string{"cat", "/var/log/../../etc/shadow"}, false},
		{"cat /var/log/*", []string{"cat", "/var/log/syslog"}, true},
		{"echo **", []string{"echo"}, true},
		{"echo **", []string{"echo", "a", "b"}, true},
		{"ls -l **", []string{"ls"}, false},
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
	for _, bad := range []string{"", "  ", "* status", "** x", "echo ** x", "echo a**", "ls [", "**"} {
		if _, err := ParseRule(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	r, _ := ParseRule("  systemctl   status  * ")
	if r.String() != "systemctl status *" {
		t.Errorf("canonical %q", r.String())
	}
	rs, err := ParseRules([]string{"uptime", "df -h"})
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := rs.Find([]string{"df", "-h"}); !ok || m.String() != "df -h" {
		t.Errorf("Find %v %v", m, ok)
	}
	if _, err := ParseRules([]string{"ok", "* bad"}); err == nil || !strings.Contains(err.Error(), "allow[1]") {
		t.Errorf("ParseRules error %v", err)
	}
}

// unquote splits a line Line wrote back into its words, as a POSIX shell
// does: single-quoted strings, '\” between them, words separated by one
// space.
func unquote(s string) ([]string, bool) {
	var out []string
	var cur strings.Builder
	in, word := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case in && c == '\'':
			in = false
		case in:
			cur.WriteByte(c)
		case c == '\'':
			in, word = true, true
		case c == '\\' && i+1 < len(s) && s[i+1] == '\'':
			i++
			cur.WriteByte('\'')
			word = true
		case c == ' ' && word:
			out = append(out, cur.String())
			cur.Reset()
			word = false
		default:
			return nil, false
		}
	}
	if in {
		return nil, false
	}
	if word {
		out = append(out, cur.String())
	}
	return out, true
}

// Whatever the arguments, the line holds nothing a shell would read as
// syntax: it splits back into exactly the argv.
func FuzzLineRoundTrip(f *testing.F) {
	for _, s := range []string{"", "a b", "it's", "$(id)", "`x`", "a;b|c>d", "'''", "\\'"} {
		f.Add("echo", s, s+s)
	}
	f.Fuzz(func(t *testing.T, a, b, c string) {
		argv := []string{a, b, c}
		got, ok := unquote(Line(argv))
		if !ok || len(got) != len(argv) {
			t.Fatalf("%q: %q %v", argv, got, ok)
		}
		for i := range argv {
			if got[i] != argv[i] {
				t.Fatalf("%q: %q", argv, got)
			}
		}
	})
}
