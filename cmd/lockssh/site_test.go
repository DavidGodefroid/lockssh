package main

import (
	"html"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockssh/internal/mcptools"
)

// The verbs of lockhub's lox the site may name.
var loxVerbs = []string{"init", "add", "run", "attach"}

var (
	codeRe   = regexp.MustCompile(`(?s)<(code|pre)\b[^>]*>(.*?)</(code|pre)>`)
	tagRe    = regexp.MustCompile(`<[^>]+>`)
	lockssh  = regexp.MustCompile(`(?m)^\s*lockssh ([a-z][a-z-]*)`)
	lox      = regexp.MustCompile(`(?m)^\s*lox ([a-z][a-z-]*)`)
	flagRe   = regexp.MustCompile(`--[a-z][a-z-]*`)
	toolRe   = regexp.MustCompile(`\blockssh_[a-z_]+`)
	cmdStart = regexp.MustCompile(`^lockssh [a-z]`)
)

// The flags every client command takes (the help's "Client commands" header).
var clientFlags = []string{"--profile", "--json", "--instance"}

// commandUsage is the help's entries for a command: its line and the more
// indented lines under it (both "profile add" and "profile rules" for profile).
func commandUsage(cmd string) string {
	var b strings.Builder
	in := false
	for _, l := range strings.Split(usageText, "\n") {
		if strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "   ") {
			in = strings.HasPrefix(l, "  "+cmd+" ") || l == "  "+cmd
		}
		if in {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

// siteCode is the text of every <code> and <pre> of the site's pages, by page.
func siteCode(t *testing.T) map[string][]string {
	t.Helper()
	pages, err := filepath.Glob("../../site/*.html")
	if err != nil {
		t.Fatal(err)
	}
	more, _ := filepath.Glob("../../site/*/index.html")
	pages = append(pages, more...)
	if len(pages) < 6 {
		t.Fatalf("site pages: %v", pages)
	}
	out := map[string][]string{}
	for _, p := range pages {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range codeRe.FindAllStringSubmatch(string(b), -1) {
			out[p] = append(out[p], html.UnescapeString(tagRe.ReplaceAllString(m[2], "")))
		}
		if s := string(b); strings.Contains(s, "lox up") || strings.Contains(s, "up.json") {
			t.Errorf("%s names lox up or up.json", p)
		}
	}
	return out
}

// The site names only the commands, flags and MCP tools lockssh has, and
// only lox's init, add, run and attach.
func TestSiteNamesRealCommands(t *testing.T) {
	tools := []string{mcptools.ToolStatus, mcptools.ToolRun, mcptools.ToolPIIList, mcptools.ToolPIIAdd, mcptools.ToolRequestChange}
	for page, codes := range siteCode(t) {
		for _, c := range codes {
			for _, m := range lockssh.FindAllStringSubmatch(c, -1) {
				if !regexp.MustCompile(`(?m)^  `+m[1]+`\b`).MatchString(usageText) && !strings.Contains(usageText, " "+m[1]+" [--json]") {
					t.Errorf("%s: lockssh %s is no lockssh command", page, m[1])
				}
			}
			for _, m := range lox.FindAllStringSubmatch(c, -1) {
				if !slices.Contains(loxVerbs, m[1]) {
					t.Errorf("%s: lox %s is not one of %v", page, m[1], loxVerbs)
				}
			}
			for _, tool := range toolRe.FindAllString(c, -1) {
				if !slices.Contains(tools, tool) {
					t.Errorf("%s: %s is no MCP tool", page, tool)
				}
			}
			// A flag on its own (<code>--instance NAME</code>) is lockssh's.
			if f := flagRe.FindString(c); f != "" && strings.HasPrefix(c, f) && !strings.Contains(usageText, f) {
				t.Errorf("%s: %s is no lockssh flag", page, f)
			}
			// A command line's flags, up to "--" (the remote program's own).
			for _, line := range strings.Split(strings.ReplaceAll(c, "\\\n", " "), "\n") {
				line = strings.TrimSpace(line)
				if !cmdStart.MatchString(line) {
					continue
				}
				line, _, _ = strings.Cut(line, " -- ")
				line, _, _ = strings.Cut(line, "#")
				usage := commandUsage(strings.Fields(line)[1])
				for _, f := range flagRe.FindAllString(line, -1) {
					if !strings.Contains(usage, f) && !slices.Contains(clientFlags, f) {
						t.Errorf("%s: %q: %s is no flag of that command", page, line, f)
					}
				}
			}
		}
	}
}
