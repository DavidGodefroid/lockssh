package agentassets

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockssh/internal/mcptools"
)

// The texts name lockssh only: another product's name would send the agent
// to a tool that is not this one.
func TestSkillHasNoProductNamesOfOthers(t *testing.T) {
	for name, text := range map[string][]byte{"skill": Skill, "instructions": Instructions, "cursor": CursorFrontMatter, "config": ProjectConfig} {
		low := strings.ToLower(string(text))
		for _, other := range []string{"locksql", "lockfile", "lockkit"} {
			if strings.Contains(low, other) {
				t.Errorf("%s names %s", name, other)
			}
		}
	}
}

// Every tool the texts name exists, and Claude Code never auto-allows a
// tool that reads message content.
func TestTextsNameRealTools(t *testing.T) {
	tools := map[string]bool{}
	for _, n := range mcptools.Names() {
		tools[n] = true
	}
	for _, f := range strings.FieldsFunc(string(Skill)+string(Instructions), func(r rune) bool {
		return !(r == '_' || r >= 'a' && r <= 'z')
	}) {
		if strings.HasPrefix(f, "lockssh_") && f != "lockssh_" && !tools[f] {
			t.Errorf("texts name unknown tool %s", f)
		}
	}
	for _, a := range Wiring.Assets.ClaudeAllow {
		if strings.Contains(a, "lockssh_run") || strings.Contains(a, "lockssh run") {
			t.Errorf("auto-allowed: %s", a)
		}
	}
}
