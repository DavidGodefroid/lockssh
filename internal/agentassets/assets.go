// Package agentassets holds lockssh's agent texts (skill, instructions,
// Cursor rule, example config) and their wiring through lockkit's
// agentwire.
package agentassets

import (
	_ "embed"

	"github.com/DavidGodefroid/lockkit/agentwire"

	"github.com/DavidGodefroid/lockssh/internal/product"
)

var (
	//go:embed skill.md
	Skill []byte
	//go:embed agents.md
	Instructions []byte
	//go:embed cursor-rule.mdc
	CursorFrontMatter []byte
	//go:embed config.toml
	ProjectConfig []byte
)

// Wiring wires the agents to lockssh. Claude Code may call, without a
// prompt, only the status: lockssh_run runs a command on the host.
var Wiring = agentwire.Wiring{Product: product.P, Assets: agentwire.Assets{
	MCPCommand:        []string{"lockssh", "mcp"},
	Skill:             Skill,
	Instructions:      Instructions,
	CursorFrontMatter: CursorFrontMatter,
	ProjectConfig:     ProjectConfig,
	ClaudeAllow:       []string{"mcp__lockssh__lockssh_status", "Bash(lockssh status:*)", "Bash(lockssh doctor:*)"},
	ClaudeNote:        "lockssh_run asks Claude Code each time: its allow-listed commands run on the host at once; other commands are decided on lockhub (lox approve, the lea deck or a paired phone).",
}}
