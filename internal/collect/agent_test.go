package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secret = "sk-super-secret-value"

func TestParseMCPKeepsNamesAndPackagesAndNeverASecret(t *testing.T) {
	cfg := `{
		"mcpServers": {
			"pinned": {"command": "npx", "args": ["-y", "@scope/tool@1.2.3", "--api-key", "` + secret + `"], "env": {"TOKEN": "` + secret + `"}},
			"moving": {"command": "/opt/homebrew/bin/npx", "args": ["@scope/moving@latest"]},
			"bare":   {"command": "npx", "args": ["bare-tool"]},
			"python": {"command": "uvx", "args": ["py-tool==1.0"]},
			"flag":   {"command": "npx", "args": ["--token", "` + secret + `", "tool"]},
			"local":  {"command": "/usr/local/bin/thing", "args": ["` + secret + `"]},
			"remote": {"type": "http", "url": "https://user:` + secret + `@mcp.example/v1?key=` + secret + `", "headers": {"Authorization": "` + secret + `"}}
		},
		"projects": {"/some/repo": {"mcpServers": {"nested": {"command": "npx", "args": ["nested@2.0.0"]}}}},
		"mcp": {"opencode": {"type": "local", "command": ["npx", "-y", "oc@3.0.0"], "environment": {"K": "` + secret + `"}}},
		"unrelated": {"servers": {"web": {"port": 80}}}
	}`
	got, err := ParseMCP([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	dump, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(dump), secret) {
		t.Fatalf("a secret left the parser: %s", dump)
	}
	by := map[string]AgentTool{}
	for _, s := range got {
		by[s.Name] = s
	}
	if len(by) != 9 {
		t.Fatalf("%d: %s", len(by), dump)
	}
	if s := by["MCP: pinned"]; s.Pkg != "@scope/tool" || s.Version != "1.2.3" || s.Unpinned || s.Ecosystem != "npm" {
		t.Errorf("%+v", s)
	}
	if s := by["MCP: moving"]; s.Pkg != "@scope/moving" || s.Version != "" || !s.Unpinned {
		t.Errorf("%+v", s)
	}
	if s := by["MCP: bare"]; s.Pkg != "bare-tool" || !s.Unpinned {
		t.Errorf("%+v", s)
	}
	if s := by["MCP: flag"]; s.Pkg != "" {
		t.Errorf("a flag's value could be a secret, so no guessing: %+v", s)
	}
	if s := by["MCP: local"]; s.Pkg != "" || s.Ecosystem != "" {
		t.Errorf("%+v", s)
	}
	if s := by["MCP: remote"]; s.Host != "mcp.example" {
		t.Errorf("%+v", s)
	}
	if s := by["MCP: nested"]; s.Version != "2.0.0" {
		t.Errorf("%+v", s)
	}
	if s := by["MCP: opencode"]; s.Pkg != "oc" || s.Version != "3.0.0" {
		t.Errorf("%+v", s)
	}
}

func TestAPackageNameCantBeAPath(t *testing.T) {
	for _, spec := range []string{"..", "../x", "@../x", "@a/../x", ".hidden", "/etc/passwd", "x/y", "https://evil.example/x"} {
		got := runnerPackage([]string{spec})
		if got != "" {
			t.Errorf("%q was taken as a package", spec)
		}
	}
	for _, spec := range []string{"tool", "tool@1.0.0", "@scope/tool", "@scope/tool@latest", "my.tool_2"} {
		if runnerPackage([]string{spec}) != spec {
			t.Errorf("%q should be a package", spec)
		}
	}
}

func TestAgentToolsReadsVersionsWithoutRunningAnything(t *testing.T) {
	home := t.TempDir()
	versioned := filepath.Join(home, ".local/share/claude/versions/2.1.317")
	if err := os.MkdirAll(filepath.Dir(versioned), 0o700); err != nil {
		t.Fatal(err)
	}
	// Would fail the test's output if it ever ran: it isn't even executable.
	if err := os.WriteFile(versioned, []byte("not a program"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".local/bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(versioned, filepath.Join(home, ".local/bin/claude")); err != nil {
		t.Fatal(err)
	}
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".mcp.json", `{"mcpServers":{"a":{"command":"npx","args":["cached-tool"]}}}`)
	write(".cursor/mcp.json", `{"mcpServers":{"a":{"command":"npx","args":["cached-tool"]}}}`)
	write(".npm/_npx/abc/node_modules/cached-tool/package.json", `{"version":"4.5.6"}`)
	write(".gemini/settings.json", `not json`)
	write(".codex/config.toml", `[mcp_servers.x]`)
	write(".claude/plugins/installed_plugins.json", `{"plugins":{"design@market":[{"version":"1.1.1"}]}}`)
	tools, notes := AgentTools(home)
	by := map[string]AgentTool{}
	for _, tool := range tools {
		by[tool.Name] = tool
	}
	if c := by["Claude Code"]; c.Version != "2.1.317" || c.Pkg != "@anthropic-ai/claude-code" {
		t.Errorf("%+v", c)
	}
	if a := by["MCP: a"]; a.Version != "4.5.6" || !a.Unpinned {
		t.Errorf("an unpinned spec should resolve through npx's cache: %+v", a)
	}
	if p := by["Plugin: design"]; p.Version != "1.1.1" {
		t.Errorf("%+v", p)
	}
	count := 0
	for _, tool := range tools {
		if tool.Name == "MCP: a" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("one server in two configs should list once, got %d", count)
	}
	joined := strings.Join(notes, " ")
	if !strings.Contains(joined, ".gemini/settings.json") || !strings.Contains(joined, ".codex/config.toml") {
		t.Errorf("what wasn't read must be said: %q", joined)
	}
}

func FuzzParseMCP(f *testing.F) {
	f.Add([]byte(`{"mcpServers":{"a":{"command":"npx","args":["x@1.0.0"]}}}`))
	f.Add([]byte(`{"mcp":{"a":{"command":["npx"],"url":7}}}`))
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = ParseMCP(b) })
}
