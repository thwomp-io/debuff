package collect

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Agent tool kinds.
const (
	AgentCLI    = "agent cli"
	AgentMCP    = "mcp server"
	AgentPlugin = "agent plugin"
)

// AgentTool is one thing an AI agent on this machine can run. It carries names and versions only. The configs
// it comes from hold secrets, in env blocks and sometimes in arguments or URLs, so those never leave the parser.
type AgentTool struct {
	Name, Kind     string
	Version        string
	Ecosystem, Pkg string // what to ask an advisory database about; empty when it can't be known
	Host           string // a remote server's host
	Unpinned       bool   // runs whatever is newest each time it starts
}

var (
	pathVersion = regexp.MustCompile(`\d+\.\d+\.\d+`)
	exactPin    = regexp.MustCompile(`^\d+\.\d+\.\d+`)
	packageSpec = regexp.MustCompile(`^(@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*(@[A-Za-z0-9.^~*_-]+)?$`)
)

// The agent CLIs with a package to ask about.
var agentCLIs = []struct{ name, bin, pkg string }{
	{"Claude Code", "claude", "@anthropic-ai/claude-code"},
	{"OpenCode", "opencode", "opencode-ai"},
	{"Codex", "codex", "@openai/codex"},
	{"Gemini CLI", "gemini", "@google/gemini-cli"},
}

// Where agents keep MCP configs, relative to home. ~/.codex/config.toml is TOML, which the standard library can't
// read, so it's named as not read rather than quietly skipped.
var mcpConfigs = []string{
	".claude.json", ".mcp.json", ".claude/settings.json",
	"Library/Application Support/Claude/claude_desktop_config.json",
	".cursor/mcp.json", ".codeium/windsurf/mcp_config.json",
	"Library/Application Support/Code/User/mcp.json", "Library/Application Support/Code/User/settings.json",
	".config/opencode/opencode.json", ".config/opencode/config.json", ".gemini/settings.json",
}

const maxConfig = 128 << 20

// cliVersion reads a CLI's version from where it's installed, without running it: installers put it in the path.
func cliVersion(path string) string {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ""
	}
	found := pathVersion.FindAllString(real, -1)
	if len(found) == 0 {
		return ""
	}
	return found[len(found)-1]
}

// AgentTools lists what agents here can run. It reports files it couldn't parse as notes: a config it can't read
// is a gap in coverage, not nothing to find.
func AgentTools(home string) ([]AgentTool, []string) {
	var out, servers []AgentTool
	var notes []string
	for _, c := range agentCLIs {
		for _, dir := range []string{filepath.Join(home, ".local/bin"), "/opt/homebrew/bin", "/usr/local/bin"} {
			p := filepath.Join(dir, c.bin)
			if _, err := os.Stat(p); err == nil {
				out = append(out, AgentTool{Name: c.name, Kind: AgentCLI, Version: cliVersion(p), Ecosystem: "npm", Pkg: c.pkg})
				break
			}
		}
	}
	for _, rel := range mcpConfigs {
		p := filepath.Join(home, rel)
		fi, err := os.Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || fi.Size() > maxConfig {
			notes = append(notes, rel+" wasn't read")
			continue
		}
		b, err := os.ReadFile(p) // #nosec G304 -- a fixed path under the user's home
		if err != nil {
			notes = append(notes, rel+" wasn't read")
			continue
		}
		found, err := ParseMCP(b)
		if err != nil {
			notes = append(notes, rel+" wasn't readable")
			continue
		}
		servers = append(servers, found...)
	}
	if _, err := os.Stat(filepath.Join(home, ".codex/config.toml")); err == nil {
		notes = append(notes, ".codex/config.toml wasn't read: MCP servers there aren't listed")
	}
	slices.SortFunc(servers, func(a, b AgentTool) int { return strings.Compare(a.Name+a.Pkg+a.Host, b.Name+b.Pkg+b.Host) })
	servers = slices.CompactFunc(servers, func(a, b AgentTool) bool {
		return a.Name == b.Name && a.Pkg == b.Pkg && a.Host == b.Host && a.Version == b.Version
	})
	for i := range servers {
		if s := &servers[i]; s.Version == "" && s.Ecosystem == "npm" {
			s.Version = npxCached(home, s.Pkg)
		}
	}
	out = append(out, servers...)
	return append(out, claudePlugins(home)...), notes
}

// npxCached is the newest version of a package in npx's cache: what an unpinned spec most recently ran.
func npxCached(home, pkg string) string {
	names, err := filepath.Glob(filepath.Join(home, ".npm/_npx/*/node_modules", filepath.FromSlash(pkg), "package.json"))
	if err != nil {
		return ""
	}
	newest := ""
	for _, n := range names {
		b, err := os.ReadFile(n) // #nosec G304 G703 -- npx's own cache; packageSpec keeps a name from climbing out of it
		if err != nil {
			continue
		}
		var p struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(b, &p) == nil && p.Version > newest {
			newest = p.Version
		}
	}
	return newest
}

func claudePlugins(home string) []AgentTool {
	b, err := os.ReadFile(filepath.Join(home, ".claude/plugins/installed_plugins.json")) // #nosec G304 -- a fixed path under home
	if err != nil {
		return nil
	}
	var f struct {
		Plugins map[string][]struct {
			Version string `json:"version"`
		} `json:"plugins"`
	}
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	var out []AgentTool
	for id, installs := range f.Plugins {
		name, _, _ := strings.Cut(id, "@")
		t := AgentTool{Name: "Plugin: " + name, Kind: AgentPlugin}
		if len(installs) > 0 {
			t.Version = installs[0].Version
		}
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b AgentTool) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// ParseMCP finds MCP servers anywhere in a config: agents nest them per project, and under different keys. It
// keeps a server's name, its package and a remote's host. Env blocks, headers and other arguments are never read.
func ParseMCP(b []byte) ([]AgentTool, error) {
	var root any
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, err
	}
	var out []AgentTool
	walkMCP(root, 0, &out)
	return out, nil
}

func walkMCP(v any, depth int, out *[]AgentTool) {
	if depth > 8 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if m, ok := child.(map[string]any); ok && (k == "mcpServers" || k == "mcp_servers" || k == "mcp" || k == "servers") {
				for name, s := range m {
					if server, ok := s.(map[string]any); ok && looksLikeServer(server) {
						*out = append(*out, parseServer(name, server))
					} else {
						walkMCP(s, depth+1, out)
					}
				}
				continue
			}
			walkMCP(child, depth+1, out)
		}
	case []any:
		for _, child := range t {
			walkMCP(child, depth+1, out)
		}
	}
}

func looksLikeServer(s map[string]any) bool {
	_, command := s["command"]
	_, u := s["url"]
	return command || u
}

func stringList(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func parseServer(name string, s map[string]any) AgentTool {
	t := AgentTool{Name: "MCP: " + name, Kind: AgentMCP}
	if raw, ok := s["url"].(string); ok {
		if u, err := url.Parse(raw); err == nil {
			t.Host = u.Hostname() // never the path or query, which can hold a key
		}
		return t
	}
	var argv []string
	switch c := s["command"].(type) {
	case string:
		argv = append([]string{c}, stringList(s["args"])...)
	case []any: // some agents put the whole command line here
		argv = stringList(c)
	}
	if len(argv) == 0 {
		return t
	}
	ecosystem := map[string]string{"npx": "npm", "pnpx": "npm", "bunx": "npm", "uvx": "PyPI", "pipx": "PyPI"}[filepath.Base(argv[0])]
	if ecosystem == "" {
		return t
	}
	spec := runnerPackage(argv[1:])
	if spec == "" {
		return t
	}
	t.Ecosystem = ecosystem
	t.Pkg, t.Version = splitSpec(spec)
	if !exactPin.MatchString(t.Version) {
		t.Version, t.Unpinned = "", true
	}
	return t
}

// runnerPackage is the package a runner will fetch: the first argument, past the few flags known to take no value.
// Any other flag might be followed by a value, even a secret, so then it gives up rather than guess.
func runnerPackage(args []string) string {
	for _, a := range args {
		switch a {
		case "-y", "--yes", "-q", "--quiet", "--silent", "--bun", "run":
			continue
		}
		if strings.HasPrefix(a, "-") || !packageSpec.MatchString(a) {
			return ""
		}
		return a
	}
	return ""
}

func splitSpec(spec string) (name, version string) {
	at := strings.LastIndex(spec, "@")
	if at <= 0 {
		return spec, ""
	}
	return spec[:at], spec[at+1:]
}
