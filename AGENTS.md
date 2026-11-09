# AGENTS.md

Directions for coding agents working in this repository. People should start with
[README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## What this is

Debuff is a single Go binary for macOS that scans one machine for known vulnerabilities and serves the
result as a web page on loopback. Standard library only. Read [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md)
before changing how a scan or the server behaves.

## Commands

```sh
just check          # every check, mid-work. Run it before you say a change is done
just gate           # the same, plus a clean tree. A release must pass it
just build          # dist/debuff
go test ./internal/server/...   # one package while iterating
just shots          # screenshots of every layout from sample data, into dist/shots/
```

Run a build without touching real data:

```sh
dist/debuff serve --demo --addr 127.0.0.1:0 --state-dir "$(mktemp -d)"
```

`serve` prints the address it bound. `debuff open --print --state-dir DIR --addr ADDR` prints a signed-in URL.

## Layout

| Path | What lives there |
|---|---|
| `cmd/debuff/` | The CLI. Thin: flags, wiring, output |
| `internal/collect/` | Finds what is installed. Only reads |
| `internal/resolve/` | Turns a product and version into findings: Chrome, Electron, NVD, the Homebrew catalog |
| `internal/fetch/` | The one HTTP client: pacing per host, retries, deadlines, the on-disk cache |
| `internal/scan/` | Runs one scan end to end and writes a snapshot |
| `internal/snapshot/`, `internal/state/` | On-disk formats, each with a format number |
| `internal/registry/` | `apps.json`, the shipped map from bundle ID to CVE source |
| `internal/server/` | The page, its template (`web/`), the buttons, the sample data |
| `internal/update/` | The only code that changes the machine |
| `internal/version/VERSION` | The one version source |
| `scripts/`, `justfile`, `launchd/` | Gate, build, deploy, rollback, screenshots |

## Rules

1. **Never put real machine data in the repository.** No findings, app inventories, host names, user names,
   home paths or tokens, in code, tests, fixtures, docs, commit messages or screenshots. Tests use invented
   apps (`Mail.app`, `Example Chat`) and invented CVE numbers (`CVE-0000-0001`). The data directory
   (`~/.local/state/debuff/` by default) is off limits: don't read from it, copy from it or screenshot it.
2. **Screenshots come from sample data only.** `just shots` and `scripts/tour.sh` serve `--demo` on a
   throwaway state directory. `just shot` captures a real console and writes outside the repository on
   purpose; never commit its output.
3. **Standard library only.** Don't add a module. If you believe one is needed, stop and ask.
4. **Read-only by default.** Collectors never run the things they inspect and never write outside the data
   directory. Anything that changes the machine belongs in `internal/update` and runs only from a button.
5. **A request names a row, never a command.** The server derives each action from its own scan. Don't add
   a handler that takes a path, a program or an argument from the request.
6. **Unknown is never clean.** A source that failed, a config that couldn't be parsed and an app with no
   CVE source must each be said on the page. Don't let an error become an empty list.
7. **Outside data is hostile.** Advisory text, bundle contents, config files and HTTP responses reach the
   page only through `html/template`. A new parser of outside data needs size bounds and a fuzz test.
8. **Agent config files hold secrets.** `internal/collect/agent.go` keeps names, package specs and remote
   host names, and nothing else. Don't widen what it reads.
9. **Loopback only, no JavaScript.** Don't relax the bind check, the Host and Origin checks or the
   Content-Security-Policy.
10. **Every outbound request goes through `internal/fetch`** and names one product and version, never a
    list of what is installed. A new host goes in the network table in `docs/HOW-IT-WORKS.md`.
11. **A persisted format change bumps its format number**, and an unknown format is refused, not guessed.

## Tests

- Table tests, `t.TempDir()` for any state, no network. The scan takes replaceable collectors
  (`scan.Options`) and the fetch client reads fixtures.
- A regression test counts once you have seen it fail without the fix.
- UI changes: run `just shots` and look at the images, dark and light, desktop and phone. The screenshot
  check fails on a console error, horizontal overflow or overlapping cards.
- A behavior only a browser shows (what `Origin` it sends, for example) needs `scripts/press.mjs`.

## Registry entries

You may draft an entry in `internal/registry/apps.json`, but leave `verified` unset unless
`debuff registry check` printed `ok` for it in this session. An unverified CPE is a guess, and the scan
ignores it by design.

## Releases

`just bump X.Y.Z`, add the `CHANGELOG.md` entry (a test fails without it), commit, then
`just release && just deploy`. Never join those with `;` or a pipe: a failed release must stop the deploy.
The changelog states what changed for a user, factually, first sentence first.

## Comments

Explain why, not what happened on a given day. No incident diaries, ticket numbers or names. The one dated
note allowed is the day an outside system's quirk was verified, since that can go stale.
