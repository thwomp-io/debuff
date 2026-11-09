# How Debuff works

## A scan, step by step

`debuff scan` (also the daily launchd job and the page's Rescan button) does this, in order:

1. **Finds bundled runtimes.** It walks `/Applications` and `~/Applications` for app bundles carrying an
   Electron framework, and reads the Playwright browser cache. For each it reads the Electron and Chromium
   versions from the bundle. Nothing is launched.
2. **Resolves bundled Chromium.** An Electron app ships its own copy of Chromium, patched on Electron's
   schedule, not Chrome's. Debuff reads Chrome's release notes for CVEs, then looks for evidence each fix
   reached this app's line: Electron's backport notes, the release branch's history, and the engines' own
   branches (V8, Skia, ANGLE, Dawn, PDFium, WebRTC). What is left is labeled **Inferred**.
3. **Asks OSV** about the Electron version itself, about Homebrew formulae (through `brew vulns`), and about
   agent tools that have a package and a version.
4. **Lists every other app** in the apps folders. An app with a verified entry in the registry is checked
   against NVD by product and version. The rest are listed as having no CVE source.
5. **Reads the agent stack**: agent CLIs on disk, MCP servers named in agent config files, and plugins. See
   below for what is read from those files.
6. **Checks for updates**: `brew outdated`, the result of Software Update's own background check, and
   Homebrew's cask catalog for app versions.
7. **Marks and scores** findings against CISA's Known Exploited Vulnerabilities list and EPSS.
8. **Writes one gzipped snapshot** to the data directory, prunes old snapshots and unused icons, and trims
   the logs.

A source that fails makes the scan weaker, not wrong. It is recorded in the snapshot and named in a banner
on the page. It never reads as "no findings".

## Labels

| Label | Meaning |
|---|---|
| Confirmed | An advisory lists this exact version as affected |
| Inferred | The version is older than the fix, and no sign of the fix was found. An upper bound |
| Doubtful | The advisory seems to describe another project. Hidden unless the severity control is on All |

A card's exploited count says how many are confirmed, because most bundled-runtime findings are inferred.

## Ranking

Cards are ordered by: any known-exploited finding, then the app's exposure (how much untrusted content it
handles, 1 to 3), then its top EPSS score, then its count of Critical findings. Rows inside a card are
ordered by known exploited, severity, then EPSS. An unrated finding counts as Medium.

## What is read from agent configs

Agent config files often hold secrets in `env` blocks, headers, arguments and URLs. The parser keeps only a
server's name, the package a runner (`npx`, `uvx`, `pipx` and similar) would fetch, and a remote server's
host name. It never keeps a URL's path or query, an `env` block or any other argument. If the first argument
after the runner's known flags isn't plainly a package name, it gives up on that server instead of guessing.
Versions are read from install paths and npx's cache. No agent tool is ever run.

A config that can't be parsed is named on the page as a gap in coverage.

## Network

| Host | Why | What the request names |
|---|---|---|
| chromereleases.googleblog.com | Chrome's security release notes | Nothing about this machine |
| chromium.googlesource.com and the engine hosts | Branch histories | A Chromium version or branch |
| releases.electronjs.org | Electron's release list and notes | An Electron version |
| api.osv.dev | Advisories | One package and version per request |
| services.nvd.nist.gov | CVEs by product | One product and version per request |
| www.cisa.gov | The known-exploited list | Nothing about this machine |
| api.first.org | EPSS scores | CVE identifiers |
| formulae.brew.sh | Homebrew's cask catalog | Nothing about this machine |

Requests are paced per host, at least a second apart, slower after a server error, and stop for that host
on a 403 or 429. Answers are cached in the data directory, most for a day. `debuff scan --timing` prints
where the time went, as counts and durations only.

## The server

Any website can make a browser call a port on localhost, so listening on loopback isn't a boundary by
itself. The server adds:

- **A token.** Every page but `/healthz` needs it. `debuff open` passes it once and the server sets an
  HttpOnly, SameSite=Strict cookie. The token is a file in the data directory, mode 0600.
- **A Host check**, which stops DNS rebinding, and **an Origin check** on anything a browser sends
  cross-site.
- **A strict Content-Security-Policy.** The page runs no JavaScript at all.
- **Buttons that name a row, never a command.** A press says "update this row". The server works out from
  the newest scan what that means, so a forged request can't choose a program, an argument or a path.

The only things a button can do: start a scan, run `brew upgrade --formula` on formulae the scan found
outdated, or `open` an app bundle, Software Update or the App Store's updates page.

## The data directory

`~/.local/state/debuff/`, mode 0700. Override with `--state-dir` or `$DEBUFF_STATE_DIR`.

| File | What it is |
|---|---|
| `token` | The sign-in secret |
| `snapshots/` | One gzipped file per scan, pruned to the scans that found something different |
| `icons/` | App icons by content hash. Which icons exist says which apps are installed |
| `cache/` | Cached answers from the sources above |
| `state.json`, `last-scan.json` | When the server last started, and how the last scan went |
| `serve.log`, `scan.log` | Logs when run under launchd, capped at 1 MB each |
| `registry.json`, `exposure.json` | Optional, yours. See [CONFIGURATION.md](CONFIGURATION.md) |

Every JSON file carries a format number. A binary refuses a format it doesn't know instead of guessing, so
rolling back to an older binary can't quietly damage newer data.
