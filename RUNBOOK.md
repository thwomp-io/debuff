# Debuff runbook

Everything here is a plain command. Run them from a clone of the repo.

## Is it OK?

```sh
just status
```

It checks that the binary is installed and a rollback is ready, the launchd unit is loaded, the running
process started from the installed binary, the server answers healthy on the installed version, and the data
directory is private. Exit 1 means something failed, and the failing line says what.

Open <http://127.0.0.1:8737/>.

## A friendlier address

`printf '127.0.0.1\tdebuff\n' | sudo tee -a /etc/hosts` lets you use <http://debuff:8737/>. Sign in with `debuff open`
once afterwards, since a sign-in belongs to one host name.

## Where things are

| What | Where |
|---|---|
| Binary | `~/.local/bin/debuff` |
| Previous binary (rollback) | `~/.local/bin/debuff.prev` |
| launchd unit | `~/Library/LaunchAgents/local.debuff.serve.plist` (rendered from `launchd/serve.plist.in`) |
| Daily scan | `~/Library/LaunchAgents/local.debuff.scan.plist`, 06:00 (a slot missed in sleep runs on wake; a powered-off one is skipped, and the page says when a scan is old); run it now: `launchctl kickstart gui/$(id -u)/local.debuff.scan` |
| Data and log | `~/.local/state/debuff/` (private, not in git, not in backups); logs: `serve.log`, `scan.log`; past 1 MB each moves to `.1` at the end of a scan |
| Icons | `icons/` in the data dir, named by content hash, read from each bundle during a scan. Which icons exist says which apps are installed, so they stay private too |
| Registry | `internal/registry/apps.json` (shipped, common apps) plus a private `registry.json` in the data dir, same shape. An entry's CVE source counts only once `verified` is set; `debuff registry check` confirms each source answers, and takes minutes because NVD is slow on old versions |
| Snapshots | Every scan prunes them: it keeps the newest and the earliest of each run that found the same thing. The two newest states stay regardless of age; older ones go after 30 days or past 30 states. A file it can't read is left alone |
| Listens on | `127.0.0.1:8737`, loopback only; the server refuses anything else |

## Ship a release

```sh
just bump 0.2.0          # sets internal/version/VERSION
$EDITOR CHANGELOG.md     # add the 0.2.0 entry; a test fails without it
git commit -am "release 0.2.0: what changed"
just release             # tags it and pushes; the pre-push hook runs the whole gate
just deploy              # build, install, restart, require a healthy answer
just status
```

If the gate fails, the push is blocked and the tag is removed. Fix forward and run `just release` again. Don't
use `git push --no-verify` unless you can write down why.

Run `just deploy` only after `just release` succeeded (`just release && just deploy`).

## Roll back

`just deploy` already rolls back on its own if the new version doesn't answer healthy.

By hand:

```sh
just rollback    # swaps in the previous binary and checks it answers; running it again goes forward
just status
```

## When something's wrong

| Symptom | First move |
|---|---|
| `no healthy answer` | `tail ~/.local/state/debuff/serve.log`, then `launchctl print gui/$(id -u)/local.debuff.serve` |
| The log says `has format N; this binary reads format M` | The data is newer than this binary. Deploy a newer binary; don't edit the file |
| `pid … is running …, not …` | The binary was replaced but the old one is still serving: `launchctl kickstart -k gui/$(id -u)/local.debuff.serve` |
| `serving X but Y is installed` | Same restart |
| `address already in use` | `lsof -nP -iTCP:8737 -sTCP:LISTEN` to see who holds the port |
| Gate fails at `toolchain matches go.mod` | Homebrew moved Go. Update the `go` line in `go.mod` in its own commit |
| Gate fails at `vulnerability scan` | Update the dependency, or Go for a standard-library advisory. It's strict on purpose: "not called" doesn't pass |
| Remove it completely | `launchctl bootout gui/$(id -u)/local.debuff.serve` and `…/local.debuff.scan`, then delete both plists, both binaries and the data directory |

## Try something without touching real data

```sh
debuff serve --addr 127.0.0.1:0 --state-dir "$(mktemp -d)"
```

Every script takes the same overrides (`DEBUFF_PREFIX`, `DEBUFF_LABEL`, `DEBUFF_ADDR`, `DEBUFF_STATE_DIR`,
`DEBUFF_AGENTS_DIR`).

## Prove the machinery still works

```sh
just prove-gate      # each fault in a throwaway worktree must stop the gate, at the right step
just prove-deploy    # install, upgrade, bad builds, rollback on a throwaway install
just shot            # a headless screenshot of the running console to dist/shot.png
just shots           # every layout, on labeled sample data and throwaway state, into dist/shots/
scripts/tour.sh      # re-record the README's GIF from the same sample data
```

Run the first two after changing `scripts/`, or after a tool like `govulncheck` or `golangci-lint` moves. The
screenshot commands need Playwright: see `scripts/playwright.sh`.

## Fresh clone

```sh
git config core.hooksPath .githooks    # without this, the gate doesn't fire on push
brew install go golangci-lint govulncheck osv-scanner just
```

`GOTOOLCHAIN=local` keeps a `go.mod` from downloading a compiler, and telemetry stays off: `go env -w GOTOOLCHAIN=local` and `go telemetry off`.
