# Security

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (the repository's **Security** tab, *Report a
vulnerability*). Don't open a public issue for anything security-sensitive. This is a personal project, so
please allow reasonable time for a fix.

## What Debuff is trusted with

It reads what is installed on your machine and holds a list of what is unpatched. That list is the sensitive
thing, so the design keeps it local:

- **Loopback only.** `debuff serve` refuses to bind anything else.
- **A token on every page** but `/healthz`, kept in a file only you can read, sent as an HttpOnly,
  SameSite=Strict cookie.
- **Host and Origin checks**, because any website can make a browser call a localhost port.
- **No JavaScript** on the page, under a strict Content-Security-Policy.
- **Read-only until a button is pressed.** A press names a row; the server decides from its own scan what
  that row's action is. It can start a scan, run `brew upgrade --formula` for formulae the scan found
  outdated, or open an app or a system updater. Nothing else, and never with `sudo`.
- **No telemetry, no notifications, no account.** Outbound requests go only to the public sources listed in
  [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md), and name one product and version at a time.
- **Secrets in agent configs are never read.** See the same document.
- **No third-party code.** Go standard library only, so there is no dependency tree to audit.

Everything in the data directory (`~/.local/state/debuff/`) is private to your user. Don't commit it, sync
it or paste from it. `debuff scan` prints counts only, so its output is safe to share in a bug report.

## Release checks

A release must pass `just gate`: format, vet, lint (including gosec), race-enabled tests, fuzzing of every
parser of outside data, `govulncheck` and `osv-scanner` in their strict modes, a reproducible build, and a
smoke test that probes the built server from the attacker's side.
