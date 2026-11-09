# Configuration

Debuff runs with no configuration. Two optional files in the data directory (`~/.local/state/debuff/`)
teach it about your machine. They live there, and not in this repository, because a list of the apps on a
machine is itself an inventory.

## `registry.json`: where an app's CVEs live

The shipped registry ([`internal/registry/apps.json`](../internal/registry/apps.json)) maps common Mac apps,
by bundle ID, to an NVD product name and a Homebrew cask. Your own `registry.json` has the same shape, and
adds to it or overrides an entry with the same `id`.

```json
{
  "format": 1,
  "apps": [
    {
      "id": "com.example.editor",
      "name": "Example Editor",
      "cask": "example-editor",
      "cpe": "example:editor",
      "check": "1.0.0",
      "evidence": "https://example.com/security/advisories",
      "why": "Opens files from anywhere",
      "exposure": 2,
      "verified": "2026-01-15"
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `id` | The app's `CFBundleIdentifier`. Required. `mdls -name kMDItemCFBundleIdentifier /Applications/Some.app` prints it |
| `name` | What to call it |
| `cask` | Its Homebrew cask, for the newest-version check |
| `cpe` | NVD's `vendor:product` for it |
| `check` | An old version NVD should list CVEs for. `debuff registry check` asks about it |
| `evidence` | The vendor's advisories page, for a person to compare against |
| `why` | What the app handles, shown on its card |
| `exposure` | 1 to 3: how much untrusted content it handles |
| `verified` | The date `debuff registry check` last passed. **NVD is only asked once this is set** |
| `parts` | How many leading parts of a version to compare, for vendors whose build numbers don't match the catalog's |

An entry without `verified` still gives the app its cask, its description and its exposure. It just isn't
checked for CVEs, and the page says so. To verify one, run `debuff registry check` (it takes minutes: NVD is
slow for old versions) and set `verified` to today's date for each line that says `ok`.

Entries for widely used apps are welcome in the shipped list. See [CONTRIBUTING.md](../CONTRIBUTING.md).

## `exposure.json`: your own read of an app

Overrides the exposure rank and its reason for any app, keyed by the bundle's file name. This wins over the
registry.

```json
{
  "format": 1,
  "apps": {
    "Example Mail.app": {"rank": 3, "why": "Renders inbound email"},
    "Example Notes.app": {"rank": 1, "why": "Local notes only"}
  }
}
```

## Flags and environment

| Setting | Default | Meaning |
|---|---|---|
| `--state-dir`, `$DEBUFF_STATE_DIR` | `~/.local/state/debuff` | The data directory |
| `serve --addr` | `127.0.0.1:8737` | Where to listen. Loopback only |
| `serve --demo` | off | Made-up sample findings under a banner. Nothing is scanned or changed |

The install scripts (`just deploy`, `just status`, `just rollback`) take `DEBUFF_PREFIX`, `DEBUFF_LABEL`,
`DEBUFF_SCAN_LABEL`, `DEBUFF_ADDR`, `DEBUFF_STATE_DIR` and `DEBUFF_AGENTS_DIR`, so a second install can sit
beside the first without touching it.

## A friendlier address

`printf '127.0.0.1\tdebuff\n' | sudo tee -a /etc/hosts` lets you use <http://debuff:8737/>. Run `debuff open`
once afterwards: a sign-in belongs to one host name.
