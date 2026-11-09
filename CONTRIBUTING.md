# Contributing

Thanks for looking. Issues and pull requests are welcome.

## Set up

```sh
brew install go just golangci-lint govulncheck osv-scanner
git config core.hooksPath .githooks
just check
```

`just check` runs every check the release gate runs except the clean-tree one. If it fails at
`toolchain matches go.mod`, your Go is a different patch version from the one pinned: the tests still run
with `go test -race ./...`.

## Ground rules

- **Standard library only.** A new module needs a strong reason.
- **Read-only by default.** Anything that changes the machine goes through `internal/update`, from a button.
- **Never real data.** No findings, inventories, host names or screenshots from a real machine, in code,
  tests, issues or pull requests. Tests use made-up apps; screenshots come from `just shots`, which serves
  the sample data.
- **Unknown is never clean.** If something couldn't be checked, the page has to say so.
- **A parser of outside data gets a fuzz test.**

## Adding an app to the registry

The most useful small contribution. Add an entry to `internal/registry/apps.json` (fields are described in
[docs/CONFIGURATION.md](docs/CONFIGURATION.md)), run `debuff registry check`, and set `verified` only if the
entry's line says `ok`. Include the `evidence` link so a reviewer can compare.

## Screenshots

`just shots` and `scripts/tour.sh` need Playwright, which isn't a dependency of this repository. See
`scripts/playwright.sh`.
