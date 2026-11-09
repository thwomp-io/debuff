# Changelog

All notable changes, [Keep a Changelog](https://keepachangelog.com/) style, SemVer.

## [Unreleased]

## [0.15.0] — 2026-11-09

### Added
- A README written for someone meeting Debuff for the first time, with screenshots and a recorded tour of the sample
  data; `docs/HOW-IT-WORKS.md` (a scan step by step, labels, ranking, every host a scan contacts and what it is told);
  `docs/CONFIGURATION.md` (`registry.json`, `exposure.json`, flags); `SECURITY.md`; `CONTRIBUTING.md`; and `AGENTS.md`
  for coding agents.
- `go install github.com/thwomp-io/debuff/cmd/debuff@latest` works: the module is named for where it lives.
- `scripts/tour.sh` records the README's GIF from `serve --demo`.
- An Apache-2.0 license.

### Changed
- The screenshot scripts take Playwright from `$PLAYWRIGHT_DIR` (see `scripts/playwright.sh`). Playwright still isn't
  a dependency of this repository.

## [0.14.0] — 2026-11-06

### Added
- **Update all** on the Updates page: one `brew upgrade --formula` of every Homebrew row, picked by the server from
  the scan. Homebrew locks each install, so this is one command it orders rather than several that would queue or
  collide. Every row it covers, and the button, say Updating… while it runs.

### Changed
- A press refused because an update is already running now says so on the page; before, it was silently dropped.
- The page rescans after any update attempt, a failed one included: a failure can still have changed things (a
  dependency, or the formulae before the one that failed). A failed Update all says the rescan shows which ones
  updated.

## [0.13.1] — 2026-11-04

### Fixed
- A button's outcome shows once. A refused press or "updated" otherwise stayed on the page until the next press.

## [0.13.0] — 2026-11-04

### Added
- An Updates page in the left menu lists only what has an update, the most urgent first, each with a button. An app
  with findings and no update isn't on it.
- A Homebrew formula's button runs `brew upgrade` and then rescans. This is the first thing in Debuff that changes the
  machine, and it only happens on a press. The server works out what a press does from the scan, and a request only
  names the row, so it can't choose a command or a path.
- Other buttons open where the update happens: the app itself, the App Store or Software Update. Casks aren't upgraded
  from here, since a cask's uninstall step can quit a running app before an install that then needs sudo.
- Scans now record outdated formulae (`brew outdated`) and what Software Update has found (`softwareupdate --no-scan`),
  adding about 3 seconds. A system component or formula with a card shows the update there too.
- The page names what it can't see: App Store apps, and apps Homebrew's catalog doesn't list.

## [0.12.0] — 2026-11-03

### Changed
- A card's findings are collapsed behind a disclosure arrow, showing how many there are. Opening it gives the same
  scrollable list as before. An app's own page still shows them outright.
- A calmer design. Facts sit in labeled rows, like Finder's Get Info, instead of running together on one line. Color
  now means something: red when known exploited, amber when there's something to do, and severity in a list is by
  weight rather than hue. A large title, a segmented severity control, and cards without borders.
- "Also on this machine" is split into what was checked and what has no CVE source, so that phrase is a heading
  instead of repeating on every row. A dot marks what's running.

## [0.11.0] — 2026-11-03

### Added
- A registry maps an app, by bundle ID, to its CVE source, its Homebrew cask and what it handles. It ships covering common
  Mac apps, so it says nothing about any one machine, and a private `registry.json` in the data directory adds to it. A
  CVE source counts only once verified, and `debuff registry check` confirms each one answers for an old version.
- Findings from NVD for apps in the registry, by product and version: Firefox, Safari, Chrome, LibreOffice and others. A
  new version is a new question, so an update shows at once; answers are otherwise cached for a day. NVD sees the
  product and version asked about. An entry with no version range is labeled Inferred, since it may not apply.
- Newest-version checks for apps whose cask names no app, such as Microsoft Office and Tailscale.

### Fixed
- A dropped connection is retried, and its error names only the host. The transport's own error held this machine's address.

## [0.10.0] — 2026-11-03

### Added
- Every app in the apps folders is on the page. Most have no findings to carry a card, so a list under the cards gives
  each one's icon, version, newest version and whether it's running, with updates first. "No CVE source" says nothing
  could check it, which isn't the same as clean.
- The agent stack: agent CLIs, MCP servers from each agent's config, and Claude plugins. Anything with a package and a
  version is checked against OSV, and an unpinned `npx` spec is named as such and resolved through npx's cache. Versions
  come from install paths, so nothing is run. These configs hold secrets, so only names, packages and a remote's host
  are ever read from them, and a config that can't be read is named on the page.

## [0.9.0] — 2026-11-03

### Added
- Each card carries the app's own icon, read from the bundle during a scan: the file `CFBundleIconFile` names, its best
  PNG, checked and kept by content hash in the private data directory. No list of apps, no outside tool, no network.
  Anything without an icon, such as a Homebrew formula, gets a plain letter. Icons the newest scan doesn't use are removed.

## [0.8.1] — 2026-11-03

### Fixed
- Cards with long lists overlapped the row below, a regression in 0.8.0. Two rows now fit the screen again.
- The screenshot check fails on overlapping cards, and `just shots` includes a sample at a real machine's size
  (`serve --demo`, `?sample=many`), since the short sample couldn't show this.

## [0.8.0] — 2026-11-03

### Added
- A daily scan at 06:00 under launchd, installed by `just deploy` and checked by `just status`. A failed scan, whoever
  started it, reaches the page; a scan older than 36 hours says it may be out of date. No notifications.
- Every scan prunes snapshots. It keeps the newest and the earliest of each run that found the same thing, so a machine
  that isn't changing stops accumulating files. The two newest states stay regardless of age; older ones go after 30
  days or past 30 states. A file it can't read is left alone.
- Logs past 1 MB move to `name.1` at the end of a scan, emptied in place because launchd holds them open.

### Changed
- The change line compares with the last scan that found something different, not simply the scan before, so a rescan
  or a daily scan that finds nothing new can't erase what changed. It says so: "No change since the scan at …".
- A card fits its findings, up to half the screen, and its link to all findings appears only when there are more.
- A card's list always shows its scrollbar, so it's clear there's more below the fold.

## [0.7.0] — 2026-11-03

### Added
- Each card says whether a newer version exists: `v1.43.0 available`, `latest`, or `Newest version unknown`, which never
  reads as up to date. It comes from Homebrew's shared catalog, one file every Homebrew user reads, so no vendor sees a
  request about this machine, and it covers apps that weren't installed through Homebrew. The catalog can lag a vendor,
  so an app ahead of it counts as current. An app listed by more than one cask, or at a version that can't be compared,
  stays unknown. A failed or stale catalog is named on the page.

## [0.6.0] — 2026-11-02

### Added
- A Rescan button. A press scans this machine and returns to the same page with the result, or, past 5 seconds, keeps
  scanning in the background while the page checks back every 3. One scan runs at a time, and a second press joins it.
  A failed scan keeps the earlier results on screen and says so. Only this page can start a scan: it takes the session
  cookie and this page's own Origin, and a foreign or missing Origin is refused. The page still runs no script.
- The page says what changed since the scan before, under the current view and severity setting: closed, new, the
  exploited count before and after, and apps removed. Each card shows its own part, including a version change.

### Changed
- `Referrer-Policy` is `same-origin`, not `no-referrer`, under which a browser sends `Origin: null` on the button's POST.
  Other sites still get nothing. `form-action` is `self`, was `none`.

## [0.5.0] — 2026-11-02

### Added
- `debuff scan --timing` says where the time went, per source: requests, failures, time paced, time on the network,
  the slowest single request and the data received. Durations and counts only, so it's safe to paste.

### Fixed
- A stalled connection can no longer hold a scan. Requests had no deadline, and one sat for 238 seconds of a
  262-second scan. Each now gets 30 seconds, reading included.
- Retries pause, 2 then 5 seconds, instead of meeting the same 503 again a second later, which left scans incomplete.
- A host that answers a server error or stalls gets a slower pace for the rest of the run, up to 8 seconds. Other hosts
  keep theirs. The pace is now per host, so servers no longer wait on each other. 403 and 429 still stop that host.

## [0.4.0] — 2026-11-02

### Changed
- The inbox is one card per app instead of a mail-style thread list, three across at most, so six apps fill the screen.
  A card shows the app and its version, what it handles, whether it's running, its runtime, how long it has trailed the
  fixes, and large counts for exploited, critical, high and top EPSS. Its findings are short rows in a list that scrolls
  inside the card, 100 at most, with a link to the app's page holding them all. Clicking a row opens its detail in place.
- The exploited count says how many are confirmed. Most are inferred from the bundled runtime's version: upper bounds.

### Added
- `debuff scan` records each app's own version, when Spotlight last saw it opened, and when its bundle last changed.
  A snapshot from an earlier version still loads, without them; run a scan to fill them in.

### Fixed
- Top EPSS no longer goes blank when an unscored finding follows a score of zero.
- On a phone, a row takes two lines so its title can be read, and cards no longer clip.
- The exploited number is legible in the light theme.
- The screenshot check also fails on sideways overflow inside the scrolling pane, which it couldn't see before.

## [0.3.2] — 2026-11-02

### Fixed
- A branch history that fails partway resumes from the failed page on the next scan, and apps on the same Chromium
  share it. Before, a flaky git server could leave one app's history incomplete every run, counting fixes as missing.

## [0.3.1] — 2026-11-02

### Added
- `http://debuff:8737` works with an /etc/hosts entry, and `debuff open` uses that name once it resolves.

### Fixed
- A thread's date is its newest finding, not its most urgent one's.
- The incomplete-scan banner names the host, not a long URL.

## [0.3.0] — 2026-11-02

### Added
- `debuff scan`: finds Electron apps, the Playwright browser cache and Homebrew advisories, resolves each against
  Chrome Releases, Electron's notes, OSV, CISA's known-exploited list and EPSS, and writes one gzipped snapshot
  to the private data directory. Bundled Chromium findings go through Electron's backport notes, the release
  branch's history and the engines' own branches before they're labeled Inferred. A failed source is
  named on the page; it never reads as no findings.
- `debuff open`, and a token on every page but `/healthz`, set as an HttpOnly, SameSite=Strict cookie.
- The inbox reads the newest scan without a restart. Long threads show their 25 most urgent rows and link to the
  rest. Findings in Chrome-only features, or that look like another project's, stay hidden unless All is on.
- A black and silver dark theme and a white, black and gray light theme. Color is left for what carries meaning:
  exploited, severity and warnings.
- An optional `exposure.json` in the data directory rates how much untrusted content each app handles. It's
  there and not in git because the list of apps is itself the inventory.

## [0.2.0] — 2026-11-02

### Added
- Threads: the inbox groups findings by app, one line of the worst facts (exploited count, worst severity, finding
  count, label mix, top EPSS), with the CVE rows inside. Most urgent first: known exploited, then exposure,
  EPSS, severity.
- A severity toggle (Critical, High+, Medium+, All), defaulting to High+. A known-exploited finding always
  shows, whatever its rating, and the page says how many findings the filter is hiding. An unrated finding
  counts as Medium.

## [0.1.1] — 2026-11-02

### Added
- The inbox shell: a left panel of views (Inbox, Known exploited, Confirmed) with counts, and a center panel of
  rows showing the critical facts at a glance, each expanding on click for the long text. It needs no
  JavaScript. A real server shows only the empty state, which says no scan has run.
- `debuff serve --demo`: made-up sample findings under a banner, to look at the layout.

## [0.1.0] — 2026-11-02

### Added
- The walking skeleton: `debuff serve` (one embedded page and `/healthz`, loopback only, with Host and
  Origin checks and a strict CSP), `debuff health`, `debuff version`, and a private state directory that
  `--state-dir` or `$DEBUFF_STATE_DIR` can point anywhere.
