# bangbang

A CLI that hunts down public proof-of-concept exploits for a product's CVEs, so you don't have to do it by hand.

## Why

Chasing down PoCs for a product's CVEs the manual way looks like this: search NVD for what's affected, then for *each* CVE, separately search GitHub, GitLab, Codeberg, and exploit-db for a working writeup or exploit. Even with shortcuts like DuckDuckGo's `!cve` and `!gh` bangs, that's still one search per CVE per source, in a browser, by hand. And a lot of what comes back is noise: abandoned forks, unrelated "list of 200 CVEs" aggregator repos, the odd typosquat.

`bangbang` automates that whole loop. Point it at a product name and it:

1. Finds the CVEs. Searches NVD for everything matching, sorted newest-first, each with its CVSS score and severity.
2. Finds the PoCs. Searches GitHub, GitLab, Codeberg, and exploit-db for every one of those CVEs, concurrently, and hands back one interactive list you can filter, read, and download from.

It also works the other way: give it a specific `CVE-YYYY-NNNNN` and it skips straight to step 2.

## How it works

```
$ bangbang CVE-2026-46368

1 CVE(s) Found!

Newest first: CVE-2026-46368(8.7)
hunting PoCs for CVE-2026-46368 on gh + glab + cb + edb...

[1] CVE-2026-46368  8.7  (2 shown)
  [ ] 1.1  gh  iwallplace/CVE-2026-46368-OpenWrt-Exploit  ★1  Proof of Concept exploit for CVE-2026-46368 -- authenticated root command injection in OpenWrt luci-app-https-dns-proxy
        forks:0  created:2026-01-16  https://github.com/iwallplace/CVE-2026-46368-OpenWrt-Exploit  (author: https://github.com/iwallplace)
  [ ] 1.2  edb  EDB-52521  ★0  OpenWrt 23.05 - Authenticated Remote Code Execution (RCE)
        forks:0  created:2026-04-29  https://www.exploit-db.com/exploits/52521
commands:
  list                    reprint the current listing
  expand <target...>      show the full readme for one or more hits (e.g. `expand 1` or `expand 1.2`)
  select <target...>      mark hits for download (`select 1` selects every hit under CVE 1)
  unselect <target...>    unmark hits
  dir [path]              show or set the download directory
  download                clone every selected hit into <dir>/<group>/...
  show-all                also show hits filtered out as CVE-list dumps
  hide-dumps              hide them again
  help                    this message
  quit                    exit

> expand 1.1
> select 1.1 1.2
> download
```

(a keyword search, e.g. `bangbang caddy`, looks the same but starts with a whole list of CVEs found for that product, each with its own colored score, before diving into per-CVE PoC hunting)

The CVE count and each score are colored by severity: bold red for critical/high, yellow for medium, blue for low. The worst findings jump out immediately.

## Prerequisites

bangbang itself has no runtime dependencies, but two things change what it can do:

- **[`gh`](https://cli.github.com/) and [`glab`](https://gitlab.com/gitlab-org/cli), already logged in.** Optional but recommended. If present and authenticated, bangbang uses them automatically for much higher GitHub/GitLab rate limits than unauthenticated requests get. Without them, it falls back to plain unauthenticated HTTP requests, which still works, just with tighter limits (a `GITHUB_TOKEN` / `GITLAB_TOKEN` env var gets you the same higher limit without the CLI). Codeberg has no CLI to detect, but a `CODEBERG_TOKEN` env var gets it the same kind of boost. Exploit-db needs no auth at all, ever. Run `bangbang --init` any time to set any of this up interactively.
- **`git`**, for actually downloading a selected GitHub, GitLab, or Codeberg hit. Exploit-db hits are plain file downloads and don't need it.

## Installing

Grab the binary for your platform from the [latest release](https://github.com/its-ryans-work/bangbang/releases/latest) and put it on your `PATH`. For example, on Linux (amd64):

```bash
curl -LO https://github.com/its-ryans-work/bangbang/releases/latest/download/bangbang-linux-amd64
chmod +x bangbang-linux-amd64
sudo mv bangbang-linux-amd64 /usr/local/bin/bangbang
```

Swap the filename for your platform:

| Platform | Filename |
|---|---|
| Linux (amd64) | `bangbang-linux-amd64` |
| Linux (arm64) | `bangbang-linux-arm64` |
| macOS (Apple Silicon) | `bangbang-macos-arm64` |
| Windows (x64) | `bangbang-windows-x64.exe` |

On macOS, use the same `curl` / `chmod +x` / `mv` steps as Linux. On Windows, download the `.exe` and either run it from wherever you saved it, or move it into a folder that's already on your `PATH`.

## Building

If you'd rather build from source, or your platform isn't covered by a release binary: requires [Zig 0.16.0](https://ziglang.org/download/) or newer, no other build-time dependencies.

```bash
cd bangbang
zig build
```

The binary lands at `zig-out/bin/bangbang`. Put it on your `PATH`, or run it in place:

```bash
./zig-out/bin/bangbang caddy
```

## First run

The first time you run a real search, bangbang offers a short setup wizard:

```
first run: set up GitHub/GitLab/Codeberg auth now to avoid rate limits? [Y/n]
```

It detects what you already have (an authenticated CLI, an env var, nothing), and for anything missing offers to install the CLI and log in, or paste a personal access token. Auto-install currently only works on macOS/Homebrew; on Linux or Windows you'll get a manual install link instead. exploit-db needs no auth at all, so it's never part of this flow.

Revisit it any time with `bangbang --init`, or skip it once and it won't ask again (until you run `--init` yourself).

## Usage

```
usage: bangbang [options] <keyword|CVE-ID>
       bangbang --init
       bangbang --delete-tokens

  --init             run the interactive auth setup wizard (also offered automatically
                     on first run) and exit
  --delete-tokens    delete any tokens bangbang has cached locally on this machine, and exit
                     (does NOT revoke them on GitHub/GitLab/Codeberg's side -- local disk only)
  --max-cves N       max CVEs to pivot on (default: unlimited -- every match NVD has,
                     capped only at 5000 as a backstop)
  --max-hits N       max repo hits fetched per CVE per host (default 5)
  --threshold N      hide repos mentioning >= N distinct CVEs as list-dumps (default 8)
  --show-all         don't hide anything, just flag it
  --dir PATH         download directory (default ./bangbang-downloads); can still be
                     changed later with the `dir` command inside the REPL
  --nvd-api-key KEY  NVD API key (raises the keyword-search rate limit); also read from NVD_API_KEY
  --sources LIST     comma-separated hosts to search: gh, glab, cb, edb
                     (or github/gitlab/codeberg/exploitdb; default: all four). Useful after a
                     run reports a host as rate-limited -- rerun with just the others, or just
                     the limited one(s) once it resets.
  -h, --help         this message
  -v, --version      print the version and exit
```

Examples:

```bash
bangbang confluence                       # keyword search, every matching CVE
bangbang CVE-2023-22515                   # one specific CVE
bangbang caddy --max-cves 5 --max-hits 10 # cap breadth/depth for a faster, smaller run
bangbang log4j --sources gh,glab          # skip codeberg and exploit-db this run
bangbang caddy --dir ~/pocs               # download to ~/pocs instead of ./bangbang-downloads
bangbang --init                           # (re)run the auth wizard
bangbang --delete-tokens                  # wipe locally-cached tokens
```

### Interactive commands

Once results are in, you're dropped into a prompt:

| Command | Effect |
|---|---|
| `list` | reprint the current listing |
| `expand <target...>` | show the full README (or exploit source, for exploit-db hits) |
| `select <target...>` | mark hits for download |
| `unselect <target...>` | unmark hits |
| `dir [path]` | show or set the download directory (`./bangbang-downloads` unless `--dir` was passed) |
| `download` | clone/download every selected hit into `<dir>/<CVE>/...` |
| `show-all` | also show hits filtered out as CVE-list dumps |
| `hide-dumps` | hide them again |
| `help` | this message |
| `quit` / `exit` | leave |

**Targets** are `N` (a whole CVE group) or `N.M` (one specific hit within it), space-separated and mixable: `select 1 2.3` selects every hit under CVE 1 plus just hit 3 of CVE 2.

If a keyword search comes back with CVEs but zero PoCs anywhere, you'll be offered a broader `"<keyword> CVE"` search across all sources as a fallback. If there's truly nothing to show (no CVEs, or CVEs but no PoCs even after the fallback), bangbang just says so and exits instead of dropping you into an empty menu.

## Sources

- **GitHub**, **GitLab**, **Codeberg**: live repository search per CVE, filtered for likely PoC repos.
- **exploit-db**: the [exploit-database](https://gitlab.com/exploit-database/exploitdb) CSV, cached locally at `~/.cache/bangbang/exploitdb.csv` (~10MB) and searched by CVE ID. Refreshed automatically once per UTC calendar day. The first run on a new day re-downloads it; every other run that same day reuses the cache instantly. Needs no auth or live API calls at all, so it's never rate-limited on the search itself.

All four are searched concurrently per CVE, but never more than one request at a time to any single host. GitHub's own API guidance warns that firing concurrent requests at one host can trip its abuse-detection layer even under the numeric rate limit, so bangbang only overlaps across hosts, not within one.

"CVE-dump" repos (ones that mention a huge number of unrelated CVEs, think aggregator/tracker repos, not real PoCs) are hidden by default once a repo crosses `--threshold` distinct CVE mentions. They're not discarded, just tucked away. `show-all` brings them back.

## Auth

Each host is resolved independently, in this order:

1. `GITHUB_TOKEN` / `GITLAB_TOKEN` / `CODEBERG_TOKEN` env var, if set.
2. A token saved locally by `--init` (or a prior browser login).
3. An authenticated `gh` / `glab` CLI.
4. Browser-based OAuth device flow, if `BANGBANG_GITHUB_CLIENT_ID` / `BANGBANG_GITLAB_CLIENT_ID` is set (opt-in, since bangbang can't register an OAuth App on your behalf).
5. No auth at all, which still works but with much tighter rate limits.

Tokens saved via `--init` live at `~/.cache/bangbang/<host>_token`, mode `0600`. `bangbang --delete-tokens` removes them. That's local disk only, and it does **not** revoke the token on GitHub/GitLab/Codeberg's side, so revoke it there too if that's what you actually want.

## Rate limits

If a host looks rate-limited during a run (checked against each API's actual documented signal, not guessed), you'll get a warning at the end naming which host(s), so you know the results might be incomplete:

```
warning: rate-limited by gh -- results from those host(s) may be incomplete. Use --sources to target specific hosts on a re-run.
```

Use `--sources` to re-run against just the unaffected hosts, or just the limited one(s) once the limit resets.

## Project layout

```
src/
  main.zig       CLI entry point: flag parsing, orchestration, summary/status output
  ui.zig         the interactive REPL (list/expand/select/download/...)
  nvd.zig        NVD keyword/CVE-ID search, CVSS extraction
  cve.zig        CVE ID parsing/sorting, severity types
  color.zig      ANSI colors + severity-to-color mapping, TTY-aware
  forge.zig      shared types (RepoHit, CveGroup, Host) used across all four sources
  github.zig     GitHub search + README fetch + clone
  gitlab.zig     GitLab search + README fetch + clone
  codeberg.zig   Codeberg search + README fetch + clone
  exploitdb.zig  exploit-db CSV cache/parse/search + raw exploit fetch
  filter.zig     CVE-dump repo detection
  download.zig   dispatches a selected hit to the right host's clone/download
  auth.zig       tiered auth resolution, token caching
  wizard.zig     first-run / --init interactive setup flow
  sysinfo.zig    OS + package manager detection
```

## Security note

This is a reconnaissance tool for defensive research, vulnerability triage, and authorized security testing. It finds out what's already public about a CVE; it doesn't exploit anything itself. Anything it downloads is exactly as trustworthy (or not) as a random GitHub repo, so read before you run.
