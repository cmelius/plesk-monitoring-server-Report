# README changes for 2.0 (branch README)

**This file belongs to the branch `feature/plugin-system`.** It collects everything in [README.md](README.md) that has to change for version 2.0, so nothing is forgotten – and nothing else: the 1.x texts stay in `README.md`, which this branch does not edit, so merging `main` into the branch causes no conflict there. When 2.0 is released, each part below goes into `README.md` at the place it names and this file is removed. What changed in the code is listed in [CHANGELOG-2.0.md](CHANGELOG-2.0.md), the design in [docs/plugin-concept.md](docs/plugin-concept.md).

Parts marked **(planned)** describe something the branch has not built yet; check them against the code before the release.

---

## Introduction: "A single bash script"

**Where:** the first sentence of the README. "A single bash script that writes …" → "A bash script with a few plugin files that writes …" (or similar).

## Why plugins (new section)

**Where:** a new section right after the introduction, before *Quick start*, with a link in *Contents*. Text:

> ### Why plugins
>
> Since 2.0, the checks that depend on specific software – Plesk's own log, Plesk backups, Roundcube, PHP settings in `.htaccess`, `.user.ini` and `php.ini` – are plugins: small files in `plugins/`, shipped with each release. The rest of the script does what is the same on every server.
>
> - **Only checked plugins run.** The script holds a SHA-256 checksum of every plugin file of its release. A file that is missing, changed or not on that list does not run, and the report says so. The file must also belong to root and be writable by nobody else. There is no folder for plugins of your own or from third parties: every plugin is reviewed like the script and released with it.
> - **Clear limits.** A plugin answers only with report lines, notes, alerts and its own state. It can't touch the alerts of other checks, the status line or the state files, and it sees only the settings it needs – not the upload target or the mail settings, for example.
> - **A failure costs one section, not the run.** A plugin that fails or hangs is stopped at its time limit and reported; the other checks run as usual.
> - **Software-specific parts in one place.** Support for another CMS or mail setup (see [Using another CMS?](#using-another-cms-help-wanted)) has a clear home: a new plugin.
> - **Each plugin can be switched off** with `PLUGINS_OFF`.
> - **Each plugin is tested on its own**, and the automatic checks make sure no plugin contains network or changing commands. When a check became a plugin, a test showed that it reports exactly what it reported before.
>
> What it costs:
>
> - **More than one file.** Installation and updates use a release archive with checksums instead of a single `curl` command, see [Installation](#installation).
> - **More parts that must fit together.** A partial update – the script of one release, a plugin of another – is not run silently: every check whose file is missing or differs raises an alert.
> - **No protection against root.** Whoever can change root's files could change the script as well. The checksums guard against half-finished updates, mixed versions and files slipped into the folder – not against an attacker who is already root. Plugins run as root like the script, without a sandbox.
> - **A little more run time:** each plugin is a process of its own.

## Quick start, Installation, Updates: install from the release archive (planned)

**Where:** the code blocks in *Quick start*, *Installation* and *Updates*; the sentence about `curl` in *Requirements*.

The script is no longer a single file: `lib/` and `plugins/` must lie next to it. A release is a `tar.gz` archive with a `SHA256SUMS` file; it is unpacked as root into `/usr/local/lib/plesk-server-report/`, with a link in `/usr/local/sbin`, so the cron entry stays valid. Draft:

```bash
cd /root
curl -fsSLO https://github.com/cmelius/plesk-monitoring-server-Report/releases/latest/download/plesk-server-report.tar.gz
curl -fsSLO https://github.com/cmelius/plesk-monitoring-server-Report/releases/latest/download/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
mkdir -p /usr/local/lib/plesk-server-report
tar -xzf plesk-server-report.tar.gz -C /usr/local/lib/plesk-server-report --no-same-owner
ln -sf /usr/local/lib/plesk-server-report/plesk-server-report.sh /usr/local/sbin/plesk-server-report.sh
/usr/local/sbin/plesk-server-report.sh --no-upload        # test run: prints the report
```

To write next to it:

- `--no-same-owner`: the files must belong to root. The script runs only files that belong to root and that nobody else may write, in folders of the same kind; otherwise the check is not run and the report says why.
- **Updating from 1.x:** unpack the archive as above; the link replaces the old single file in `/usr/local/sbin`. Settings and state are kept. The old file must not stay a regular file at that path (`ln -sf` replaces it).
- **An incomplete installation** (only the script, `plugins/` missing, or a file of another version) is reported: every check whose file is missing or differs raises an alert "the check … was not run", naming the reason, and `--verify` lists every file that differs. The script never downloads plugins or itself on its own.
- *Releases or `main`?*: following `main` means a `git clone` (or the archive of the branch) instead of the raw URL of one file.
- **Updating 2.x → newer** (the *Updates* section): one command –

  ```bash
  plesk-server-report.sh --self-update        # shows the changes and asks; --yes: no question
  plesk-server-report.sh --self-update --rollback   # back to the previous version
  ```

  Text: It runs only when you start it as root – never from cron, the script never updates itself. It downloads the archive of the latest release with `SHA256SUMS` and the signature `SHA256SUMS.sig`, checks the **signature** with the maintainer's public key built into the script – so a release swapped on GitHub would be refused, not only a broken download –, checks the checksum, unpacks next to the installation, lets the new version test itself (`--verify`), shows the changes since your version and asks. Only then it swaps the folders; the previous version stays in `/usr/local/lib/plesk-server-report.old`. Signature checks need OpenSSH 8.1 or newer (Debian 11+, Ubuntu 20.04+, RHEL 9); on RHEL 8 it says so and asks before going on with the checksum only. It replaces only an installation from the release archive – a git checkout is updated with `git pull`.
- `--verify` (options list): checks that `lib/` and `plugins/` are the files of this release.
- *Check it before you run it as root* → "Expect it to point out": "It deletes files only in its own folder …" gets the exception: `--self-update`, run by hand, replaces the folder `/usr/local/lib/plesk-server-report` (keeping the previous one as `.old`). Same for *Security* ("It writes only to `/var/lib/plesk-server-report` …") and the network list (`--self-update` downloads from GitHub). "Nothing about your server is sent; the script never updates itself" → "… never updates itself on its own".
- **(planned) for the maintainer, not the README:** the release steps – `tools/build-release.sh`, sign `SHA256SUMS` with `ssh-keygen -Y sign -n plesk-server-report`, upload archive, `SHA256SUMS`, `SHA256SUMS.sig`; the public key goes into `RELEASE_KEY` before 2.0.

## Check it before you run it as root

**Where:** the first paragraph and the prompt.

- The review now covers several files: the script, `lib/plugin-lib.sh` and every file in `plugins/`. Attach all of them (or the archive) – the review prompt names them.
- Line count: "more than 3,000 lines of bash" → the current figure, script and plugins.
- New point for the list "Expect it to point out a few things that are by design":
  > **It runs the files in `plugins/` with bash** – each in a process of its own, with an empty environment, as root like the script. Only files of the release run: the script holds a SHA-256 checksum of each one and refuses a file that differs, is not in the list, or could be changed by someone other than root. A plugin gets the new log lines on stdin and answers with lines the script checks (`TEXT`, `NOTE`, `ALERT`, `STATE`); it can't touch the alerts of other checks or the state files. A plugin is core code in a separate file, reviewed like the script – there are no third-party plugins.
- *Every push is also checked automatically*: ShellCheck covers `lib/`, `plugins/` and `tools/` too; the tests check the checksums, the plugin header and that plugins contain no network or changing commands.

## What the report covers / Example report

**Where:** *Once a day*, the example report, the example summary.

- The daily paragraph of `webshell` covers PHP files only: heading *Suspicious code in recently changed PHP files (typical webshell/backdoor patterns):*. The settings in `.htaccess`, `.user.ini` and `php.ini` have a paragraph of their own (check `php-config`):

  ```
  Suspicious code in recently changed PHP files (typical webshell/backdoor patterns):
    42 document root(s) scanned, 0 suspicious file(s)

  PHP settings in .htaccess, .user.ini and php.ini (code loaded before every request, PHP for image files, known malware):
    42 document root(s) scanned, 0 suspicious file(s)
  ```
- `panel`, `backups` and `webmail` look as before.

## Configuration

**Where:** the table of settings. (`BACKUP_LOG_DIR` came with 1.11.1 and is in the README already; the plugin `backups` uses it.)

| Setting | Default | Meaning |
|---|---|---|
| `PLUGINS_OFF` | empty | names of checks that are plugins and should not run, e.g. `"backups webmail"`. Checks of the main script can't be switched off here – they have their own switches. |

- `WEBSHELL_CHECK` / `WEBSHELL_IGNORE`: switch and ignore list now apply to the checks `webshell` and `php-config`.
- `FIND_TIMEOUT`: also the time limit of an hourly plugin; a daily plugin gets three times as much, because it scans all document roots in one go.

## First run, `--only`, `--list`

- `--list` shows `php-config` among the daily checks (after `webshell`). `--only php-config` runs the scan of `.htaccess`, `.user.ini` and `php.ini` alone.
- First run after the update from 1.x: `php-config` takes the time of the last scan over from 1.x, so these files are not scanned or reported twice.

## What the script remembers

- New folder `plugins/<name>/state` (today only `php-config`); `webshell_conf_full` is gone. The text is in STATE-FILES.md already – only check that the README's short description still fits.

## Notes and limitations

- *Webshell scan*: "only PHP files changed since the previous scan" stays; add one sentence that `.htaccess`, `.user.ini` and `php.ini` are the check `php-config`, which scans all of them the first time, whatever their date.
- *Safety limits*: a plugin that runs too long is stopped like any external command, and the report says so; a plugin that fails costs its own section, not the run.

## Using another CMS? / "An idea: plugins"

**Where:** the last paragraph of *Using another CMS? Help wanted*. Replace it:

> **Plugins.** Since 2.0, checks tied to specific software (Plesk's own log, backups, Roundcube, PHP settings, and later WordPress) are plugins: small files in `plugins/` with a fixed contract, shipped with each release. Only plugins of the release run – there is no folder for your own, and no sandbox, because every plugin is reviewed like the script. Support for another CMS would be a new plugin; the issue template above is still the way to ask for it.

## Tests

- The tests now also cover the plugin framework (`tests/plugins.bats`) and every plugin with its fixtures; each moved check has a parity test against the function it replaced (`tests/legacy/`).
- Fixtures written by hand (not from a server): only the Roundcube logs in `tests/fixtures/webmail`, for attacks the real logs don't show; the backup and Roundcube tests of 1.11.1 use real, anonymized logs.
- For contributors: after changing a file in `lib/` or `plugins/`, run `tools/update-plugin-sums.sh`; the tests fail otherwise.

## Security

- "It writes only to `/var/lib/plesk-server-report`" stays true for the plugins: they write no files; their state is stored by the script.
- New point: the plugin rules (only released files, checksum, ownership, own process, line protocol), in two sentences, with a link to [docs/plugin-concept.md](docs/plugin-concept.md).
