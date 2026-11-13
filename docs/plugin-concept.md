# Plugin system – concept

Status: concept for a later major version (2.0). Steps 1 to 4 of the order below are
built (framework, `panel`, `backups`, `webmail`, `php-config`, `wordpress`; see "State of the code"). This branch
(`feature/plugin-system`) carries the work; `main` continues with the 1.x releases
and is merged into this branch from time to time.

## Summary

Checks that depend on specific software (Plesk, Roundcube, WordPress, PHP settings)
move out of the main script into plugins: one file per check, with a fixed contract.

- **Only plugins shipped with a release run.** There is no directory for third-party
  plugins. A plugin is core code in a separate file, reviewed like the main script.
- **No sandbox.** A plugin runs as root, like the main script. What keeps it safe is
  that only released files run (hash check), the release rules below, and the tests.
- **Each plugin is its own `bash` process**, never sourced into the main script.
- **New log lines arrive on stdin**, the plugin answers with a line protocol
  (`TEXT`, `NOTE`, `ALERT`, `STATE`). Alerts, summary, `--only`, state files and
  everything that needs the network stay in the core.
- **Shipped plugins are on by default** (`PLUGINS_OFF="…"` switches one off), so an
  update never drops a check silently.

The basic rule of the script holds for plugins too: nothing on the server is changed,
blocked or deleted outside the script's own state directory.

## What the code looks like today (1.11.0)

These properties of `plesk-server-report.sh` shape the design:

- Checks write straight into the report: every `check_<name>` calls `section`, `out`,
  `alert`, `note` (hourly) or prints to stdout and calls `dalert` (daily). Order and
  names come from `HOURLY_CHECKS` and `DAILY_CHECKS`; `--only` and `--list` use them.
- `summary.txt` is parsed from the report text. `summary_records` recognizes sections
  by their header (`== MAIL ==`, `== WEB `, `== BACKUPS ==`, …) and subsections by
  fixed line beginnings. Renaming a section or a line breaks the summary silently.
- Three checks have no section of their own: `webmail` writes into `== MAIL ==`, the
  WordPress analysis is part of `check_web` (including the column "login POSTs"), and
  the `.htaccess`/`.user.ini` scan is part of `check_webshell`.
- Log positions belong to the core: `new_lines` keeps inode and offset per log path in
  `offsets/`. A second reader of the same log would get nothing.
- Checks share state: `known_mail_ips` is written by `mail` and read by
  `old_password_check` and `fail2ban`; `known_login_ips` is written by `logins` and
  read by `fail2ban`. `check_logins` asks whether `panel` runs.
- Plesk data comes from `plesk db` / `plesk bin` (`docroots`, `site_domains`,
  `load_aliases`, `check_mailboxes`).
- Reusable safety mechanics: `log_clean`, `load_conf` (refuses an unsafe file), `T`
  (time limit, timeout becomes an alert), `self_sum` (daily checks run again after a
  change).

## Contract

A plugin is a bash file `plugins/<name>.sh` with a static header and one function.

```bash
PLUGIN_NAME="panel"
PLUGIN_API="1"
PLUGIN_SCHEDULE="hourly"                      # hourly | daily
PLUGIN_SECTION="PLESK PANEL LOG"              # section title in the report
PLUGIN_LOGS="/var/log/plesk/panel.log"        # logs whose new lines it gets on stdin
PLUGIN_READS=""                               # other paths it reads (documentation, review)
PLUGIN_INPUTS=""                              # context files from the core: domains, …
PLUGIN_SETTINGS=""                            # settings it gets as environment variables
PLUGIN_REQUIRES="plesk"                       # skipped with a note where this is missing
PLUGIN_OS="debian rhel"
PLUGIN_MAINTAINER="…"

plugin_check() { …; }
```

- The header is read as text by the core: lines `PLUGIN_X="…"` only, values checked
  against a pattern, nothing expanded. The core never sources a plugin.
- `PLUGIN_NAME` matches `^[a-z][a-z0-9-]{1,30}$`, equals the file name and is the name
  for `--only` and `--list`. It must not collide with a core check.
- An unknown `PLUGIN_API` means: not run, note in the report.
- Settings: the plugin does not load the configuration file. The core passes the
  declared variables only.
- Context: the core asks Plesk once and hands over files (`domains`: domain TAB
  document root; `last_run`; `os`; `plesk`). Plugins never call `plesk` themselves.

## Loading and running

Loading (in the core, without running plugin code):

1. Candidates are the files in `plugins/` next to the script (path from
   `readlink -f "$0"`, not from the configuration), minus `PLUGINS_OFF`.
2. The file and every parent directory must belong to root, must not be writable by
   group or others, and must not be a symlink – the rule `load_conf` applies today.
3. The content is read once and its SHA-256 compared with the list built into the
   core. A file that is not in the list or differs is not run and raises an alert.
   The checked copy is what runs.
4. The header is parsed and validated.

The hash does not protect against someone who can change root's files – they could
change the main script as well. It protects against half-finished updates, mixed
versions and a file dropped into the directory running along unnoticed.

Running:

- Own process with an empty environment (`env -i`, fixed `PATH`, `LC_ALL=C`, the
  `PSR_*` variables, the declared settings), `bash --noprofile --norc`, `umask 077`.
  It loads the shared library, then the plugin, then calls `plugin_check`.
- Time limit through `T`; a timeout becomes a `Script:` alert as today.
- stdin: the new log lines, already through `log_clean`. With several logs, a
  separator line starting with the control character `\036` marks each file; `log_clean`
  removes that character from every log line, so a log line can't imitate it.
- stderr is dropped; on a non-zero exit code its first lines become a note.
- A plugin that fails costs its own section, not the run.

## Output protocol

Every stdout line starts with a keyword and a space. Anything else is dropped and
counted in a note.

| Line | Effect in the core | Limit |
|---|---|---|
| `TEXT <line>` | `out` in the plugin's section, indentation kept | 300 lines, 300 characters each |
| `NOTE <text>` | ` i ` note below the STATUS line (missing data source) | 5 |
| `ALERT <text>` | `alert` (hourly) or `dalert` (daily) | 20, 400 characters each |
| `STATE <line>` | replaces the plugin's state, only if `can_write_state` | 1 MB |

The limits guard against mistakes (a loop, a huge log), not against attacks. The core
applies `log_clean` to every line. `MASK_MAILBOXES` works without further code,
because it is applied to the whole report.

State: a plugin writes no files. It gets its previous state as a file (`$PSR_STATE`)
and prints the new one as `STATE` lines; the core stores it in
`$STATE_DIR/plugins/<name>/state`. So `--only` and locked-out runs change nothing, and
`--show-state` can show it. `state_readme()` and `STATE-FILES.md` describe it.

## Rules for a plugin to be released (checked by the workflow)

- ShellCheck without a finding, like the main script.
- Static check: no network commands (`curl`, `wget`, `nc`, `dig`, `ssh`, `/dev/tcp`),
  no changing commands (`rm`, `mv`, `cp`, `chmod`, `chown`, `kill`, `systemctl`,
  `plesk`, `sed -i`), no redirection into files other than `/dev/null`, no `eval`, no
  `source`. An exception needs a comment with the reason, like `# shellcheck disable`.
- Fixtures and a test for every plugin; the header matches the contract; the hash list
  in the core matches the files.
- Data from logs is text: never in `(( ))`, `eval` or as a command. The test with
  hostile log lines runs against every plugin.

## Which checks move

Five of the 21 checks move in 2.0 – the ones tied to specific software that only read
and share no state with other checks.

| Check | Reads | Also needs | Notes |
|---|---|---|---|
| `panel` (hourly) | `/var/log/plesk/panel.log` | GeoIP | first: one log, no state, own section, test exists |
| `backups` (hourly) | the Plesk PMM log directory | `pgrep` (Acronis) | no log on stdin; `summary.txt` reads `== BACKUPS ==` |
| `webmail` (hourly) | Roundcube `sendmail` and `errors` | GeoIP, several `WARN_*`, `ALLOWED_COUNTRIES` | first with two logs; today inside `== MAIL ==` |
| `php-config` (daily, from `webshell`) | `.htaccess`, `.user.ini`, `php.ini` in the document roots | context `domains`, state "last scan" | first daily plugin |
| `wordpress` (hourly, from `web` and `uploads`) | access logs of all domains, `wp-content/uploads` | state `last_scan`, `WARN_LOGIN_*`, GeoIP | last: changes the layout of `== WEB ==`, reads the largest logs a second time |

Staying in the core:

- everything with the network: `updates`, `certificates`, `https`, `serverdns`,
  `mailtls`, `domaindns`, `mailauth`, `exposed`, upload, GeoIP download;
- `persistence`, `logins`, the PHP part of `webshell` – the security core;
- `mail`: one awk program covers Postfix, Dovecot and Courier; Courier is not a
  separable block. A parser layer would have to come first (2.x);
- `fail2ban`: depends on the state of `mail` and `logins`;
- `system`, `services`, `web` without WordPress: the same on every server;
- `mailboxes`: needs the Plesk database; possible later with a context file.

Shared helpers (`geo`, `geo_foreign`, `fmt_bytes`, `in_cidr`, the separator logic) go
into `lib/plugin-lib.sh`, loaded by the core and by the plugins.

## Order

Each step adds one capability to the framework and ends when old and new output are
equal. The contract stays open (`PLUGIN_API=0`) until step 6.

1. Framework and `panel`: loader, static header, hash list, own process, protocol, one
   log on stdin, offsets, name in `--only`/`--list`.
2. `backups`: a plugin without a log.
3. `webmail`: several logs, settings, GeoIP library, own section, `summary_records`.
4. `php-config`: daily plugin, context file `domains`, `STATE`.
5. `wordpress`: many logs per domain, layout of `== WEB ==`, state `last_scan`.
6. Freeze the contract (`PLUGIN_API=1`), release 2.0.

Comparing on a server: `--only` reads from the stored offsets and writes nothing. A
second cron entry a few minutes after the normal run calls the released version and
the branch version with `--only <check>` and compares the two outputs.

Offsets: the key becomes a hash of plugin name and path. On the first run of a moved
check the core takes over the old offset, so the last 20,000 lines are not read again
and old alerts are not repeated.

## Tests

Rule: when a check moves, the assertions of its existing tests stay as they are; only
`setup` changes. Unchanged assertions that still pass show that report and alert texts
are the same.

- Checks in the core: tests unchanged, with mawk and gawk as today.
- Moved checks: `setup` calls the loader with the plugin (`run_plugin <name>` in
  `tests/helper.bash`) and the fixture as log – the same path as in production, without
  root and without the ownership check, which only the test helper switches off.
- Parity test per moved check: the same fixture through the old function from the last
  release tag and through the plugin; report and alerts must be byte-identical.
- Loader tests: wrong owner, writable directory, symlink, header with `$(…)`, wrong
  name, unknown API, hash mismatch, foreign file in the plugin directory.
- Protocol tests: 10,000 lines, overlong lines, control characters, unknown keywords,
  a hanging plugin, a failing plugin.
- The workflow keeps syntax, ShellCheck (script and plugins), the `STATE-FILES.md`
  comparison and bats with mawk/gawk, and adds the contract check, the static check
  and the hash list check.

## Distribution

- Layout: `/usr/local/lib/plesk-server-report/` with the script, `lib/` and
  `plugins/`; a link in `/usr/local/sbin`. The cron entry from the README stays valid.
- Release as tar.gz, unpacked as root with `--no-same-owner`, with `SHA256SUMS`.
- If `plugins/` is missing next to the script (an old single-file installation) or a
  plugin from the hash list is missing, the report raises an alert naming the checks
  that did not run.
- The script never downloads plugins or itself on its own. `--self-update`, run by hand as
  root, installs a release: signature of `SHA256SUMS` (SSH key of the maintainer,
  `RELEASE_KEY`), checksum, plain files only, self-test of the new version (`--verify`),
  question, then the folders are swapped; the previous one stays as `.old`.
- Releases: the workflow `release` (started by hand) builds the archive and `SHA256SUMS`
  on GitHub as a draft release. The private key is never on GitHub: the maintainer signs
  `SHA256SUMS` on their own computer, adds `SHA256SUMS.sig` and publishes the draft.
- README: the review prompt names every file of the archive; the sentence about
  sandboxed plugins is replaced.

## Open

- (decided) Runtime of step 5: on the maintainer's server all access logs together are
  1.2 MB, read in 5 ms; `--only web` takes 1.5 s, almost all of it fixed costs. `wordpress`
  reads the logs a second time, with positions of its own; no shared stream.

## State of the code

Steps 1 to 5 are built: `lib/plugin-lib.sh` (runs one plugin), `plugins/panel.sh`,
`plugins/backups.sh` (no log on stdin; `PLUGIN_READS` names the directories),
`plugins/webmail.sh` (several logs), `plugins/php-config.sh` (daily, context `domains`,
state), `plugins/wordpress.sh` (the logs of every domain, own section), the loader
and the protocol in the main script (`run_plugin`), `tools/update-plugin-sums.sh`, and
the tests in `tests/plugins.bats` and one file per plugin (with
parity tests against the old functions in `tests/legacy/`). Where it differs from the text above, for now:

- GeoIP stays in the main script. A plugin writes `$(geo_ref IP)` into a line and the
  main script replaces it with "IP (country, operator)". So a plugin needs neither the
  database nor the settings for it.
- `PLUGIN_LOGS` may name a setting (`$PLESK_ERROR_LOG`) or a file below a directory
  from the settings (`$ROUNDCUBE_LOG_DIR/sendmail`); the main script resolves it, and
  only if the setting is listed in `PLUGIN_SETTINGS`. `webmail` lists the logs of every
  place Roundcube may log to and takes those of the directory in use.
- Country alerts: a plugin prints `ALERT-FOREIGN <ips> :: <text>` (`alert_foreign`); the
  main script raises the alert only if one of the IPs is outside `ALLOWED_COUNTRIES`,
  and puts those IPs into the text. Among each other these alerts now come in the order
  of the mailboxes in the report (before: in no fixed order).
- `webmail` has no section of its own, other than planned: it leaves out
  `PLUGIN_SECTION` and continues `== MAIL ==`, so the report and `summary.txt` stay as
  they are. A section of its own can follow with 2.0 if wanted.
- A plugin's name stands in `HOURLY_CHECKS` like every check; a name without a
  `check_<name>` function is a plugin.
- Offsets: a plugin's key is a hash of its name and the path (`new_lines FILE PLUGIN`),
  the main script's stays a hash of the path. Before the checks of a normal run,
  `plugin_seed_offsets` gives a plugin without a position the one the main script stored
  in the run before – so the update from 1.x neither repeats nor misses lines, also for
  the access logs, which `web` keeps reading.
- `PLUGIN_LOGS` may contain `*` as a whole part of a path (`$VHOST_LOGS/*/logs/access_log`);
  each match is a log of its own on stdin, numbered by its entry in `PLUGIN_LOGS`.
- `wordpress` has the section `WORDPRESS (since last run)` after `WEB`, which loses the
  column *login POSTs*; the section `WEBROOTS` is gone. `summary.txt` reads both layouts.
  Successful logins of a domain are listed in IP order (before: the order awk kept them).
  Its scan of the upload folders gets two thirds of the time limit and stores no new
  `last_scan` when it is cut off.
- Daily plugins print their own heading (`PLUGIN_SECTION` empty), their time limit is
  three times `FIND_TIMEOUT` (one scan over all document roots instead of one `find`
  per domain), their alerts go to the daily alerts.
- State: `STATE` lines are kept only if the plugin ended without error and printed at
  least one, and only in a normal run. `plugin_state_seed` takes the state over from the
  files of version 1.x (`php-config`: the time of `webshell_scan`, if
  `webshell_conf_full` exists); the old file is deleted once the new state exists.
- `php-config` stores the scan time with nanoseconds (`date +%s.%N`, compared with
  `find -newermt/-newerct @…`), as precise as the stamp file it replaces.
- `PLUGIN_REQUIRES` is not built: no plugin needs it yet.
- Limits: 500 `TEXT` lines, 100 alerts, 10 notes, 2000 bytes per line. The time limit
  is `FIND_TIMEOUT`.
- Commands inside a plugin have no time limit of their own (`T`); the limit for the
  whole plugin covers them.
- `PLUGIN_API` is `0` until step 6.
- The changes of this branch are listed in `CHANGELOG-2.0.md` (branch changelog), not
  in `CHANGELOG.md`, so that merging `main` into this branch stays simple. The README
  changes are collected in `README-2.0.md` (branch README); the release archive follows
  before 2.0.

## If third-party plugins are ever wanted

Process boundary, stdin and protocol are already there, so a sandbox can be added
without changing the contract. Three findings from the first draft to keep in mind:
don't run plugins as root (uid 0 can signal root's processes even without
capabilities); block `open_by_handle_at`, because `CAP_DAC_READ_SEARCH` reads past any
mount isolation with it; and older systemd versions (239 on RHEL 8) lack some of the
hardening options.
