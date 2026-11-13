# Changelog for 2.0 (branch changelog)

**This is the changelog of the branch `feature/plugin-system`.** It lists what this branch changes compared with `main`, for the later major version 2.0. Nothing here is released. The changes of the 1.x releases stay in [CHANGELOG.md](CHANGELOG.md), which this branch does not edit, so merging `main` into the branch causes no conflict there. When 2.0 is released, these entries move into `CHANGELOG.md` as the section `[2.0.0]` and this file is removed.

The design is described in [docs/plugin-concept.md](docs/plugin-concept.md); the README changes for 2.0 are collected in [README-2.0.md](README-2.0.md).

## Not yet released

### Added
- **Plugins:** checks tied to specific software move out of the main script into files of their own (`plugins/<name>.sh`), shipped with the release. Each plugin runs in a `bash` process of its own with an empty environment, gets the new lines of its logs on stdin and the settings it declares, and answers with `TEXT`, `NOTE` and `ALERT` lines. A plugin only reads: it writes no files and makes no network connections. Alerts, summary, `--only`, state files and everything that needs the network stay in the main script.
- **Only the plugins of the release run.** The main script holds the SHA-256 of `lib/plugin-lib.sh` and of every plugin. A file that is missing, changed or not in the list is not run and raises an alert; so do a plugin that fails or runs too long. The files and their directories must belong to root and must not be writable by others, like the configuration file.
- `PLUGINS_OFF` (new setting, default empty): names of plugins that should not run. Shipped plugins are on by default, so an update never drops a check silently.
- **Tests** for the plugin framework (`tests/plugins.bats`): checksums, header, protocol and limits, failing and hanging plugins, and a rule check that plugins contain no network or changing commands. The workflow checks `lib/`, `plugins/` and `tools/` with ShellCheck too.
- `PLESK_BACKUP_LOGS` (new setting, default empty = the usual places): the directory with the logs of Plesk's backups, for systems that keep them elsewhere. README: follows with the other changes for 2.0.
- `tools/update-plugin-sums.sh` (for developing): writes the checksums into the main script after a plugin was changed.

### Changed
- **`panel` is a plugin** (`plugins/panel.sh`). Section `PLESK PANEL LOG`, its lines and its alerts are unchanged; a test compares them with the output of the old function. The name for `--only` and `--list` stays `panel`.
- **`backups` is a plugin** (`plugins/backups.sh`), the first one without a log on stdin. Section `BACKUPS`, its lines and its alerts are unchanged, so `summary.txt` shows the backup status as before. New tests with hand-written backup logs (`tests/backups.bats`).
- **`webmail` is a plugin** (`plugins/webmail.sh`), the first one with several logs. Its lines stay in the section `MAIL` and its alerts are unchanged, so `summary.txt` counts failed webmail logins as before. New tests with hand-written Roundcube logs (`tests/webmail.bats`); the test with hostile log lines covers it.
- For plugins: a plugin may leave out `PLUGIN_SECTION` and continue the section before it; `PLUGIN_LOGS` may name a file below a directory from the settings (`$SETTING/file`); `ALERT-FOREIGN` (`alert_foreign`) raises an alert only if one of the given IPs is outside `ALLOWED_COUNTRIES` – the main script, which has the GeoIP database, decides.
- **`php-config` is a plugin** (`plugins/php-config.sh`), the first daily one: the scan of `.htaccess`, `.user.ini` and `php.ini` in the document roots moves out of `webshell` into a check of its own (`--only php-config`). It finds the same files and raises the same alerts; in the daily checks it has its own paragraph *PHP settings in .htaccess, .user.ini and php.ini*, and the paragraph of `webshell` covers PHP files only. `WEBSHELL_CHECK=0` switches off both. The time of its last scan is kept in `plugins/php-config/state` instead of `webshell_conf_full`; the first run takes it over from version 1.x, so nothing is scanned or reported twice. README: the example report follows with the other changes for 2.0.
- For plugins: daily plugins (`PLUGIN_SCHEDULE="daily"`, time limit three times `FIND_TIMEOUT`); the context file `domains` (`PLUGIN_INPUTS`: domain and document root, asked from Plesk by the main script); a state (`STATE` lines, stored by the main script in `plugins/<name>/state` – only in a normal run – and handed back as `$PSR_STATE`). `--show-state` shows the plugins' states; STATE-FILES.md describes them.
- A plugin runs with the time zone (`TZ`) of the main script.
- The script no longer consists of one file: `lib/` and `plugins/` must be installed next to it. Installation from a release archive and the README section for it follow before 2.0.
