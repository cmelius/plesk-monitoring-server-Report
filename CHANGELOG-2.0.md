# Changelog for 2.0 (branch changelog)

**This is the changelog of the branch `feature/plugin-system`.** It lists what this branch changes compared with `main`, for the later major version 2.0. Nothing here is released. The changes of the 1.x releases stay in [CHANGELOG.md](CHANGELOG.md), which this branch does not edit, so merging `main` into the branch causes no conflict there. When 2.0 is released, these entries move into `CHANGELOG.md` as the section `[2.0.0]` and this file is removed.

The design is described in [docs/plugin-concept.md](docs/plugin-concept.md).

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
- A plugin runs with the time zone (`TZ`) of the main script.
- The script no longer consists of one file: `lib/` and `plugins/` must be installed next to it. Installation from a release archive and the README section for it follow before 2.0.
