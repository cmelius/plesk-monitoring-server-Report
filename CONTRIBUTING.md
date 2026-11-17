# Contributing

Thanks for helping! This script runs as root on production Plesk servers, so a few rules matter more than usual.

## Ways to help

- **Another CMS or application** (Joomla, TYPO3, Nextcloud, …): open an issue with the template [*Support for another CMS / application*](https://github.com/cmelius/plesk-monitoring-server-Report/issues/new?template=cms-support.yml). Anonymized log lines of real logins and attacks are what's needed most.
- **A mail rejection the report doesn't name yet** (no line under *What to do, by who rejected*): open an issue with the rejection line from the mail log, anonymized – see [Rejections by other mail providers?](README.md#rejections-by-other-mail-providers-help-wanted) for a command.
- **A false alarm or a blind spot**: open an issue with the alert text and, anonymized, the log lines behind it.
- **A security problem**: not as an issue – see [SECURITY.md](SECURITY.md).
- **Code**: a pull request against `main`. For anything bigger than a fix, please open an issue first, so we can agree on the approach.

## Rules for code

- **Read only.** The script never changes the server: it blocks nothing, stops nothing, deletes nothing outside its own state directory. Findings are reported, the action is the admin's. (The only exception is `--self-update`, started by hand.)
- **Not only Debian.** It must keep running on other Plesk servers (RHEL family, AlmaLinux, Rocky) and with both `mawk` and `gawk`. No new dependencies; if a tool may be missing, the check says so in a note instead of failing.
- **Log lines are hostile.** Treat everything from a log, a file name or a DNS answer as untrusted text: never run it, never use it unquoted, check numbers before computing with them.
- **The text report is an interface.** People and AI assistants read it every day. Don't change existing lines without a reason; new findings get a line in the matching section and, if they need action, an alert.
- **shellcheck** must report nothing: `shellcheck plesk-server-report.sh`.
- **Tests**: add or adapt bats tests in `tests/` and run them with both awk variants (the CI does the same):

  ```bash
  bats tests/                                     # default awk
  mkdir -p /tmp/gawk && ln -sf "$(command -v gawk)" /tmp/gawk/awk
  AWK_DIR=/tmp/gawk bats tests/                   # gawk
  ```

- **Docs in the same pull request**: README (the section of the check, and the setting in *Configuration*), `CHANGELOG.md` (under the next version), and for a new or changed state file the description in `state_readme()` – then regenerate `STATE-FILES.md` with `./plesk-server-report.sh --state-readme > STATE-FILES.md` (the CI compares both).

## No real data – anywhere

Code, tests, fixtures, README, CHANGELOG, issues and pull requests are public. Use only `example.com` / `*.example` domains and documentation IPs (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`, `2001:db8::/32`). Anonymize real logs with `tests/anonymize.py` (see *Tests* in the README), **read the result before you post it**, and delete the raw logs afterwards.

## License

By contributing you agree that your contribution is published under the [MIT License](LICENSE) of this project.
