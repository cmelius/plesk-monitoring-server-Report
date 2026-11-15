## What and why

<!-- What does this change, and which problem does it solve? Link the issue if there is one. -->

## Checklist

- [ ] The script still only reads – it changes nothing on the server
- [ ] Works with `mawk` and `gawk`, no new dependencies, not only on Debian
- [ ] `shellcheck plesk-server-report.sh` reports nothing
- [ ] Tests added or adapted in `tests/`, `bats tests/` passes
- [ ] README and `CHANGELOG.md` updated (and `state_readme()` / `STATE-FILES.md` for state files)
- [ ] No real data: only `example.com` and documentation IPs, logs anonymized with `tests/anonymize.py`

<!-- Security problems: please don't open a pull request – see SECURITY.md. -->
