# Security policy

`plesk-server-report.sh` runs as root on production servers. Please report security problems **privately**, not in a public issue.

## Reporting a vulnerability

Use GitHub's private reporting: on the [Security tab](https://github.com/cmelius/plesk-monitoring-server-Report/security) of this repository, click **Report a vulnerability**. Only the maintainer sees the report; we can discuss it and work on a fix there before anything is published.

Please include what you found, how to reproduce it (a log line, a configuration, the command you ran) and what an attacker could do with it. **Don't post real IPs, domains, mailbox names or log excerpts of a real server** – use `example.com` and documentation IPs (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`), or `tests/anonymize.py`.

This is a one-person project maintained alongside regular work. You can expect an answer within a few days; a fix for a confirmed problem goes into the next release, with credit in the CHANGELOG if you like.

## Supported versions

| Version | Security fixes |
|---|---|
| newest 1.x release | yes |
| older 1.x releases | no – update with `--self-update` |
| development version from `main` (`--self-update --edge`) | yes, fixed on `main` |

## What counts as a security problem

The script only reads; it changes nothing on the server (except `--self-update`, started by hand). Security problems are, for example:

- a log line, file name or DNS answer that makes the script **run code**, write outside its state directory, or crash in a way an attacker can trigger to hide an attack;
- a way to make `--self-update` install something other than the expected release (or, with `--edge`, the tested commit on `main`);
- the report, the upload or a mail **revealing secrets** – passwords from cron lines or logs, tokens, private keys;
- an attack the script should detect but that a trivial change slips past (a blind spot of a check that claims to cover it).

Not a security problem: false alarms, a check that doesn't cover software it doesn't claim to support (see *Using another CMS?* in the README), or the documented trust in GitHub and HTTPS for `--self-update` of 1.x releases (see *Security* in the README).
