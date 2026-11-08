# Changelog

All notable changes to `plesk-server-report.sh`. The format follows [Keep a Changelog](https://keepachangelog.com/), versions follow [Semantic Versioning](https://semver.org/). Released versions are on the [releases page](https://github.com/cmelius/plesk-monitoring-server-Report/releases); the version of a running script is shown in the first line of every report and with `--version`.

## [1.7.0] – 2026-11-08

### Added
- **Pseudonymised mailboxes** (`MASK_MAILBOXES`, new setting, default off): the uploaded reports show every mail address as a stable pseudonym (`mbx-4f2a91@example.com`), computed with a secret key that stays on the server; the local reports stay complete. `--decode` translates a pseudonym – or a whole pasted AI review – back to the real addresses. `--pseudonymise FILE` shows a local report as it would be uploaded, without uploading anything. Key and pseudonym list are described in [STATE-FILES.md](STATE-FILES.md).
- **Update check** (`UPDATE_CHECK`, new setting, default on): once a day the script asks the GitHub API for its latest release and shows `Script version: … – version … is available` in the daily checks. Info only, no alert, nothing is installed. One HTTPS request a day; `UPDATE_CHECK=0` switches it off.
- README: a note in the quick start that the project is young and updated often.
- README: section **Privacy (GDPR)** – which personal data the reports and the state directory contain, how long it is kept, and what to consider when the reports are uploaded or read by an AI.

### Changed
- **Failed logins are counted per mailbox regardless of upper/lower case:** attackers try `Office@example.com` and `office@example.com` separately – that is the same mailbox and now one line under "Most attacked mailboxes" (mail and webmail, also in `summary.txt`).
- **SSH/Plesk login IPs are forgotten** after `KNOWN_LOGIN_IP_DAYS` (new setting, default 90) without a login from them – until now `known_login_ips` was never cleaned up. The file now stores the last login time per IP; existing entries count as seen at the update.

## [1.6.0] – 2026-11-07

### Added
- **Description of the state directory:** every normal run keeps a `README.txt` in `/var/lib/plesk-server-report` that explains each file – what it contains, what it is used for and what happens if you delete it. The same text is in [STATE-FILES.md](STATE-FILES.md) and is printed by `--state-readme`; it comes with the script, so it always matches the installed version.
- **`--show-state`:** prints what the script remembers – known login IPs, client IPs of mail logins, foreign countries per mailbox, log positions – with dates instead of Unix timestamps. Changes nothing.
- The log position files in `offsets/` also store the path of their log, so `--show-state` can name it.

### Changed
- README: the example prompt for AI reviews also covers rejections by the big mail providers, watched recipient domains, IMAP/POP3 logins from new countries and customers banned by fail2ban (with the unban command); recommendations such as missing HSTS are mentioned once at the end instead of as issues. If you use the prompt, update your copy.

## [1.5.0] – 2026-11-06

### Added
- **Alert when fail2ban bans a customer:** the client IPs of successful IMAP/POP3 and SMTP logins are remembered for `KNOWN_MAIL_IP_DAYS` (new setting, default 30; the first run also reads the rotated mail logs). When a jail bans one of them – or an IP with earlier SSH/Plesk logins – the report lists it under FAIL2BAN and raises an alert with the mailbox and the unban command. Until now a banned customer disappeared from the failed-login figures, because their attempts no longer reach the server.

### Fixed
- RHEL-based systems: the daily `dnf` check for pending updates had no time limit (`CMD_TIMEOUT`) and could hang on a slow mirror.
- README: says up front that the script is for Plesk on Linux; the note on RHEL-based systems no longer reads as if the script were updated with `dnf`.
- **Log lines lost at rotation** when the rotated file isn't called `.1`: Plesk's daily maintenance moves the mail log to `maillog.processed` (on every Linux distribution), and logrotate on RHEL-based systems adds a date to the other logs (e.g. `secure-20261106`, where SSH logins are read from). The lines between the last run and the rotation were never read. The rotated file is now found by its inode, whatever its name.

## [1.4.0] – 2026-11-06

### Added
- **HSTS and http→https redirect** (daily, new setting `HTTPS_CHECK`): every domain with a valid certificate that points to this server is checked for a `Strict-Transport-Security` header and a redirect from http to https. Missing ones are listed as a recommendation (`security can be improved`), no alert.

### Changed
- **Backup check in every run** instead of once a day. The daily checks run shortly after midnight, before most backups, so the age shown all day was the one from the previous night's backup, and a failed backup was reported almost a day later. The line now shows the time of the latest backup, e.g. `last run 2026-11-06 03:25 UTC (3 h ago, …)`, in its own BACKUPS section and in `summary.txt`.

## [1.3.0] – 2026-11-06

### Added
- **Country check for IMAP/POP3 logins** (Dovecot and Courier). Logins from outside `ALLOWED_COUNTRIES` are listed in the report and in `summary.txt`. The alert (`mailbox … logged in via IMAP/POP3 from a new country …`) is raised only once per mailbox and country, so holidays don't cause an alert in every run. A country not seen for a mailbox for `IMAP_COUNTRY_KEEP_DAYS` (new setting, default 30) is forgotten, so the next trip alerts again.
- **Rejections by the big providers:** deferrals and bounces with the wording of Gmail, Microsoft, Apple iCloud, Yahoo/AOL, GMX/web.de and T-Online (`likely unsolicited`, `unusual rate`, rate limiting, `4.7.28`, `5.7.26`, `4.7.650`, `local policy` `[CS01]`/`[HM08]`, `[HME1]`, `excessive volume`, `[TSS04]`, `policy restrictions`, DMARC rejections) now count towards `WARN_BLOCKLIST`. Examples show the recipient domain and the remote reply, also in `summary.txt`.
- **Outgoing deliveries per provider** (sent / deferred / bounced) in the report and in `summary.txt`: Microsoft, Google, Apple iCloud, GMX/web.de/IONOS, T-Online, Yahoo/AOL and Strato by their MX hosts, other providers by their MX domain. Shows delivery trouble even when the rejection wording is unknown.
- **`WATCH_RECIPIENT_DOMAINS`** (new setting): business-critical recipient domains, e.g. `invoices.example.com`. Every deferral or bounce to them raises an alert with the remote reply.
- **Spam filter line:** `Spam filter: N mail(s) not scanned` for mails above SpamAssassin's size limit (Plesk: `SA_MAX_MAIL_SIZE`), summed in `summary.txt`. The current limit is shown in MB and bytes, also when all mails were scanned.
- README: quick start at the top. The script works without any configuration.
- README: the example report and the example `summary.txt` show the new parts.

### Fixed
- **Plesk panel logins were never detected.** `panel.log` contains no login events, and a task line with `runTaskUnderLogin=admin` could even be misread as a login. Logins are now read from the panel's access log `/var/log/plesk/httpsd_access_log` (`PLESK_PANEL_LOG` now points there): successful logins with IP and country, an alert for unknown IPs, and a count of failed attempts.
- Courier's SSL services (`courier-imaps`, `courier-pop3s`) were not recognized, so failed logins on ports 993/995 were missing from the IMAP/POP3 count.
- Blocklist/reputation keywords are matched in the remote reply only, not in the mail addresses.

## [1.2.0] – 2026-11-05

### Added
- **Safety limits:** time limits for every external command that can hang (`CMD_TIMEOUT`) and for file-system scans of the web folders (`FIND_TIMEOUT`), a runtime limit for the whole cron run (`MAX_RUNTIME`), at most `MAX_LOG_MB` per log file and run. The script runs with low CPU and I/O priority.
- **No silent failures:** an aborted run, a run that is still hanging or a command that timed out raises a `Script: …` alert. Missing data sources (logs not found, empty paths in the configuration) are shown as ` i ` notes below the STATUS line and in a new SCRIPT NOTES section of `summary.txt`.
- Plausibility check: if the IMAP/POP3 server writes log lines but no login is recognized, a note says the log format is unknown.
- **Courier IMAP/POP3:** failed logins are counted when Plesk uses Courier instead of Dovecot (until now the report showed 0), including top IPs and attacked mailboxes. Dovecot mailboxes are listed too.
- README: note on the `plesk-courierimap` fail2ban jail (Plesk only activates the Dovecot jail by default); example prompt reports `Script:` alerts and script notes.

### Changed
- Temporary files are kept under the state directory instead of `/tmp`, which is in RAM on Debian 13.
- The daily checks are marked as done before they run, so one aborting check can't block all following runs.
- `--only` and `--summary` say so when another run is in progress instead of exiting silently.
- rclone keeps its default retries, which Google Drive's rate limits need. README recommends an own Google client ID for rclone.

## [1.1.1] – 2026-11-04 (released as part of 1.2.0)

### Fixed
- Local reports are deleted after exactly `LOCAL_KEEP_DAYS` days (`find -mtime +7` only matched files at least 8 days old).
- `latest.txt` and `summary.txt` are uploaded as new files instead of being overwritten, so Google Drive keeps no older versions of them for up to 30 days.

## [1.1.0] – 2026-11-04

### Added
- **`summary.txt`:** every run also writes a condensed summary of the last 24 hours (all alerts with count and first/last time, totals, every login and every finding of the normally empty sections) and uploads it next to `latest.txt`. A daily review needs two files instead of every report.
- Option `--summary`.
- README: example prompt for AI reviews searches the two files by name instead of listing the folder.

## [1.0.1] – 2026-11-03 (released as part of 1.1.0)

### Fixed
- The "sent to N recipients" alert only counts mail sent from this server (mailbox login or local script). Incoming mail no longer triggers it, and delivery retries are no longer counted twice.

## [1.0.0] – 2026-11-02

First release, after several days of running on a production server with about 40 domains. Version shown in the report header and with `--version`.

### Changed
- SPF/DKIM check recognizes Plesk domain aliases with the mail service switched off and lists them for information only instead of alerting (SPF `+all` is still reported).

## Before 1.0.0

- **2026-10-30:** script restructured: one function per check (`check_mail`, `check_web`, `check_mailauth`, …) and a short `main()` that defines the order; local variables instead of globals shared between sections. Report output unchanged. New option `--only CHECK,…` runs single checks immediately without changing any state, `--list` shows the names.
- **2026-10-30:** exposed-file scan: clearer wording – files answered with 403 are reported as "blocked by the web server", files that return a server error are listed separately.
- **2026-10-30:** exposed-file scan: blocked findings summarized per domain, SQL files shipped with software (plugin schemas, osTicket/phpBB upgrade scripts) ignored by default; first real run found a public backup archive and leftover installer directories.
- **2026-10-30:** web attack statistics (SQLi, traversal, code execution, XSS, probes for sensitive files with "served and present on disk" detection), traffic peaks and distributed requests, ModSecurity summary per domain, daily scan of document roots for exposed files (with reachability test) and of recently changed PHP files for webshell code.
- **2026-10-30:** fix: link-local IPv6 (`fe80::`) was taken as the server's public IPv6, so every domain got `v6:fail`. Now only a global, non-ULA address counts, and the IPv4 and IPv6 SPF results are evaluated separately.
- **2026-10-30:** server DNS (PTR, forward-confirmed, HELO name, optional IPv6), mail server certificates on all mail ports for the client host name, per-domain DNS (still pointing here, CAA vs. Let's Encrypt, broken DNSSEC/SERVFAIL, Spamhaus DBL/SURBL), SPF hard errors (multiple records, >10 lookups, `+all`), SPF for IPv6.
- **2026-10-30:** SPF/DKIM check queries a public resolver (systemd-resolved returned empty answers for the server's own hostname); alert only when SPF *and* DKIM fail (DMARC logic), single failures listed as recommendations.
- **2026-10-30:** daily SPF/DKIM/DMARC check for all mail domains (DKIM key in DNS compared with the Plesk key, SPF evaluated against this server's IP, MX and DNS hoster shown), paths configurable.
- **2026-10-29:** Roundcube webmail analysis (mails sent per mailbox with real client IP, recipients and geolocation, failed webmail logins, alerts for mass sending, foreign countries and sending after repeated failed logins); issue template for other CMS; optional geolocation (country + network operator, local DB-IP Lite database, monthly refresh) for successful logins and top failed-login IPs, alerts via `ALLOWED_COUNTRIES` for mailboxes, SSH, Plesk panel and WordPress logins from unexpected countries; WordPress login-attack analysis with brute-force success detection; full `PATH` for cron runs (Plesk domain list for the TLS check and the mail queue size were missing under cron).
- **2026-10-26:** first public version.
