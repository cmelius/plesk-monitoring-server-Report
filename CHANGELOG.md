# Changelog

All notable changes to `plesk-server-report.sh`. The format follows [Keep a Changelog](https://keepachangelog.com/), versions follow [Semantic Versioning](https://semver.org/). Released versions are on the [releases page](https://github.com/cmelius/plesk-monitoring-server-Report/releases); the version of a running script is shown in the first line of every report and with `--version`.

## [1.10.0] – not yet released (on `main`)

### Added
- **Devices with an outdated mail password – before fail2ban bans them.** Failed logins of one mailbox from an IP that has logged in successfully before (the same mailbox, or another one from the same office connection) raise an alert from `WARN_OLD_PASSWORD` failures in a run (new setting, default 3, `0` = off). Typically a phone or tablet after a password change, which retries until fail2ban bans the whole connection. Until now the report only noticed after the ban.
- **Login names that don't exist** are marked in "Most attacked mailboxes", with their total (Plesk: `authpsa`/`plesk_saslauthd` "No such user", Dovecot "unknown user"). A device still set up for a deleted mailbox is named as such.
- **Refused blocklist lookups of the spam filter:** SpamAssassin results with `URIBL_BLOCKED` and similar rules (`…_BLOCKED…`) are counted, with an alert and the fix. They mean that the DNS resolver – usually the hosting provider's, or a public one – is over the blocklists' free limit, so links in spam are not checked.
- **Plesk's own log** (`PLESK_ERROR_LOG`, new setting, default `/var/log/plesk/panel.log`; new hourly section `PLESK PANEL LOG`, check name `panel`): failed panel logins with login name and top IPs, and **failed automatic certificate renewals** with the reason from Let's Encrypt (DNS pointing elsewhere, domain gone, challenge URL blocked) – an alert per domain, weeks before the certificate expires. The section replaces the bare count of failed panel logins from the access log.
- **`.htaccess`, `.user.ini` and `php.ini`** in the document roots are part of the daily scan for suspicious code: a file loaded before every PHP request (`auto_prepend_file`/`auto_append_file` – Wordfence, NinjaFirewall and Sucuri excepted), PHP executed for image or text files, and the signature of a widespread WordPress malware campaign that blocks every PHP file except its own. The first scan after the update checks all of these files, whatever their date (state file `webshell_conf_full`); later scans only changed ones.
- **Delivery confirmations (DSN) sent to other servers** are counted, with an alert from `WARN_DSN` (new setting, default 1, `0` = off). Spammers request them to verify addresses, and they go to the forged sender; Postfix offers DSN to everyone by default. The README shows the fix from Postfix's documentation (offer DSN to the server itself only).
- **New IP addresses of the server** raise an alert within the hour (access & persistence check, baseline `addrs`): a hosting provider may switch on IPv6 without notice, and Postfix then sends from an address without reverse DNS and SPF entry. Until now only the daily check noticed – after up to a day. Private addresses are listed without alert.
- **Mail logins from datacenters inside `ALLOWED_COUNTRIES`** are listed for information (no alert): mail apps fetching through their servers, VPNs – or a password used from a rented server.
- **Missing DMARC record** is listed as a recommendation in the mail authentication check (no alert).
- README, *What it found so far*: the spam filter that checked no links.

### Changed
- The table "Outgoing deliveries per provider" is now called "… per receiving mail server (provider or MX host)": it always grouped by the mail server, not by the recipient's domain, so a spammer's forged domain shows up under the name of its mail server. `summary.txt` reads both names.
- **The daily checks run again after any change of the script or the configuration file**, not only after a new version number. Until now an update from `main` with the same version, or a changed setting, showed the old daily results until the next night. `daily_date` now holds a checksum of both.
- README: the example prompt for the AI review mentions outdated passwords, failed certificate renewals and refused blocklist lookups – if you use the prompt, update your copy.

## [1.9.0] – 2026-11-11

> **After updating, run the script once by hand:** `plesk-server-report.sh --only services`. From this version on, it refuses to run if `/etc/plesk-server-report.conf` belongs to another user or group/others may write it (see *Changed*). From cron you would only notice that in root's mail, the system log, or by reports that stop coming. A manual run shows the reason and the fix right away. `--version` doesn't help here: it doesn't load the configuration.

### Added
- **Access & persistence check** (hourly, new section `ACCESS & PERSISTENCE`, `PERSISTENCE_CHECK`, `PERSISTENCE_IGNORE`): what an attacker leaves behind to come back or to use the server. The script compares every run with the previous one and lists each change once:
  - **SSH keys** in the `authorized_keys` of every account (with fingerprint and comment), **accounts** with a login shell or UID 0, members of `sudo`/`wheel`/`admin`, **sudoers** files, `/etc/ld.so.preload` (normally absent; rootkits use it) – alert for anything new or changed; a key whose comment changed (same fingerprint) is listed without alert.
  - **Cron jobs** of customers, root and the system, and **autostart files** (`/etc/cron.hourly` … `monthly`, `rc.local`, systemd units in `/etc`) – alert for suspicious content (download piped into a shell, `base64 -d`, reverse shells, programs started from `/tmp`, interpreter one-liners, known miners; the alert quotes the line) and for new entries of root or the system; new customer cron jobs are listed without alert. Passwords in cron lines are masked.
  - **Processes** running from `/tmp`, `/var/tmp`, `/dev/shm` or a web folder, from a file deleted after start (not replaced by an update), from memory only, or posing as a kernel thread – typical for crypto miners and backdoors. Checked live in every run.
  - **Listening TCP ports** (not loopback) – alert for a new port number; the report lists them all in one line.

  The first run stores the current state as baseline (`baseline/` in the state directory, described in [STATE-FILES.md](STATE-FILES.md), shown by `--show-state`; `--only persistence` compares without storing anything). The script only reads: nothing is deleted, blocked or stopped. `summary.txt` has a new section with all changes and findings of the day. README: coverage table, notes, first run, configuration, example report and example prompt updated – if you use the prompt, update your copy.

- README: **Check it before you run it as root** – a prompt to let an AI review the script before the first run, and what it will point out by design (root, the configuration file loaded as code, network connections, what it deletes). The configuration file should be writable by root only (`chmod 600`).
- **The script refuses to run with an unsafe configuration file:** if `/etc/plesk-server-report.conf` belongs to another user or group/others may write it, the script stops before loading it – it is run as root code, so a warning afterwards would come too late. The reason and the fix go to stderr (cron mails it to root) and the system log. `--version`, `--help` and `--state-readme` still work.
- README, *What it found so far*: the switched-off fail2ban jail for Courier and the customer devices it revealed, the spam filter size limit, missing HSTS, unchecked SSH keys, and IPv6 switched on overnight by the hosting provider.

- **Inodes:** the filesystem list shows space and inodes used; running out of inodes (too many small files) raises an alert like a full disk (`WARN_DISK_PCT`).
- **A failed upload raises an alert.** Until now it was only in the system log, and the report that could have said so was not uploaded either. The script remembers the first failure and rclone's message (state file `upload_failed`); every following report alerts – locally, by mail, and in the upload once it works again. A note says so when `REMOTE` is set but rclone is not installed.

### Fixed
- **Kernel security updates were not counted.** The simulated `apt-get upgrade` leaves out updates that need a new package – on Debian and Ubuntu nearly every kernel update. Now simulated with `--with-new-pkgs`. And "reboot required" no longer depends on the distribution's signal alone (`/var/run/reboot-required` on Debian/Ubuntu, `needs-restarting` on the RHEL family – both come from optional packages): where it is missing, a newer kernel in `/boot` than the running one counts.
- **PHP files with their date set back were not found.** The scans for new PHP files in upload folders and for suspicious code looked at the file date only, which malware sets back (PHP `touch()`). They now also use the inode change time, which can't be forged; the report says when a file was found that way.
- Failed SMTP logins with other SASL methods than LOGIN, PLAIN and CRAM-MD5 were not counted.

### Changed
- **PHP fatal errors caused by scanners don't count.** A scanner requesting a theme, plugin or wp-admin file directly produces "Call to undefined function get_header()" and the like. These are listed separately and no longer count towards `WARN_PHP_FATAL`.
- The server's own addresses (localhost, its public IP – webmail and local scripts) are labelled "this server" instead of an unknown country.
- **Exposed files: how to check again after a fix.** The daily list of publicly reachable files and its alert now say that the result is from the daily check and how to recheck right away (`--only exposed`, or delete `daily_date`). The hourly alert for a sensitive file served with 200 says that it is a request from the access log – a past download, not the current state. (Thanks to the first GitHub issue.)
- **Every file the script creates is readable by root only** (`umask 077`). The state directory was already mode 700; now the files in it are 600 as well.
- **Size limits for the DB-IP download:** at most 200 MB compressed and 500 MB unpacked, so that a broken or tampered download can't fill the disk. The real databases are far smaller.
- **The IPv6 reverse DNS alerts say what to do:** add the PTR or AAAA record (and the address to SPF), or send over IPv4 only (`inet_protocols = ipv4`) – and that Plesk may reset that setting after `plesk repair mail` or updates. This happens when the hosting provider switches IPv6 on: Postfix uses it by default.
- README, *Notes and limitations*: FTP logins and uploads are not checked.
- README, *Using another CMS?*: plugins for other software as an idea, depending on interest.
- README, *Check it before you run it as root*: check the lines an AI quotes with `grep` before believing a finding.
- **Daily checks run again right after an update.** Until now the daily checks of the old version were shown until the next night – including its version line (`Script version: … newer than the latest release …`) – and checks new in the update were missing. The script now remembers which version ran the daily checks and repeats them in the first run of a new version.

## [1.8.0] – 2026-11-09

### Added
- **How much mail a foreign login read:** every line under "IMAP/POP3 logins … from outside ALLOWED_COUNTRIES" – and the alert for a new country – now says `no mail read` or e.g. `48.3 MB of mail read` (Courier: IMAP headers and bodies, POP3 downloads; Dovecot: `hdr_bytes`/`body_bytes` and POP3 `retr` of its default logout line). A phone keeping an idle connection open over a VPN reads nothing; an attacker downloads the mailbox. The example prompt says so.
- **Reports by mail** (`REPORT_MAIL_TO`, new setting, default off): the reports can be mailed instead of – or in addition to – the upload. By default a mail goes out when a run has an alert that was not mailed in the last 24 hours, and `summary.txt` once a day (`REPORT_MAIL`, `REPORT_MAIL_HOUR`); `all` mails every report. Sent with the local `sendmail`: to a mailbox on the same server the reports never leave it – no cloud storage needed. The script leaves its own mails out of its mail figures. `--test-mail` sends the newest report right away and shows from the mail log whether it was delivered. A report mail that bounces raises an alert in the next report. README: new section *Reports by mail* (including why the sender belongs on the spam filter whitelist: the reports quote attack paths like `/wp-admin/`, which SpamAssassin counts as spam signals), Privacy and Security updated.
- README, Privacy: the setups ranked from a GDPR point of view – local only, mail to a mailbox on this server, pseudonymised upload, upload with full addresses – and a clear note that the AI review is the most useful and the weakest option for data protection.

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
