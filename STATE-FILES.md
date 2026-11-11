# State files of plesk-server-report

This folder (default `/var/lib/plesk-server-report`, setting `STATE_DIR`) is the
script's memory between runs. The script writes this description itself and
replaces it when an update changes it – edits to this file are lost.

You never have to touch these files. Typical reasons to look anyway:
"why was there no alert?" (is the IP or country already known?) and
"the script should forget something" (a known IP that turned out to be an
attacker). `plesk-server-report.sh --show-state` prints the content in readable
form, with dates instead of Unix timestamps.

**Deleting is safe:** any file or folder here can be deleted. The script starts
that part from scratch on its next run. For the "known" lists this means: the
next run learns silently again (no alert for anything it sees then), so delete
them only if you want exactly that. To forget a single entry, delete its line.

Timestamps are Unix time (seconds since 1970, UTC): `date -d @1793684400`.

## Remembered for alerts

| File | Content (one entry per line) | Used for |
|---|---|---|
| `known_login_ips` | `IP last-seen` | SSH and Plesk panel logins: an IP not in this list raises "login … from previously unknown IP". The first run fills it without alerts. An IP not seen for `KNOWN_LOGIN_IP_DAYS` is dropped. |
| `known_mail_ips` | `IP mailbox last-seen` | client IPs of successful IMAP/POP3 and SMTP logins, kept for `KNOWN_MAIL_IP_DAYS`. Failed logins from one of them raise "… failed logins of … – a device with an outdated password?" (`WARN_OLD_PASSWORD`); when fail2ban bans one of them, the report raises "fail2ban: jail … bans … which had successful logins before". |
| `known_imap_countries` | `mailbox country last-seen` | countries outside `ALLOWED_COUNTRIES` a mailbox has fetched mail from. The alert "logged in via IMAP/POP3 from a new country" comes once per mailbox and country; an entry not seen for `IMAP_COUNTRY_KEEP_DAYS` is dropped, so the next trip alerts again. |

## Baseline for the access & persistence check (`baseline/`)

Each run compares the current state with these lists, reports what is new, changed
or gone, and then replaces them. Delete the folder or a file and the next run stores
the current state silently as the new baseline (except suspicious cron content, which
is always reported). Processes are not stored – they are checked live in every run.

| File | Content (one entry per line) | Used for |
|---|---|---|
| `baseline/keys` | `account key-type fingerprint comment` | the SSH keys in the `~/.ssh/authorized_keys` of all accounts. A new key raises "Access: new SSH key for …". |
| `baseline/access` | `kind name details` | accounts with a login shell or UID 0, members of the groups `sudo`, `wheel` and `admin`, the sudoers files with a checksum, and – only if the file exists, which it normally doesn't – what `/etc/ld.so.preload` loads. New or changed entries raise an alert. |
| `baseline/cron` | `line where cron-line` or `file path checksum` | the cron jobs of all accounts and of the system (passwords in them masked), and checksums of the autostart files (`/etc/cron.hourly` … `monthly`, `rc.local`, systemd units in `/etc/systemd/system`). New entries are listed; suspicious ones and new entries of root or the system raise an alert. |
| `baseline/addrs` | `address interface` | the server's global IPv4 and IPv6 addresses. A new public address raises "Network: new public address …" – e.g. IPv6 switched on by the hosting provider; private addresses are listed without alert. |
| `baseline/ports` | `port process` | TCP ports listening on an address other than loopback. A new port number raises "Ports: new listening TCP port …"; the process name is information only (processes sharing a socket take turns, e.g. Postfix `master` and `smtpd`). |

## Pseudonyms (only with `MASK_MAILBOXES=1`)

| File | Content | Used for |
|---|---|---|
| `mask_key` | a random secret (mode 600), created on first use | the pseudonym of a mail address is a hash of the address with this key, so the same mailbox always gets the same pseudonym (`mbx-4f2a91@example.com`) and nobody without the key can compute it back. It never leaves the server. Delete it and all mailboxes get new pseudonyms. |
| `mailbox_pseudonyms` | `pseudonym address last-seen` | `--decode` turns pseudonyms in a report or an AI review back into real addresses. Entries are kept for 30 days (or `RETENTION_DAYS`, if longer), as long as uploaded reports may contain them. |

## Mails (only with `REPORT_MAIL_TO`)

| File | Content | Used for |
|---|---|---|
| `mailed_alerts` | `key mailed-at` – a hash of each mailed alert without its figures | a report is mailed right away only for an alert that was not mailed in the last 24 hours, so a lasting problem doesn't send a mail every run. Delete it and the next alert is mailed again. |
| `mail_summary_date` | the day (YYYY-MM-DD) the summary was last mailed | the summary goes out once a day, with the first run from `REPORT_MAIL_HOUR` on. |
| `mail_failed` | time of a mail that `sendmail` refused | the next report mentions it as a note, then the file is deleted. Mails that were accepted but could not be delivered (wrong address, mailbox full) raise an alert in the next report instead. |

## Where reading stopped

| File | Content | Used for |
|---|---|---|
| `last_run` | Unix time of the last normal run | everything "since the last run" (journal, web logs). |
| `offsets/` | one file per log, named after a hash of its path; content `inode bytes-read path` | the script reads only the lines added since the last run. The inode identifies the file after a rotation (`maillog` → `maillog.processed`), so the rest of the old file is still read. Delete a file here and that log is read again from its last 20,000 lines. |
| `journal_since` | Unix time | position in the systemd journal (only if there is no mail log file). |
| `last_scan` | empty; its modification time counts | new PHP files in upload folders are files changed after this – by file date or by inode change time, so a file with its date set back is found too. |
| `webshell_scan` | empty; its modification time counts | the daily scan for suspicious code looks only at PHP files, `.htaccess`, `.user.ini` and `php.ini` changed since then (file date or inode change time). |
| `webshell_conf_full` | empty | marks that `.htaccess`, `.user.ini` and `php.ini` were scanned completely once. Without it, the next daily scan checks all of them, whatever their date. |

## Daily checks

| File | Content |
|---|---|
| `daily_date` | the day (YYYY-MM-DD), the script version and a checksum of the script and its configuration file of the last daily checks – they run in the first run of a new day, and right after the script or the configuration file changed. Delete it to run them again in the next run. |
| `daily.txt` | their output, repeated in every report of that day under DAILY CHECKS. |
| `daily_alerts.txt` | their alerts, repeated in every report of that day. |

## Other

| File / folder | Content |
|---|---|
| `out/` | the reports and `summary.txt`, kept for `LOCAL_KEEP_DAYS`. `summary.txt` is built from these files. |
| `geoip/` | the DB-IP Lite databases for country and network operator (`GEOIP_DIR`), refreshed monthly. |
| `lock` | lock file, so that only one run at a time is active (it is never deleted). |
| `running` | exists only while a run is active: `PID start now step exit-code`. If it is still there at the next run, that run did not finish, and the report says so (alert "Script: …"). |
| `upload_failed` | time of the first failed upload, and rclone's last error message | while the upload to `REMOTE` fails, every report raises an alert (local report, mail). Deleted by the next successful upload. |
| `tmp.*` | temporary files of the current run, removed at its end. |
| `README.txt` | this description. |
