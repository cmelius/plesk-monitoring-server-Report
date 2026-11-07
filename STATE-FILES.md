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
| `known_mail_ips` | `IP mailbox last-seen` | client IPs of successful IMAP/POP3 and SMTP logins, kept for `KNOWN_MAIL_IP_DAYS`. When fail2ban bans one of them, the report raises "fail2ban: jail … bans … which had successful logins before". |
| `known_imap_countries` | `mailbox country last-seen` | countries outside `ALLOWED_COUNTRIES` a mailbox has fetched mail from. The alert "logged in via IMAP/POP3 from a new country" comes once per mailbox and country; an entry not seen for `IMAP_COUNTRY_KEEP_DAYS` is dropped, so the next trip alerts again. |

## Pseudonyms (only with `MASK_MAILBOXES=1`)

| File | Content | Used for |
|---|---|---|
| `mask_key` | a random secret (mode 600), created on first use | the pseudonym of a mail address is a hash of the address with this key, so the same mailbox always gets the same pseudonym (`mbx-4f2a91@example.com`) and nobody without the key can compute it back. It never leaves the server. Delete it and all mailboxes get new pseudonyms. |
| `mailbox_pseudonyms` | `pseudonym address last-seen` | `--decode` turns pseudonyms in a report or an AI review back into real addresses. Entries are kept for 30 days (or `RETENTION_DAYS`, if longer), as long as uploaded reports may contain them. |

## Where reading stopped

| File | Content | Used for |
|---|---|---|
| `last_run` | Unix time of the last normal run | everything "since the last run" (journal, web logs). |
| `offsets/` | one file per log, named after a hash of its path; content `inode bytes-read path` | the script reads only the lines added since the last run. The inode identifies the file after a rotation (`maillog` → `maillog.processed`), so the rest of the old file is still read. Delete a file here and that log is read again from its last 20,000 lines. |
| `journal_since` | Unix time | position in the systemd journal (only if there is no mail log file). |
| `last_scan` | empty; its modification time counts | new PHP files in upload folders are files newer than this. |
| `webshell_scan` | empty; its modification time counts | the daily scan for suspicious code looks only at PHP files changed since then. |

## Daily checks

| File | Content |
|---|---|
| `daily_date` | the day (YYYY-MM-DD) the daily checks last ran – they run in the first run of a new day. Delete it to run them again in the next run. |
| `daily.txt` | their output, repeated in every report of that day under DAILY CHECKS. |
| `daily_alerts.txt` | their alerts, repeated in every report of that day. |

## Other

| File / folder | Content |
|---|---|
| `out/` | the reports and `summary.txt`, kept for `LOCAL_KEEP_DAYS`. `summary.txt` is built from these files. |
| `geoip/` | the DB-IP Lite databases for country and network operator (`GEOIP_DIR`), refreshed monthly. |
| `lock` | lock file, so that only one run at a time is active (it is never deleted). |
| `running` | exists only while a run is active: `PID start now step exit-code`. If it is still there at the next run, that run did not finish, and the report says so (alert "Script: …"). |
| `tmp.*` | temporary files of the current run, removed at its end. |
| `README.txt` | this description. |
