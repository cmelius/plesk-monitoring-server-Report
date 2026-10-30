# plesk-server-report

A single bash script that writes an **hourly health and security report** for a Plesk server and (optionally) uploads it to cloud storage with [rclone](https://rclone.org/).

It is built around the most common way a shared Plesk server gets into trouble: **a compromised mailbox or a hacked website starts sending spam**, the server IP ends up on a blocklist, and every customer's mail bounces. The report is short, plain text and readable by a human or by an AI assistant that summarises it for you once a day.

The script only **reads** logs and system state. It never changes the server configuration, mail queue or websites.

> **Built with Claude.** This script was written together with [Claude](https://claude.ai) (Anthropic) and tested against a production Plesk server. On that server, Claude also reads the uploaded reports every morning as a scheduled task, through a Google Drive connector linked to a dedicated account, and sends a push notification when something needs attention. See [Reading the reports](#reading-the-reports). Findings from these daily reviews flow back into the script, see [Updates](#updates).

---

## What the report covers

**Hourly (only log lines written since the previous run):**

| Area | Checks | Alerts when … |
|---|---|---|
| **Outgoing mail / spam** | recipients per sender, mails per authenticated mailbox, distinct client IPs per mailbox, **login ≠ sender domain**, mails injected by scripts (PHP `mail()`, per Plesk subscription), **mail sent through Roundcube webmail** (mailbox, real client IP, recipients), failed webmail logins, deferred/bounced, queue size | a mailbox suddenly sends a lot, is used from many IPs, sends with foreign `From` domains, a website's scripts send mass mail, or a webmail user sends after repeated failed logins |
| **Reputation** | server IP against Spamhaus, SpamCop, Barracuda, PSBL; remote rejections mentioning blocklists | the server IP is listed or recipients reject because of reputation |
| **Brute force** | failed SMTP/IMAP/POP3 logins, most attacked mailboxes, fail2ban jails | failures spike |
| **Intrusion** | successful SSH and Plesk panel logins, **new PHP files in `wp-content/uploads`**, **successful WordPress logins during a brute-force attack** | a login comes from a never-seen IP, a PHP file appears in an upload folder, or an IP logs in to WordPress after repeated failures |
| **Geolocation** (optional) | country and network operator of every IP with a successful login (mailboxes, SSH, Plesk panel, WordPress) and of the top failed-login IPs, datacenter networks marked, from a **local** database, so no IP leaves the server | a mailbox sends mail, or someone logs in, from a country outside `ALLOWED_COUNTRIES` |
| **System** | load, CPU per system user (= subscription), RAM, disks, failed systemd units, OOM killer | thresholds are exceeded |
| **Web** | requests, 5xx errors, WordPress login POSTs and busiest IP per domain, login-attack details (distinct IPs, wp-login vs. xmlrpc, successful logins, whether xmlrpc.php is blocked), PHP fatal errors with the first message | a domain throws many 5xx/fatal errors or gets hammered |

**Once a day (first run after midnight):** pending (security) updates and reboot-required, TLS certificates of all Plesk domains and the panel (expiry < 14 days), age and status of the latest **Plesk backup**, Acronis agent (if installed), and **SPF, DKIM and DMARC of every domain with mail service**: does SPF allow this server (including `include:`, `a`, `mx`), does the DKIM key in DNS match the key Plesk signs with, is there a DMARC policy, and where are MX and DNS hosted. That last part is especially useful for domains whose DNS you don't manage yourself. SPF errors that make receivers reject mail outright are flagged too: several SPF records, more than 10 DNS lookups, or `+all`.

**Also once a day, server and domain DNS:**
- **reverse DNS (PTR)** of the server IP, forward-confirmed, and whether Postfix's HELO name resolves to the server. Without a PTR record, Gmail, Microsoft and others reject mail from *all* domains on the server.
- **IPv6** (automatic, only if the server has a global IPv6 address and Postfix uses it): PTR for IPv6, and SPF also evaluated for the IPv6 address
- **certificates of the mail server** on ports 25/587 (STARTTLS), 465, 993 and 995: valid for the host name mail clients use (`MAIL_TLS_NAME`, default: the server's host name), and expiry
- per Plesk domain: does the website **still point to this server** (moved domains, CDNs), does a **CAA** record block Let's Encrypt renewals, does the domain resolve at all (**broken DNSSEC**, dead name servers), and is the domain **listed on Spamhaus DBL / SURBL** (typical for hacked sites serving phishing)

### Example report (fictional data)

```
Server report host.example.com – 2026-10-26 10:05 UTC
STATUS: WARNING (6)
 ! Mail: mailbox info@shop.example submitted 140 mails after logins from outside DE AT CH: 192.0.2.15 (BR, Example Cloud Ltd [datacenter]) 203.0.113.99 (VN, Example Telecom) – password compromised?
 ! Mail: mailbox info@shop.example used from 12 different IPs – password compromised?
 ! Mail: mailbox info@shop.example sent 140 mails with a foreign sender domain – spam?
 ! Web: 2 new PHP file(s) in wp-content/uploads – possible malware
 ! Web: blog.example logged 48 PHP fatal errors
 ! Updates: 3 security update(s) pending

== MAIL ==
Source: /var/log/maillog, 5212 new lines
Delivered: 162 | deferred: 3 | bounced: 1 | queue: 4
Rejections mentioning blocklist/reputation: 0
DNS blocklists for 203.0.113.10: zen.spamhaus.org:clean bl.spamcop.net:clean b.barracudacentral.org:clean psbl.surriel.com:clean

Top senders (total recipients):
     700  support@bank-secure.example
      12  office@agency.example
       6  <> (bounce)
       4  newsletter@shop.example

Authenticated mailboxes (mails, distinct IPs; IPs with country/operator, mails per IP):
     140  12 IPs  info@shop.example
          192.0.2.15 (BR, Example Cloud Ltd [datacenter]) ×61, 203.0.113.99 (VN, Example Telecom) ×40, 192.0.2.201 (BR, Example Cloud Ltd [datacenter]) ×20, 198.51.100.4 (DE, Example Telekom AG) ×3, …
       9   1 IPs  office@agency.example
          198.51.100.20 (DE, Example Telekom AG) ×9
       3   1 IPs  jane@lawfirm.example
          198.51.100.44 (AT, Example Kabel GmbH) ×3

Mailboxes sending with a foreign sender domain (login ≠ from):
     140  info@shop.example – e.g. support@bank-secure.example

Mails sent by scripts (system user = subscription):
       4  uid 10012  shopexample  /var/www/vhosts/shop.example
       2  uid 30  popuser  /var/qmail/popuser
       1  uid 999  psaadm  /opt/psa/admin

Failed mail logins: SMTP 64 | IMAP/POP3 3 – top IPs:
       9  192.0.2.200 (NL, Example Hosting B.V. [datacenter])
       3  198.51.100.66 (US, Example Cloud Ltd [datacenter])
       1  203.0.113.45 (CN, Example Telecom)
Most attacked mailboxes (failed SMTP logins):
       8  admin@agency.example
       4  info@lawfirm.example
       3  jane

Webmail (Roundcube) – mails sent (mails, recipients, IPs):
       4      5 rcpt   1 IPs  office@agency.example
          198.51.100.20 (DE, Example Telekom AG) ×4
Failed webmail logins: 12 – top IPs:
       7  192.0.2.200 (NL, Example Hosting B.V. [datacenter])
       2  203.0.113.80 (US, Example Cable Inc.)
Most attacked mailboxes (failed webmail logins):
       9  info@lawfirm.example
       3  admin@agency.example

== SYSTEM ==
Load: 0.42 / 0.37 / 0.30 (1/5/15 min) on 8 cores | up 12 days, 4 hours, 10 minutes
%Cpu(s):  3.1 us,  1.0 sy,  0.0 ni, 95.6 id,  0.2 wa,  0.0 hi,  0.1 si,  0.0 st

CPU per system user (snapshot):
    12.9 %  shopexample
     4.2 %  mysql
     2.1 %  root

Top processes:
    8.6 %  shopexample  php-fpm
    4.2 %  mysql        mariadbd
    4.3 %  shopexample  php-fpm
    1.3 %  root         fail2ban-server

RAM: 11240 of 16000 MB available (70 %) | swap used: 0/2047 MB

Filesystems:
   41%  /
    8%  /boot/efi

== FAIL2BAN ==
  plesk-modsecurity            banned:  15 (total 612), currently failed: 31
  plesk-postfix                banned:   2 (total 221), currently failed: 174
  plesk-wordpress              banned:   0 (total 114), currently failed: 4
  recidive                     banned: 286 (total 561), currently failed: 242
  ssh                          banned:   5 (total 1251), currently failed: 20
  (jails without bans/failures hidden)

== WEB (since last run) ==
requests | 5xx | login POSTs | domain | busiest IP
      562     2      0  shop.example  198.51.100.30 (472)
      310    51      0  blog.example  192.0.2.80 (40)
      188     0    122  agency.example  203.0.113.150 (160)
       95     0      0  lawfirm.example  198.51.100.12 (23)

WordPress login attacks (domains with at least 20 login POSTs):
  agency.example: 122 POSTs from 54 IPs (busiest 203.0.113.150 (20))
    wp-login.php: 80, successful (302): 1 | xmlrpc.php: 42, blocked (4xx): 0 – xmlrpc.php is NOT blocked
    successful wp-login from: 198.51.100.200 (DE, Example Telekom AG), 0 failures before

PHP fatal errors (count, domain, first message):
     48  blog.example – Uncaught Error: Call to undefined function create_function() in /var/www/vhosts/blog.example/httpdocs/wp-content/plugins/old-slider/slider.php:12

== WEBROOTS: PHP files in upload folders ==
New since last run: 2
  /var/www/vhosts/shop.example/httpdocs/wp-content/uploads/2026/10/cache.php
  /var/www/vhosts/shop.example/httpdocs/wp-content/uploads/2026/10/wp-tmp.php

== SUCCESSFUL LOGINS (SSH, Plesk panel) ==
     2× SSH   root           from 198.51.100.200   (publickey)  DE, Example Telekom AG
     1× Plesk admin          from 198.51.100.200   (panel)  DE, Example Telekom AG

== SERVICES ==
Failed units: none
OOM killer: none

== DAILY CHECKS ==
As of: 2026-10-26 01:05 UTC
Updates available: 11, security updates: 3
  libssl3t64
  openssl
  openssh-server

TLS certificates:
  all valid certificates are good for at least 14 more days
  no matching certificate (e.g. no SSL, mail-only, redirect): mail-only.example parked.example

Server DNS (reverse DNS / HELO):
  203.0.113.10 → host.example.com: ok (forward-confirmed)
  Postfix HELO name: host.example.com (resolves to this server, matches PTR)
  IPv6: not used for mail (CHECK_IPV6=auto)

Mail server certificates for host.example.com:
  port 25: name ok, valid 61 more days
  port 465: name ok, valid 61 more days
  port 587: name ok, valid 61 more days
  port 993: name ok, valid 61 more days
  port 995: name ok, valid 61 more days

Domain DNS (points here? CAA, DNSSEC, domain blocklists):
  moved.example: website points elsewhere (192.0.2.77, NL, Example Hosting B.V. [datacenter]) – moved? CDN?
  39 domain(s) checked, findings listed above

Mail authentication (SPF / DKIM / DMARC):
  nails.example                SPF fail | DKIM MISSING  | DMARC missing      | MX here | DNS ns1.other-provider.example
  38 domain(s) OK, 1 with findings. Alert only if SPF and DKIM both fail and the MX points here;
  a single missing/outdated record is a recommendation (DMARC passes if SPF or DKIM passes).
  DNS queried via 1.1.1.1

Backups:
  Plesk backup: last run 7 h ago (backup-2026-10-26-03-15-02-123), status: OK (exit code 0)
  Acronis agent: running

IP geolocation: DB-IP.com Lite databases (CC BY 4.0)
```

The report above is what a hijacked mailbox and a hacked WordPress site look like: one mailbox, used from twelve different IPs, suddenly sends 140 mails pretending to be a bank, and two PHP files show up in the uploads folder of the same customer.

---

## Requirements

- Plesk Obsidian on Linux with Postfix (tested on Debian; Ubuntu should work the same; RHEL-based systems are partially supported: updates via `dnf`, SSH logins via `/var/log/secure`)
- root access, `bash`, `awk`, `openssl`, `procps` (`top`, `free`) – all present on a standard Plesk server
- optional: `fail2ban` (Plesk component), `rclone` for the upload, `mmdblookup` for geolocation (see below)

---

## Installation

```bash
curl -fsSL -o /usr/local/sbin/plesk-server-report.sh \
  https://raw.githubusercontent.com/cmelius/plesk-monitoring-server-Report/main/plesk-server-report.sh
chmod 700 /usr/local/sbin/plesk-server-report.sh

# read it before you run it as root
less /usr/local/sbin/plesk-server-report.sh

# optional, recommended: geolocation of login IPs
apt install mmdb-bin            # RHEL-based: dnf install libmaxminddb (EPEL)

# first test run: prints the report, uploads nothing
/usr/local/sbin/plesk-server-report.sh --no-upload
```

**Geolocation:** with `mmdblookup` installed, the script downloads the free [DB-IP Lite](https://db-ip.com/db/lite.php) country and ASN databases (a few MB each) on the first run into `/var/lib/plesk-server-report/geoip` and refreshes them once a month. This needs outbound HTTPS to `download.db-ip.com`. Lookups are done locally, so no IP address is sent to any service. Without `mmdblookup` the script works as before and says so at the end of the report. To get **alerts**, set your customers' countries (see [Configuration](#configuration)):

```bash
echo 'ALLOWED_COUNTRIES="DE AT CH"' >> /etc/plesk-server-report.conf
```

The **first run** reads the last 20,000 lines of each log and lists all existing PHP files in upload folders, so it may contain warnings about older events. Review them once (see [First run](#first-run)). From the second run on, only new lines are analysed.

Then set up the storage (next section) and the cron job:

```bash
echo '5 * * * * root /usr/local/sbin/plesk-server-report.sh' > /etc/cron.d/plesk-server-report
chmod 644 /etc/cron.d/plesk-server-report
```

---

## Storage for the reports

> ### ⚠️ Use a dedicated account
> Reports contain **IP addresses, mailbox names and email addresses** – personal data (GDPR!) and a map of your server's weak spots. Create a **separate account or bucket used only for these reports**, not your personal or company drive. This way:
> - a stolen rclone token on the server only exposes the reports,
> - anything (human or AI assistant) you give read access to sees the reports and nothing else,
> - you can delete everything in one go.
>
> Never share the folder with "anyone with the link".
>
> **No AI review? Then your own account can be fine,** as long as the token on the server is limited to the report files and the folder is never shared:
> - **Google Drive with scope `drive.file`:** rclone only sees files it created itself. A stolen token exposes the reports, not the rest of your drive. A folder in your own account is acceptable.
> - **S3/B2 with a bucket-limited key, or SFTP with a chrooted user:** same, the key only reaches the report bucket or directory.
> - **OneDrive or Nextcloud/WebDAV:** the token or app password usually grants access to the **whole** account. Keep a dedicated account here.
>
> As soon as an AI assistant (or anyone else) gets read access, use a dedicated account. Connectors typically see the entire account, not just one folder.

The upload target is the rclone remote in `REMOTE` (default `reports:server-reports/<hostname>`). After every run the script uploads `report-YYYYMMDD-HHMM.txt`, overwrites `latest.txt` and deletes reports older than `RETENTION_DAYS` (default 7). Set `REMOTE=""` to keep reports only locally (in `/var/lib/plesk-server-report/out`).

Install rclone with `apt install rclone` (Debian/Ubuntu) or `dnf install rclone` (RHEL-based, from EPEL). If your distribution's version is very old, see [rclone.org/install](https://rclone.org/install/).

### Option A: Google Drive (headless server)

1. Create a new Google account just for the reports.
2. On the server run `rclone config` and answer:

   | Prompt | Answer |
   |---|---|
   | `n/s/q>` | `n` (new remote) |
   | `name>` | `reports` |
   | `Storage>` | `drive` (Google Drive) |
   | `client_id>` / `client_secret>` | Enter (empty). Fine for one small upload per hour; for heavy use [create your own client ID](https://rclone.org/drive/#making-your-own-client-id). |
   | `scope>` | **`drive.file`**: rclone can only see files it created itself, not the rest of the drive |
   | `service_account_file>` | Enter |
   | `Edit advanced config?` | `n` |
   | `Use web browser to automatically authenticate?` | **`n`**, the server has no browser |

3. rclone now prints a command like `rclone authorize "drive" "eyJ..."`. Run it **on your desktop** (install rclone there, e.g. `winget install Rclone.Rclone`, `brew install rclone`), log in **with the dedicated Google account** and allow access.
4. Copy the token printed on your desktop (`{"access_token":...}`) and paste it on the server at `config_token>`.
5. `Configure this as a Shared Drive?` → `n`, then `y` to save and `q` to quit.
6. Test:
   ```bash
   rclone mkdir reports:server-reports
   rclone lsd reports:
   ```

Deleted reports are removed permanently, not moved to the Drive trash.

### Option B: Microsoft OneDrive

Same flow as Google Drive: `rclone config` → `onedrive`, answer `n` to auto config, run `rclone authorize "onedrive"` on your desktop and log in with a **dedicated Microsoft account**. The token usually grants access to the whole OneDrive, which makes the dedicated account even more important. See [rclone.org/onedrive](https://rclone.org/onedrive/).

> **In the commands below, replace everything in `<ANGLE BRACKETS>`** with your provider's values. They are placeholders, not working defaults.

### Option C: S3-compatible object storage (AWS S3, Backblaze B2, Wasabi, Hetzner, IONOS, …)

The cleanest option security-wise: an access key that can **only write into one bucket**.

```bash
rclone config create reports s3 provider Other \
  access_key_id <ACCESS_KEY_ID> secret_access_key <SECRET_ACCESS_KEY> \
  endpoint <https://S3-ENDPOINT-OF-YOUR-PROVIDER> region <REGION>
```

- Your provider's documentation lists the endpoint and region (for AWS itself use `provider AWS` and omit `endpoint`).
- With S3 the remote path **must start with the bucket name**. Put this in `/etc/plesk-server-report.conf`: `REMOTE="reports:<BUCKET>/${HOST}"`
- Create a dedicated bucket and a key restricted to that bucket.
- Ideally the key has **no delete permission**. Then set `RETENTION_DAYS=0` and let a **bucket lifecycle rule** delete objects after 7 days.
- Keys without permission to create buckets need `RCLONE_S3_NO_CHECK_BUCKET=true` (e.g. as a line `export RCLONE_S3_NO_CHECK_BUCKET=true` in the config file).
- Backblaze B2 natively: `rclone config create reports b2 account <KEY_ID> key <APPLICATION_KEY>` with an application key limited to the bucket. The remote path also starts with the bucket here: `REMOTE="reports:<BUCKET>/${HOST}"`

### Option D: SFTP (Hetzner Storage Box, your own NAS, another server)

```bash
# 1. key pair for the upload, without passphrase (cron has to use it unattended)
ssh-keygen -t ed25519 -N '' -f /root/.ssh/report_upload
# 2. put /root/.ssh/report_upload.pub into ~/.ssh/authorized_keys of <SFTP_USER> on the target
# 3. create the remote
rclone config create reports sftp host <SFTP_HOST> port <PORT, usually 22> user <SFTP_USER> \
  key_file /root/.ssh/report_upload
rclone lsd reports:
```

Use a dedicated user that is chrooted or limited to one directory (e.g. a Storage Box sub-account). The remote path is relative to that user's home directory, so the default `REMOTE="reports:server-reports/${HOST}"` works as is.

### Option E: Nextcloud / WebDAV

```bash
rclone config create reports webdav vendor nextcloud \
  url https://<YOUR-NEXTCLOUD>/remote.php/dav/files/<NEXTCLOUD_USER> \
  user <NEXTCLOUD_USER> pass "$(rclone obscure '<APP_PASSWORD>')"
```

Use a dedicated Nextcloud user and an app password (*Personal settings → Security → Devices & sessions*). For other WebDAV servers use `vendor other` and your server's WebDAV URL.

---

## Reading the reports

- **Yourself:** open `latest.txt`. The first lines tell you everything: `STATUS: OK` or `STATUS: WARNING (n)` followed by the list of alerts.
- **With an AI assistant (this is how the author uses it, with Claude):** connect an assistant that supports your storage (e.g. a Google Drive or OneDrive connector) **to the dedicated account** and let it review the last 24 reports every morning as a scheduled task. Tell it what is normal on your server (known broken sites, mail-only domains, …) so it only reports real changes. Example prompt:

  > List all files in the folder `server-reports/<hostname>`. Read the reports of the last 24 hours (file names contain the UTC time). Report missing reports (gap > 2 h) as an issue. Summarise: outgoing spam signals, blocklist listings, new PHP files in uploads, logins from unknown IPs, failed services, 5xx/PHP errors, pending security updates, expiring certificates, backup status. Start with "All OK" or "Action required: …", max. 10 bullet points with a concrete next step. Read only, change nothing.

- A daily review **does not replace real-time alerting**. For "server down" use an uptime monitor (e.g. Plesk 360 Monitoring, Uptime Kuma), and set **outgoing mail limits** in Plesk (*Tools & Settings → Outgoing Mail Control*) so a hijacked mailbox is throttled immediately.

---

## Configuration

Override any default in `/etc/plesk-server-report.conf` (bash syntax; it survives script updates):

```bash
REMOTE="reports:server-reports/myhost"   # "" = local only
RETENTION_DAYS=7                         # 0 = never delete remotely
WEB_IGNORE_DOMAINS="legacy.example old.example"   # no web alerts, still listed
UPLOADS_PHP_IGNORE='/uploads/borlabs-cookie/|/uploads/mailchimp-for-wp/debug-log\.php$|/uploads/my-plugin/'
WARN_IPS_PER_MAILBOX=6
WARN_MAILS_PER_SENDER=300
ALLOWED_COUNTRIES="DE AT CH"              # alert on logins from other countries
GEO_TRUSTED_ORGS="Microsoft"             # no country alerts for this operator (see notes)
```

All thresholds apply **per run**. With the hourly cron job that means per hour. The full list is at the top of the script.

| Variable | Default | Meaning |
|---|---|---|
| `WARN_MAILS_PER_SENDER` | 150 | recipients per envelope sender |
| `WARN_MAILS_PER_SASL` | 150 | mails submitted by one authenticated mailbox |
| `WARN_IPS_PER_MAILBOX` | 4 | distinct client IPs per mailbox (raise it if many users roam between networks) |
| `WARN_FROM_MISMATCH` | 10 | mails with a sender domain different from the login's domain |
| `WARN_MAILS_PER_SCRIPT` | 100 | mails via PHP `mail()`/sendmail per subscription |
| `WARN_CPU_USER_PCT` | 80 | CPU of one system user in the snapshot |
| `WARN_5XX_PER_DOMAIN` / `WARN_PHP_FATAL` | 100 / 20 | web errors per domain |
| `WARN_LOGIN_DETAIL` | 20 | show login-attack details for domains with at least this many login POSTs |
| `WARN_LOGIN_BRUTE_FAILS` | 5 | alert when an IP logs in to WordPress successfully after at least this many failures |
| `GEOIP` | 1 | 0 switches geolocation off |
| `ALLOWED_COUNTRIES` | empty | ISO country codes, e.g. `"DE AT CH"`. Successful logins from other countries raise an alert. Empty = annotate only, no alerts |
| `GEO_TRUSTED_ORGS` | empty | regex of network operators exempt from country alerts, e.g. `"Microsoft\|Google"` |
| `GEO_DATACENTER_RE` | list of cloud/hosting providers | operators marked as `[datacenter]` |
| `MAILAUTH_CHECK` | 1 | daily SPF/DKIM/DMARC check, 0 = off (needs `dig`, package `bind9-dnsutils`) |
| `MAILAUTH_SHOW_ALL` | 0 | 1 = list every domain, 0 = only domains with findings |
| `MAILAUTH_IGNORE_DOMAINS` | empty | space-separated domains to skip |
| `MAILAUTH_RESOLVER` | `1.1.1.1` | DNS resolver for the SPF/DKIM/DMARC check, `""` = system resolver (see notes) |
| `DKIM_KEY_DIR` / `DKIM_SELECTOR` | `/etc/domainkeys` / `default` | where Plesk keeps the DKIM private keys (`<dir>/<domain>/<selector>`) and the selector it signs with |
| `MAILNAMES_DIR` | `/var/qmail/mailnames` | Plesk mailbox directory (`<dir>/<domain>/<mailbox>`) |
| `SERVER_DNS_CHECK` | 1 | PTR / HELO / IPv6 check, 0 = off |
| `CHECK_IPV6` | `auto` | `auto` = only if the server has a global IPv6 and Postfix uses it (`inet_protocols`), `1` = always, `0` = never |
| `MAIL_TLS_NAME` | server host name | the host name your customers enter in their mail clients. The mail certificate must be valid for it |
| `MAIL_TLS_PORTS` | `25 465 587 993 995` | ports whose certificate is checked (25/587 via STARTTLS, 143/110 also possible) |
| `DOMAIN_DNS_CHECK` | 1 | per-domain A/AAAA, CAA, DNSSEC and domain-blocklist check, 0 = off |
| `DOMAIN_BLOCKLISTS` | `dbl.spamhaus.org multi.surbl.org` | domain blocklists, queried via the local resolver |
| `WARN_CERT_DAYS` | 14 | certificate expiry warning |
| `WARN_BACKUP_HOURS` | 26 | maximum age of the last Plesk backup |

---

## First run

- **PHP files in `wp-content/uploads`:** the first run lists all existing ones. Some plugins legitimately store PHP files there (Borlabs Cookie and Mailchimp for WP are excluded by default). Add your own to `UPLOADS_PHP_IGNORE`. Anything else deserves a look: this is the classic place for web shells.
- **Logins:** all IPs with a successful SSH/panel login in the current logs are stored as known (`/var/lib/plesk-server-report/known_login_ips`). Every later login from a new IP raises an alert once. Remove lines from that file to "forget" an IP.
- **To repeat the daily checks today:** `rm /var/lib/plesk-server-report/daily_date`
- **For a complete reset:** `rm -rf /var/lib/plesk-server-report`

---

## Notes and limitations

- **Postfix logs `sasl_username` on failed logins too** (recent versions). The script handles this. If you adapt the parsing, keep in mind that a username appearing in the log does not mean the login succeeded.
- **Webmail is analysed from Roundcube's own logs** (`/var/log/plesk-roundcube/sendmail` and `errors`), because Roundcube talks to Postfix and Dovecot from `localhost`: in the mail log those mails carry neither the user's IP nor (on Plesk) the mailbox name. Without this section, a hijacked mailbox sending spam through webmail would be invisible. Roundcube does not log successful logins by default (`log_logins = false`). The script doesn't need them, since every sent mail is logged with mailbox and IP. Leave that Plesk-managed config alone.
- **"Top senders" includes incoming mail** (e.g. newsletters from Amazon SES). The *authenticated mailboxes*, *login ≠ from* and *scripts* sections are the ones that show what your server sends on behalf of your users.
- **Spamhaus** refuses queries coming through large public DNS resolvers. The report then shows `query-refused`, which means "unknown", not "listed". Use a local resolver for reliable results.
- **Plesk panel logins** are matched best-effort in `/var/log/plesk/panel.log`, whose format differs between versions. SSH logins are reliable.
- **TLS check** connects to the server's public IPv4. Domains that are mail-only, redirected elsewhere or without SSL are listed as "no matching certificate". That line is informational, not an alert.
- **Backup check** covers Plesk's own backup manager (status from `backup.log` in the PMM log directory). Provider-side snapshots are not visible to the script, except whether an Acronis agent is running.
- **WordPress login success** is derived from the HTTP status: a successful `wp-login.php` POST returns `302`, a failed one `200`. Security plugins that change the login flow (custom login URLs, 2FA, CAPTCHAs) may change these codes. Logins via `xmlrpc.php` always return `200`, so their success cannot be told from the access log. Block `xmlrpc.php` if you don't need it (Plesk: *WordPress Toolkit → Security*).
- **Country alerts and mail apps:** some apps connect to your mail server **from their provider's cloud**, not from the user's device. The Outlook app (iOS/Android) for IMAP accounts uses Microsoft servers, Gmail's "send mail as" uses Google servers, both often outside your country. Those logins show up as `[datacenter]` in another country. If your customers use such apps, add the operator to `GEO_TRUSTED_ORGS`, accepting that attackers on that cloud are then not flagged by country (the IP count and login ≠ from checks still apply). Geolocation is an additional signal, not proof: attackers can use VPNs in your country.
- **Mail certificate name:** if your customers enter something other than the server's host name in their mail clients (e.g. `mail.example.com`), set `MAIL_TLS_NAME` to that name. A name mismatch shows up in clients as a certificate warning, and many users click it away.
- **Domain DNS:** "website points elsewhere" is informational: a domain moved to another host, or sits behind a CDN such as Cloudflare. The CAA check only runs for domains whose current certificate comes from Let's Encrypt. Domain blocklists (Spamhaus DBL, SURBL) refuse queries from large public resolvers, just like the IP blocklists, so they are queried through the local resolver.
- **Public resolver for the SPF/DKIM check:** on Plesk servers the system resolver often gives wrong answers for this check. systemd-resolved (`127.0.0.53`) returns no MX/TXT records for the server's own hostname, and a local Plesk BIND may answer from zones that exist in Plesk while the domain's real DNS is hosted elsewhere. The check therefore asks `1.1.1.1` by default (`MAILAUTH_RESOLVER`). If outbound DNS is blocked, set another resolver or `""`.
- **SPF/DKIM check** covers every domain with a Plesk mail directory or DKIM key. An **alert** is raised only when the domain's MX points to this server (its users send through this server) **and neither SPF nor DKIM passes**. In that case DMARC fails and mails are likely rejected or marked as spam. If only one of them fails, DMARC still passes, so the domain is listed as a recommendation without an alert. Domains whose mail is hosted elsewhere are listed for information only. SPF evaluation is simplified: `ip4`, `a`, `mx`, `include` and `redirect` are followed (up to 10 levels), `ptr`/`exists`/macros and IPv6 are not. A `fail` therefore means "this server's IPv4 is not covered"; verify with an online SPF checker before contacting the domain owner. DKIM is compared byte for byte: `MISMATCH` usually means the key was regenerated in Plesk but the DNS record (often at an external DNS provider) was not updated.
- **DB-IP Lite** data is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The attribution line at the end of every report satisfies this. Country accuracy is high, city data is not used.
- The CPU section is a 3-second snapshot, not an average.
- Report timestamps use the server's time zone (`timedatectl` shows it).

---

## Security

- Runs as root because it needs to read all logs. It writes only to `/var/lib/plesk-server-report` (mode 700) and to the configured rclone remote.
- No external calls apart from DNS blocklist lookups and the rclone upload.
- The rclone config (`/root/.config/rclone/rclone.conf`) contains the token for the storage account. That is another reason to use a dedicated account with the narrowest possible scope (`drive.file`, bucket-limited keys, chrooted SFTP user).

---

## Using another CMS? Help wanted

Everything except two checks works with any software: mail, blocklists, system, services, fail2ban, 5xx and PHP errors, certificates, backups and geolocation. The two checks below currently understand **WordPress only**, because that is what runs on the author's server:

- **login-attack analysis** (`wp-login.php` / `xmlrpc.php`, detection of successful logins by HTTP status code)
- **PHP files in upload folders** (`wp-content/uploads`)

Other applications popular on Plesk (Joomla, Drupal, TYPO3, PrestaShop, Shopware, Magento, Nextcloud, …) use different login URLs, status codes and upload folders. Guessing them would produce false alarms. Joomla answers a successful login with `303` instead of `302`, for example, and Nextcloud redirects on failed logins too.

**If you run one of them, you can help:** open an issue with the template [*Support for another CMS / application*](../../issues/new?template=cms-support.yml). It asks for exactly what is needed:

- software and version, Plesk version, OS
- the login URL of the admin area
- a few **anonymized** access-log lines of a successful login, a failed login and (if available) an attack
- the upload folders and any legitimate PHP files inside them

The template includes a one-line command that anonymizes the log lines (IPs → `203.0.113.x`, domain → `example.com`). **Please never post real IPs, domains or user names. Issues are public.**

---

## Updates

The script runs on a production Plesk server with about 40 domains and is **actively maintained**. Every morning the reports are reviewed (see [Reading the reports](#reading-the-reports)). When a review shows a blind spot, a false alarm or a recommendation the script could have handled itself, the script is updated. New findings about attacks, log formats or Plesk behaviour go in as well. Real-world examples so far:

- a distributed WordPress brute-force attack led to the *WordPress login attacks* section (distinct IPs, wp-login vs. xmlrpc, detection of successful logins after failures),
- a daily check that silently missed data under cron led to the fixed `PATH`,
- Postfix logging `sasl_username` on failed logins initially caused false "compromised mailbox" alarms, which has been fixed.

To update, download the script again (your settings in `/etc/plesk-server-report.conf` and the state in `/var/lib/plesk-server-report` are kept):

```bash
curl -fsSL -o /usr/local/sbin/plesk-server-report.sh \
  https://raw.githubusercontent.com/cmelius/plesk-monitoring-server-Report/main/plesk-server-report.sh
```

Watch the repository (*Watch → Custom → Releases* or *All activity*) to get notified about changes. Issues and pull requests with your own findings are welcome.

### Changelog

- **2026-10-30**: fix: link-local IPv6 (`fe80::`) was taken as the server's public IPv6, so every domain got `v6:fail`. Now only a global, non-ULA address counts, and the IPv4 and IPv6 SPF results are evaluated separately
- **2026-10-30**: server DNS (PTR, forward-confirmed, HELO name, optional IPv6), mail server certificates on all mail ports for the client host name, per-domain DNS (still pointing here, CAA vs. Let's Encrypt, broken DNSSEC/SERVFAIL, Spamhaus DBL/SURBL), SPF hard errors (multiple records, >10 lookups, `+all`), SPF for IPv6
- **2026-10-30**: SPF/DKIM check queries a public resolver (systemd-resolved returned empty answers for the server's own hostname); alert only when SPF *and* DKIM fail (DMARC logic), single failures listed as recommendations
- **2026-10-30**: daily SPF/DKIM/DMARC check for all mail domains (DKIM key in DNS compared with the Plesk key, SPF evaluated against this server's IP, MX and DNS hoster shown), paths configurable
- **2026-10-29**: Roundcube webmail analysis (mails sent per mailbox with real client IP, recipients and geolocation, failed webmail logins, alerts for mass sending, foreign countries and sending after repeated failed logins); issue template for other CMS; optional geolocation (country + network operator, local DB-IP Lite database, monthly refresh) for successful logins and top failed-login IPs, alerts via `ALLOWED_COUNTRIES` for mailboxes, SSH, Plesk panel and WordPress logins from unexpected countries; WordPress login-attack analysis with brute-force success detection; full `PATH` for cron runs (Plesk domain list for the TLS check and the mail queue size were missing under cron)
- **2026-10-26**: first public version

---

## License

MIT. Use at your own risk. Contributions, parsers for other log formats and threshold experiences are welcome.
