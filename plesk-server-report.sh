#!/bin/bash
# =============================================================================
# plesk-server-report.sh
#
# Hourly health & security report for Plesk servers (Linux, Postfix with Dovecot or Courier).
#
# Focus: outgoing spam from compromised mailboxes or hacked websites, CPU/RAM,
# plus brute-force noise, fail2ban, web errors, successful logins, new PHP files
# in upload folders, failed services, OOM kills, DNS blocklists, Plesk backup
# status – and once a day: pending updates and expiring certificates.
# Mail sent through Roundcube webmail is analysed separately (its SMTP
# connections come from localhost and are invisible in the mail log).
# Web logs are also scanned for attack patterns, probes for sensitive files, traffic
# peaks and ModSecurity hits; once a day the document roots are searched for exposed
# files (.env, .git, dumps, backups) and recently changed PHP files for webshell code,
# .htaccess/.user.ini for settings that run attacker code. Plesk's own log adds failed
# panel logins and failed certificate renewals; devices with an outdated mail password
# are reported before fail2ban bans their connection.
# Successful logins are annotated with country and network operator (local
# GeoIP database, optional alerts for logins from unexpected countries).
# What an attacker leaves behind is watched too: new SSH keys, accounts with a login
# shell, sudo rights, cron jobs and autostart entries, processes started from /tmp or
# deleted binaries, new listening ports. The script only reads – it changes and blocks nothing.
#
# Only log lines written since the previous run are analysed. The resulting
# plain-text report is stored locally and (optionally) uploaded with rclone to
# any storage backend rclone supports (Google Drive, OneDrive, S3, SFTP, ...)
# and/or mailed to an address – ideally a mailbox on this server (REPORT_MAIL_TO).
#
# Run as root from cron, e.g. hourly:
#   5 * * * * root /usr/local/sbin/plesk-server-report.sh
#
# Options:
#   --no-upload       print the report to stdout; nothing is uploaded or mailed
#   --only CHECK,...  run only these checks right now and print the result; nothing
#                     is uploaded and no state is changed (log offsets, known IPs, …)
#   --list            list the check names for --only
#   --summary         print the summary of the last SUMMARY_HOURS from the stored reports (runs no checks)
#   --show-state      show what the script remembers (known IPs, countries, log positions)
#                     in readable form; changes nothing
#   --state-readme    print the description of the state files (also kept as README.txt
#                     in the state directory)
#   --pseudonymise FILE  print FILE (e.g. a local report) with the mail addresses
#                     pseudonymised as MASK_MAILBOXES=1 would upload it; uploads nothing
#   --decode [PSEUDONYM ...]  with MASK_MAILBOXES=1: the real address of a pseudonym
#                     (mbx-…@domain); without arguments it reads a text from stdin, e.g. an
#                     AI review, and prints it with the real addresses
#   --test-mail       mail the newest report to REPORT_MAIL_TO now and show from the mail
#                     log whether it was delivered; changes nothing
#   --version         print the version
#   --help            show this help
#
# Settings: edit the defaults below or – recommended, survives updates –
# override them in /etc/plesk-server-report.conf (plain bash variable syntax).
#
# Layout: settings → helper functions → one function per check (check_<name>) →
# report/upload → main(). The order of the report is defined in main().
#
# Safety: the script runs with low CPU/IO priority, every external command that can hang
# has a time limit (CMD_TIMEOUT, FIND_TIMEOUT), cron runs are stopped after MAX_RUNTIME,
# at most MAX_LOG_MB of each log is read per run, and an aborted or still running
# previous run is reported as an alert instead of being skipped silently.
#
# License: MIT. No warranty – read the code before running it as root.
# =============================================================================

VERSION=1.11.0

set -uo pipefail
export LC_ALL=C
umask 077   # every file the script creates (state, reports, temporary files) is readable by root only
# cron runs with PATH=/usr/bin:/bin – plesk, postqueue, ip etc. live in /usr/sbin
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ---------------------------------------------------------------- defaults
HOST=$(hostname -f 2>/dev/null || hostname)
STATE_DIR=/var/lib/plesk-server-report   # a new or changed state file must be described in state_readme()
REMOTE="reports:server-reports/${HOST}"  # rclone remote:path – empty = local only
RETENTION_DAYS=7                         # delete remote reports older than x days (0 = never)
UPDATE_CHECK=1                           # daily: ask GitHub for the latest release of this script (one HTTPS request; 0 = off)
MASK_MAILBOXES=0                         # 1 = uploaded and mailed reports show mail addresses pseudonymised (mbx-4f2a91@example.com); local reports stay complete, decode with --decode
REPORT_MAIL_TO=""                        # mail reports to this address (several: space-separated); "" = no mails. Recommended: a mailbox on this server – the reports never leave it
REPORT_MAIL="alerts summary"             # what is mailed, one or more words (space-separated): alerts = a report with a new alert right away, summary = summary.txt once a day, all = every report
REPORT_MAIL_HOUR=6                       # the summary mail goes out with the first run from this hour on (server time, 0-23)
REPORT_MAIL_FROM=""                      # sender address of the mails (default: plesk-server-report@<host name>)
LOCAL_KEEP_DAYS=7                        # keep local reports x days (0 = never delete; summary.txt needs at least SUMMARY_HOURS)
SUMMARY=1                                # write summary.txt (all reports of the last SUMMARY_HOURS condensed) and upload it
SUMMARY_HOURS=24
# Limits, so that a hanging command or a huge log can't block the script or fill disk/RAM
MAX_RUNTIME=50                # minutes: an unattended (cron) run is stopped after this – keep it below the cron interval (0 = no limit)
CMD_TIMEOUT=120               # seconds per external command (plesk db, fail2ban-client, postqueue, journalctl, apt-get/dnf, rclone)
FIND_TIMEOUT=600              # seconds per file-system scan of the web folders (find, grep)
IMAP_COUNTRY_KEEP_DAYS=30     # forget a mailbox's foreign country after x days without a login from there (0 = never)
KNOWN_MAIL_IP_DAYS=30         # remember IPs with successful mail logins this long – alert when fail2ban bans one of them
KNOWN_LOGIN_IP_DAYS=90        # forget an SSH/Plesk login IP after x days without a login from it (0 = never)
MAX_LOG_MB=200                # read at most x MB of new lines per log file and run, the newest part (0 = no limit)
VHOST_LOGS=/var/www/vhosts/system        # Plesk per-domain log directories
PLESK_PANEL_LOG=/var/log/plesk/httpsd_access_log   # access log of the Plesk panel (port 8443) – panel logins
PLESK_ERROR_LOG=/var/log/plesk/panel.log           # Plesk's own log – failed panel logins, failed certificate renewals
ROUNDCUBE_LOG_DIR=""          # default: /var/log/plesk-roundcube (or /usr/share/psa-roundcube/logs)

# Alert thresholds – per run (with an hourly cron job: per hour)
WARN_MAILS_PER_SENDER=150     # recipients per envelope sender
WARN_MAILS_PER_SASL=150       # mails submitted per authenticated mailbox
WARN_MAILS_PER_SCRIPT=100     # mails per system user (PHP mail() / sendmail)
WARN_IPS_PER_MAILBOX=4        # distinct client IPs per authenticated mailbox
WARN_FROM_MISMATCH=10         # mails of a mailbox with a foreign sender domain
WARN_DEFERRED=100             # deferred deliveries
WATCH_RECIPIENT_DOMAINS=""    # space-separated recipient domains whose deliveries matter most (e.g. "invoices.example.com"): every deferral or bounce raises an alert
WARN_BLOCKLIST=1              # remote rejections mentioning a blocklist, reputation, spam or rate limiting
WARN_QUEUE=200                # messages in the Postfix queue
WARN_AUTH_FAIL=300            # failed mail logins (SMTP + IMAP/POP3)
WARN_MAILBOX_PCT=95           # daily: mailbox filled to x % of its size limit; 0 = off (full mailboxes rejecting mail are always reported)
WARN_DSN=1                    # delivery confirmations (DSN "delivered") sent to other servers – spammers request them to verify addresses; 0 = off
WARN_OLD_PASSWORD=3           # failed logins of one mailbox from an IP with earlier successful mail logins (outdated password on a device?); 0 = off
WARN_LOAD_FACTOR=1.5          # 5-min load > CPU cores × factor
WARN_CPU_USER_PCT=80          # %CPU of a single system user (snapshot)
WARN_MEM_AVAIL_PCT=10         # available RAM below x %
WARN_DISK_PCT=85              # filesystem usage above x %
WARN_5XX_PER_DOMAIN=100       # HTTP 5xx responses per domain
WARN_LOGIN_POSTS=300          # POSTs to wp-login.php/xmlrpc.php per domain
WARN_LOGIN_DETAIL=20          # show login-attack details for domains with at least x POSTs
WARN_LOGIN_BRUTE_FAILS=5      # successful wp-login after at least x failures from the same IP
WARN_PHP_FATAL=20             # PHP fatal errors per domain
WARN_REQ_PER_MIN=600          # peak requests per minute for one domain (load spike / L7 flood)
WARN_DISTRIBUTED_IPS=100      # one URL requested by at least this many different IPs (botnet pattern)
WARN_CERT_DAYS=14             # certificate expires in less than x days
WARN_BACKUP_HOURS=26          # latest Plesk backup older than x hours

# Daily SPF/DKIM/DMARC check of all domains with mail service (needs dig)
MAILAUTH_CHECK=1              # 0 = off
MAILAUTH_IGNORE_DOMAINS=""    # space-separated domains to skip
# DNS resolver for these checks. A public resolver shows what the world sees; the local
# one (systemd-resolved, Plesk BIND) may answer from local data, e.g. for the server's
# own hostname or for zones that exist in Plesk but are hosted elsewhere. "" = system resolver
MAILAUTH_RESOLVER="1.1.1.1"
MAILAUTH_SHOW_ALL=0           # 1 = list every domain, 0 = only domains with findings
DKIM_KEY_DIR=/etc/domainkeys  # Plesk DKIM private keys: <dir>/<domain>/<selector>
DKIM_SELECTOR=default         # Plesk signs with selector "default"
MAILNAMES_DIR=/var/qmail/mailnames   # Plesk mailboxes: <dir>/<domain>/<mailbox>

# Daily server DNS / mail TLS checks
SERVER_DNS_CHECK=1            # PTR (reverse DNS) of the server IP, HELO name, IPv6
CHECK_IPV6=auto               # auto = only if the server has a global IPv6 and Postfix uses it; 1 = always; 0 = never
MAIL_TLS_NAME=""              # host name mail clients connect to (default: server host name)
MAIL_TLS_PORTS="25 465 587 993 995"   # ports whose certificate is checked (25/587 via STARTTLS)
# Daily per-domain DNS checks (all Plesk domains)
DOMAIN_DNS_CHECK=1            # A/AAAA still pointing here, CAA vs. Let's Encrypt, broken DNSSEC, domain blocklists
DOMAIN_BLOCKLISTS="dbl.spamhaus.org multi.surbl.org"   # queried via the local resolver (public ones are refused)
HTTPS_CHECK=1                 # daily: HSTS header and http→https redirect on domains with a valid certificate (recommendation, no alert)
# Web attack statistics (hourly) and document-root scans (daily)
ATTACK_STATS=1                # SQLi/traversal/RCE/XSS patterns, sensitive-file probes, peaks, ModSecurity
EXPOSED_FILES_CHECK=1         # daily: .env, .git, SQL dumps, backup archives, config copies in document roots
# regex on the full path of findings to ignore; default: SQL schema/upgrade files shipped with software
EXPOSED_FILES_IGNORE='/wp-content/plugins/[^/]+/(sql|schema|install)/|/include/upgrader/streams/|/install(ation)?/schemas/|/doc/[^/]+\.sql$' 
WEBSHELL_CHECK=1              # daily: recently changed PHP files containing typical backdoor code
WEBSHELL_IGNORE=""            # regex on the full path of findings to ignore
WEBSHELL_FIRST_DAYS=7         # first run: scan PHP files changed within this many days
# Access & persistence (hourly): what an attacker leaves behind. Only reads, changes nothing
PERSISTENCE_CHECK=1           # SSH keys, accounts with a login shell, sudo, cron/autostart, suspicious processes, new listening ports
PERSISTENCE_IGNORE=""         # regex on the text of findings to ignore (e.g. a known tool running from /tmp)

DNSBL_LISTS="zen.spamhaus.org bl.spamcop.net b.barracudacentral.org psbl.surriel.com"
WEB_IGNORE_DOMAINS=""         # space-separated domains without web alerts (still listed)
# Known legitimate PHP files inside wp-content/uploads (regex on the full path)
UPLOADS_PHP_IGNORE='/uploads/borlabs-cookie/|/uploads/mailchimp-for-wp/debug-log\.php$'

# GeoIP: country + network operator of IPs from a local DB-IP Lite database
# (downloaded and refreshed monthly by the script). Needs mmdblookup:
#   Debian/Ubuntu: apt install mmdb-bin    RHEL-based: dnf install libmaxminddb (EPEL)
GEOIP=1                       # 0 = off
GEOIP_DIR=""                  # default: $STATE_DIR/geoip
ALLOWED_COUNTRIES=""          # e.g. "DE AT CH": alert on successful logins from other countries ("" = no alerts)
GEO_TRUSTED_ORGS=""           # regex of operators exempt from country alerts, e.g. "Microsoft|Google"
GEO_DATACENTER_RE='amazon|google|microsoft|oracle|digitalocean|ovh|hetzner|linode|akamai|vultr|contabo|alibaba|tencent|huawei|leaseweb|scaleway|m247|choopa|hostinger|hostwinds|colocrossing|datacamp|cloudflare|ionos|strato|netcup|hosting|server|cloud|data ?cent'
# -----------------------------------------------------------------------------

CONF=/etc/plesk-server-report.conf

# Check names in report order. Hourly checks analyse the log lines since the previous run,
# daily checks run once a day and are cached in $STATE_DIR/daily.txt.
HOURLY_CHECKS="mail webmail system fail2ban web uploads logins panel persistence services backups"
DAILY_CHECKS="updates certificates https serverdns mailtls domaindns exposed webshell mailauth mailboxes"

# =============================================================================
# Helper functions
# =============================================================================

# ---------------------------------------------------------------- report output
alert() { ALERTS+=("$*"); }                       # hourly alert → STATUS line
dalert() { echo "$*" >>"$DALERTS"; }              # daily alert, cached with the daily checks
section() { printf '\n== %s ==\n' "$1" >>"$BODY"; }
out() { printf '%s\n' "$*" >>"$BODY"; }
ignored_domain() { [[ " $WEB_IGNORE_DOMAINS " == *" $1 "* ]]; }
num_gt() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a>b)}'; }
# state files (offsets, scan stamps, known IPs) are only written in normal runs – not with --only,
# --summary, or when the previous run still holds the lock
can_write_state() { (( ! ONLY_MODE && ! SUMMARY_ONLY && ! LOCKED_OUT )); }
# note TEXT – data problem (missing log, shortened log), shown as " i " line below the STATUS line
note() {
  [[ -n ${TMPD:-} ]] || return 0
  grep -qxF -- "$*" "$TMPD/notes" 2>/dev/null || printf '%s\n' "$*" >>"$TMPD/notes"
  return 0
}
# T SECONDS COMMAND… – run an external command with a time limit; a timeout becomes an alert
T() {
  local s=$1 rc c; shift
  timeout --foreground -k 10 "$s" "$@"; rc=$?
  if (( rc == 124 || rc == 137 )) && [[ -n ${TMPD:-} ]]; then
    c="$*"; (( ${#c} > 90 )) && c="${c:0:90}…"
    printf 'command timed out after %ss: %s\n' "$s" "$c" >>"$TMPD/timeouts"
  fi
  return $rc
}
timeouts_seen() { if [[ -f ${TMPD:-}/timeouts ]]; then wc -l <"$TMPD/timeouts"; else echo 0; fi; }
# step NAME – remember what the run is doing (shown if the run hangs or is aborted)
step() {
  STEP=$1
  [[ -n ${RUNFILE:-} ]] && can_write_state && printf '%s\t%s\t%s\t%s\n' "$$" "$RUN_START" "$NOW" "$STEP" >"$RUNFILE"
  return 0
}

# ---------------------------------------------------------------- GeoIP
geo_update() {   # download/refresh the DB-IP Lite databases (monthly)
  local kind f m
  mkdir -p "$GEOIP_DIR"
  for kind in country asn; do
    f="$GEOIP_DIR/dbip-$kind-lite.mmdb"
    [[ -s $f && -z $(find "$f" -mtime +35 2>/dev/null) ]] && continue
    for m in "$(date +%Y-%m)" "$(date -d "$(date +%Y-%m-15) -1 month" +%Y-%m)"; do
      # size limits (the real files: a few MB to some 100 MB unpacked), so that a broken or
      # tampered download can't fill the disk; a database that doesn't answer a lookup is not used
      if curl -fsS --max-time 180 --max-filesize 200000000 -o "$f.gz.tmp" "https://download.db-ip.com/free/dbip-$kind-lite-$m.mmdb.gz" 2>/dev/null &&
         gunzip -c "$f.gz.tmp" 2>/dev/null | head -c 500000001 >"$f.tmp" &&
         (( $(stat -c %s "$f.tmp") <= 500000000 )) &&
         mmdblookup --file "$f.tmp" --ip 1.1.1.1 >/dev/null 2>&1; then
        mv "$f.tmp" "$f"; break
      fi
    done
    rm -f "$f.gz.tmp" "$f.tmp"
  done
}
geo_init() {
  GEOIP_DIR=${GEOIP_DIR:-$STATE_DIR/geoip}
  GEO_CC_DB="$GEOIP_DIR/dbip-country-lite.mmdb"; GEO_ASN_DB="$GEOIP_DIR/dbip-asn-lite.mmdb"
  GEO_OK=0; GEO_NOTE=""
  (( GEOIP )) || return 0
  if command -v mmdblookup >/dev/null; then
    geo_update
    if [[ -s $GEO_CC_DB ]]; then GEO_OK=1
    else GEO_NOTE="GeoIP: no database – download from download.db-ip.com failed"; fi
  else
    GEO_NOTE="GeoIP: off – install mmdblookup (Debian/Ubuntu: apt install mmdb-bin)"
  fi
}
declare -A GEO_CACHE=()
# geo IP – sets GEO_CC, GEO_ORG and GEO_LABEL ("DE, Deutsche Telekom AG" / "US, Amazon.com [datacenter]")
geo() {
  local ip=$1 v cc="" org=""
  # the server itself (webmail and local scripts connect from localhost) – not a foreign IP
  if [[ $ip == 127.* || $ip == ::1 || ( -n ${PUBIP:-} && $ip == "$PUBIP" ) ]]; then
    GEO_CC=""; GEO_ORG=""; GEO_LABEL="this server"; return 0
  fi
  if [[ -n ${GEO_CACHE[$ip]+x} ]]; then v=${GEO_CACHE[$ip]}
  else
    if (( GEO_OK )) && [[ $ip =~ ^[0-9a-fA-F:.]+$ ]]; then
      cc=$(mmdblookup --file "$GEO_CC_DB" --ip "$ip" country iso_code 2>/dev/null | awk -F'"' 'NF>2{print $2; exit}')
      [[ -s $GEO_ASN_DB ]] && org=$(mmdblookup --file "$GEO_ASN_DB" --ip "$ip" autonomous_system_organization 2>/dev/null | awk -F'"' 'NF>2{print $2; exit}')
    fi
    v="$cc|$org"; GEO_CACHE[$ip]=$v
  fi
  GEO_CC=${v%%|*}; GEO_ORG=${v#*|}; GEO_LABEL=""
  (( GEO_OK )) || return 0
  GEO_LABEL=${GEO_CC:-??}
  [[ -n $GEO_ORG ]] && GEO_LABEL+=", ${GEO_ORG:0:40}"
  if [[ -n $GEO_ORG ]] && grep -qiE "$GEO_DATACENTER_RE" <<<"$GEO_ORG"; then GEO_LABEL+=" [datacenter]"; fi
  return 0
}
# geo_foreign – after geo(): true if country alerts are on and the IP is outside ALLOWED_COUNTRIES
geo_foreign() {
  (( GEO_OK )) && [[ -n $ALLOWED_COUNTRIES && -n $GEO_CC ]] || return 1
  [[ " $ALLOWED_COUNTRIES " == *" $GEO_CC "* ]] && return 1
  if [[ -n $GEO_TRUSTED_ORGS && -n $GEO_ORG ]] && grep -qiE "$GEO_TRUSTED_ORGS" <<<"$GEO_ORG"; then return 1; fi
  return 0
}

# ---------------------------------------------------------------- domains, document roots, logs
# Document roots of all domains: "domain<TAB>path" (Plesk DB, fallback /var/www/vhosts/<domain>/httpdocs)
docroots() {
  if [[ -z ${DOCROOTS_CACHE:-} ]]; then
    command -v plesk >/dev/null &&
      DOCROOTS_CACHE=$(T "$CMD_TIMEOUT" plesk db -Ne "SELECT d.name, h.www_root FROM domains d JOIN hosting h ON h.dom_id = d.id" 2>/dev/null)
    if [[ -z $DOCROOTS_CACHE && -n $VHOST_LOGS && -d $VHOST_LOGS ]]; then
      local d
      for d in "$(dirname "$VHOST_LOGS")"/*/httpdocs; do
        [[ -d $d ]] && DOCROOTS_CACHE+="$(basename "$(dirname "$d")")"$'\t'"$d"$'\n'
      done
    fi
  fi
  printf '%s\n' "$DOCROOTS_CACHE" | grep -v '^$'
}
docroot_of() { docroots | awk -F'\t' -v d="$1" '$1 == d {print $2; exit}'; }
# All Plesk sites plus the server host name (cached)
site_domains() {
  [[ -n ${SITE_DOMAINS_CACHE:-} ]] ||
    SITE_DOMAINS_CACHE=$( { command -v plesk >/dev/null && T "$CMD_TIMEOUT" plesk bin site --list 2>/dev/null; echo "$HOST"; } | sort -u)
  printf '%s\n' "$SITE_DOMAINS_CACHE"
}

# rotated_file FILE INODE – the rotated copy of FILE that still has INODE (renaming keeps the inode):
# FILE.1 (Debian logrotate), FILE.processed (Plesk's mail log, any distribution), FILE-20261106 (dateext, RHEL)
rotated_file() {
  local c
  for c in "$1".* "$1"-*; do
    [[ -f $c && -r $c && $c != *.gz && $c != *.xz && $c != *.bz2 && $c != *.zst ]] || continue
    [[ $(stat -c %i "$c" 2>/dev/null) == "$2" ]] && { printf '%s\n' "$c"; return 0; }
  done
  return 1
}

# Print only the lines appended to a log file since the previous run.
# Handles log rotation: the rest of the rotated file is read as well, found by its inode
# whatever it is called now (FILE.1, FILE.processed, FILE-date).
# At most MAX_LOG_MB are read (the newest part); more is reported as a note.
new_lines() {
  local f=$1 key st ino size off=0 oino="" ooff=0 rest=0 rsize rf="" max=$(( MAX_LOG_MB * 1048576 ))
  [[ -r $f ]] || return 0
  key=$(printf '%s' "$f" | md5sum | cut -c1-16)
  st="$STATE_DIR/offsets/$key"
  ino=$(stat -c %i "$f"); size=$(stat -c %s "$f")
  if [[ -f $st ]]; then
    read -r oino ooff _ <"$st"
    if [[ $oino == "$ino" && $ooff -le $size ]]; then
      off=$ooff
    elif rf=$(rotated_file "$f" "$oino"); then
      rsize=$(stat -c %s "$rf"); (( rsize > ooff )) && rest=$(( rsize - ooff ))   # rest of the file before rotation
    fi
  else
    # first run: only the last 20,000 lines to keep it fast
    tail -n 20000 "$f" | head -c "$size"
    can_write_state && echo "$ino $size $f" >"$st"
    return 0
  fi
  if (( max > 0 && rest + size - off > max )); then
    note "log $f: $(( (rest + size - off) / 1048576 )) MB new since the last run – only the newest $MAX_LOG_MB MB analysed (MAX_LOG_MB)"
    if (( size - off >= max )); then rest=0; off=$(( size - max )); else rest=$(( max - (size - off) )); fi
  fi
  (( rest > 0 )) && tail -c "$rest" "$rf"
  tail -c +"$((off + 1))" "$f" | head -c "$((size - off))"
  can_write_state && echo "$ino $size $f" >"$st"
  return 0
}

# ---------------------------------------------------------------- server addresses
detect_pubip() {   # public IPv4 used for outgoing connections → PUBIP
  PUBIP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="src") print $(i+1)}')
}
is_public_ipv4() {
  [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && ! $1 =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.) ]]
}
# IPv6 – only relevant if the server has a global IPv6 and Postfix uses it → PUBIP6 (or empty)
detect_pubip6() {
  local v6proto
  PUBIP6=""
  [[ $CHECK_IPV6 != 0 ]] || return 0
  PUBIP6=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="src") print $(i+1)}')
  # only a real public address counts: not link-local (fe80::/10), ULA (fc00::/7) or loopback,
  # and it must be configured with global scope on an interface
  if [[ -n $PUBIP6 ]]; then
    if [[ ${PUBIP6,,} =~ ^(fe[89ab]|f[cd]|::1$|::$) ]] ||
       ! ip -6 -o addr show scope global 2>/dev/null | grep -qiF -- " ${PUBIP6}/"; then PUBIP6=""; fi
  fi
  v6proto=$(postconf -h inet_protocols 2>/dev/null)
  if [[ $CHECK_IPV6 == auto && ( -z $PUBIP6 || ! $v6proto =~ all|ipv6 ) ]]; then PUBIP6=""; fi
  return 0
}

# ---------------------------------------------------------------- DNS, SPF
DIGQ() { dig +short +time=3 +tries=2 ${MAILAUTH_RESOLVER:+"@$MAILAUTH_RESOLVER"} "$@" 2>/dev/null; }
txt_records() { DIGQ TXT "$1" | sed 's/" "//g; s/"//g'; }          # one TXT record per line
ip2int() { local IFS=. a b c d; read -r a b c d <<<"$1"; echo $(( (a << 24) + (b << 16) + (c << 8) + d )); }
in_cidr() {   # in_cidr IP NET[/BITS] – IPv4 natively, IPv6 via python3
  if [[ $1 == *:* || $2 == *:* ]]; then
    [[ $1 == *:* && $2 == *:* ]] || return 1
    command -v python3 >/dev/null || return 1
    python3 -c 'import ipaddress,sys
try: sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2], strict=False) else 1)
except ValueError: sys.exit(1)' "$1" "$2"
    return
  fi
  local net=${2%/*} bits=32 mask
  [[ $2 == */* ]] && bits=${2#*/}
  [[ $net =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && $bits =~ ^[0-9]+$ ]] || return 1
  mask=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
  (( ($(ip2int "$1") & mask) == ($(ip2int "$net") & mask) ))
}
host_has_ip() {   # host_has_ip HOST IP [BITS] – A for IPv4, AAAA for IPv6
  local a rr=A def=32
  [[ $2 == *:* ]] && { rr=AAAA; def=128; }
  for a in $(DIGQ "$rr" "$1" | grep -E '^[0-9a-fA-F.:]+$'); do in_cidr "$2" "$a/${3:-$def}" && return 0; done
  return 1
}
# spf_eval DOMAIN IP – simplified SPF evaluation (RFC 7208 subset), result in SPF_RES:
#   pass | fail | none | permerror:<reason>; SPF_PLUSALL=1 if the record ends in +all
spf_eval() {
  SPF_LOOKUPS=0; SPF_PLUSALL=0
  _spf "$1" "$2" 0
}
_spf() {
  local d=$1 ip=$2 depth=$3 recs n rec t q m arg bits red="" mxh v6=0
  [[ $ip == *:* ]] && v6=1
  if (( depth > 10 )); then SPF_RES="permerror:loop"; return; fi
  recs=$(txt_records "$d" | grep -i '^v=spf1')
  n=$(grep -c . <<<"$recs")
  if [[ -z $recs ]]; then SPF_RES=none; (( depth > 0 )) && SPF_RES="permerror:include-without-spf"; return; fi
  if (( n > 1 )); then SPF_RES="permerror:$n-records"; return; fi
  rec=$recs
  for t in $rec; do
    q=+; [[ $t == [-~?+]* ]] && { q=${t:0:1}; t=${t:1}; }
    m=${t%%[:=/]*}; m=${m,,}; arg=""; bits=""
    [[ $t == *:* && $m != ip6 ]] && arg=${t#*:}
    [[ $m == ip6 ]] && arg=${t#ip6:}
    if [[ $m =~ ^(a|mx)$ && $t == */* ]]; then   # a/24 or a:host/24//64 – take the matching family
      local cidrs=${t#*/}; arg=${arg%%/*}
      if (( v6 )); then bits=${cidrs#*/}; [[ $cidrs == */* ]] || bits=""; else bits=${cidrs%%/*}; fi
    fi
    case $m in
      include|a|mx|ptr|exists) SPF_LOOKUPS=$((SPF_LOOKUPS + 1)) ;;
    esac
    if (( SPF_LOOKUPS > 10 )); then SPF_RES="permerror:>10-dns-lookups"; return; fi
    case $m in
      ip4) (( ! v6 )) && [[ $q == + ]] && in_cidr "$ip" "$arg" && { SPF_RES=pass; return; } ;;
      ip6) (( v6 ))   && [[ $q == + ]] && in_cidr "$ip" "$arg" && { SPF_RES=pass; return; } ;;
      a)   [[ $q == + ]] && host_has_ip "${arg:-$d}" "$ip" "$bits" && { SPF_RES=pass; return; } ;;
      mx)  if [[ $q == + ]]; then
             for mxh in $(DIGQ MX "${arg:-$d}" | awk '{print $2}'); do
               host_has_ip "${mxh%.}" "$ip" "$bits" && { SPF_RES=pass; return; }
             done
           fi ;;
      include) _spf "$arg" "$ip" $((depth + 1))
               [[ $SPF_RES == permerror* ]] && return
               [[ $q == + && $SPF_RES == pass ]] && { SPF_RES=pass; return; } ;;
      redirect) red=${t#*=} ;;
      all) if [[ $q == + ]]; then (( depth == 0 )) && SPF_PLUSALL=1; SPF_RES=pass; return; fi
           SPF_RES=fail; return ;;
    esac
  done
  if [[ -n $red ]]; then SPF_LOOKUPS=$((SPF_LOOKUPS + 1)); _spf "$red" "$ip" $((depth + 1)); return; fi
  SPF_RES=fail
}
dig_status() {   # dig_status NAME TYPE → NOERROR | NXDOMAIN | SERVFAIL | … (via MAILAUTH_RESOLVER)
  dig +time=3 +tries=2 ${MAILAUTH_RESOLVER:+"@$MAILAUTH_RESOLVER"} "$2" "$1" 2>/dev/null |
    sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1
}

# =============================================================================
# Hourly checks (only log lines written since the previous run)
# =============================================================================

check_mail() {   # delivery, senders, mailboxes, login ≠ from, scripts, failed logins, DNS blocklists
  local MAILLOG f last MAILSTATS SENT DEF BOU BL SF DF QUEUE REV BLRES bl r SAIP n nip who line k c ip ex uid user home
  section "MAIL"
  MAILLOG=""
  for f in /var/log/maillog /var/log/mail.log; do [[ -r $f ]] && { MAILLOG=$f; break; }; done

  if [[ -n $MAILLOG ]]; then
    new_lines "$MAILLOG" >"$TMP"
  else
    # no log file (no rsyslog): fall back to the journal
    last=$(cat "$STATE_DIR/journal_since" 2>/dev/null || date -d '-1 hour' +%s)
    if command -v journalctl >/dev/null; then
      T "$CMD_TIMEOUT" journalctl --since "@$last" -o short -u postfix\* -u dovecot -u courier\* 2>/dev/null |
        if (( MAX_LOG_MB > 0 )); then head -c "$(( MAX_LOG_MB * 1048576 ))"; else cat; fi >"$TMP"
      (( MAX_LOG_MB > 0 && $(stat -c %s "$TMP") >= MAX_LOG_MB * 1048576 )) &&
        note "mail journal: more than $MAX_LOG_MB MB since the last run – only the first $MAX_LOG_MB MB analysed (MAX_LOG_MB)"
    else
      : >"$TMP"
      note "mail: no mail log (/var/log/mail.log, /var/log/maillog) and no journal – mail figures are 0"
    fi
    can_write_state && date +%s >"$STATE_DIR/journal_since"
    MAILLOG="journal"
  fi
  out "Source: $MAILLOG, $(wc -l <"$TMP") new lines"

  MAILSTATS=$(awk -v watch="$WATCH_RECIPIENT_DOMAINS" -v self="$REPORT_MAIL_FROM" -v apo="'" '
    # provider of a delivery: the big mail services by their MX host, others by the MX base domain
    function prov(line,   h, r, n, x) {
      h = ""; if (match(line, /relay=[^[, ]+/)) h = tolower(substr(line, RSTART+6, RLENGTH-6))
      if (h == "" || h == "none") { r = line; if (match(r, /to=<[^>]+>/)) { h = tolower(substr(r, RSTART+4, RLENGTH-5)); sub(/.*@/, "", h) } }
      if (h ~ /(outlook|hotmail)\.(com|de)$|protection\.outlook\.com$/) return "microsoft"
      if (h ~ /(google|googlemail|gmail)\.com$/) return "google"
      if (h ~ /(icloud|me|mac)\.com$/) return "apple icloud"
      if (h ~ /(gmx\.net|gmx\.de|web\.de|ionos\.(de|com)|kundenserver\.de|1and1\.[a-z]+)$/) return "gmx/web.de/ionos"
      if (h ~ /t-online\.de$/) return "t-online"
      if (h ~ /(yahoodns\.net|yahoo\.com|aol\.com)$/) return "yahoo/aol"
      if (h ~ /rzone\.de$|strato\.de$/) return "strato"
      n = split(h, x, "."); return (n >= 2 ? x[n-1] "." x[n] : h)
    }
    function rdom(line,   r) { r = ""; if (match(line, /to=<[^>]+>/)) { r = tolower(substr(line, RSTART+4, RLENGTH-5)); sub(/.*@/, "", r) }; return r }
    function watched(d,   i, n, w) { n = split(watch, w, " "); for (i = 1; i <= n; i++) if (d == tolower(w[i]) || d ~ ("\\." tolower(w[i]) "$")) return tolower(w[i]); return "" }
    function qid(s) { if (match(s, /\]: [0-9A-Za-z]+: /)) return substr(s, RSTART+3, RLENGTH-5); return "" }
    function dom(a) { a=tolower(a); sub(/.*@/, "", a); return a }
    function ipof(s) { if (match(s, /\[[0-9a-fA-F]*[.:][0-9a-fA-F:.]*\]/)) return substr(s, RSTART+1, RLENGTH-2); return "?" }
    # the reports this script mails (REPORT_MAIL_TO) are left out of all mail figures:
    # pickup logs the sender, every later line of that message carries its queue ID
    self != "" && /postfix\/pickup/ && index($0, "from=<" self ">") { q0 = qid($0); if (q0 != "") own[q0] = 1 }
    # … except a failed delivery of such a mail (wrong address, mailbox missing, full): an alert
    self != "" { q0 = qid($0)
      if (q0 != "" && (q0 in own)) {
        if (/ status=(deferred|bounced)/) { ownn++; if (ownx == "") { r = $0; sub(/^.*: to=/, "to=", r); ownx = substr(r, 1, 250) } }
        # Plesk: Postfix logs "status=sent" when it hands the mail to Plesk (relay=plesk_virtual);
        # a missing mailbox is only logged by postfix-local, and the mail is discarded without a bounce
        if (/postfix-local\[[0-9]+\]: [0-9A-Za-z]+: (Unknown user|.*[Qq]uota)/) { ownn++
          if (ownx == "") { r = $0; sub(/^.*postfix-local\[[0-9]+\]: [0-9A-Za-z]+: /, "Plesk: ", r); ownx = substr(r, 1, 250) } }
        next }
      # a mail TO the sender address: a remote server that accepted a report mail and bounced it
      # later (Plesk drops it, as that address has no mailbox) – status line of its delivery
      if (index($0, "to=<" self ">") && / status=/) bnc++ }
    # Successfully authenticated submissions (one line per mail with sasl_username).
    # Note: recent Postfix versions also append sasl_username to FAILED auth warnings.
    /postfix\/.*smtpd.*sasl_username=/ && !/authentication failed/ {
      u=$0; sub(/.*sasl_username=/, "", u); sub(/[ ,].*/, "", u)
      ip=ipof($0); sasl[u]++
      q=qid($0); if (q != "") sq[q]=u
      if (!((u SUBSEP ip) in seen)) { seen[u SUBSEP ip]=1; nip[u]++; ipl[u]=ipl[u] " " ip }
      sic[u SUBSEP ip]++
    }
    # Mails injected locally (PHP mail(), sendmail) – uid = Plesk system user
    /postfix\/pickup.*uid=/ { m=$0; sub(/.*uid=/, "", m); sub(/[ ,].*/, "", m); pick[m]++
                              q=qid($0); if (q != "") pq[q]=1 }
    # Recipients per envelope sender (all mail, incoming included)
    /postfix\/qmgr.*from=<.*nrcpt=/ {
      f=$0; sub(/.*from=</, "", f); sub(/>.*/, "", f); if (f=="") f="<> (bounce)"
      n=$0; sub(/.*nrcpt=/, "", n); sub(/[^0-9].*/, "", n); rc[f]+=n
      q=qid($0)
      # outgoing only: submitted after a mailbox login or injected by a local script;
      # counted once per message (qmgr logs a message again on every delivery retry)
      if (q != "" && ((q in sq) || (q in pq)) && !(q in oseen)) { oseen[q]=1; orc[f]+=n }
      # sender domain differs from the domain of the authenticated mailbox?
      if (q != "" && (q in sq) && !(q in mdone) && sq[q] ~ /@/ && f ~ /@/ && dom(f) != dom(sq[q])) {
        mdone[q]=1; su=sq[q]; mm[su]++
        if (!((su SUBSEP f) in mms) && mmc[su] < 3) { mms[su SUBSEP f]=1; mmc[su]++; mml[su]=mml[su] " " f }
      }
    }
    # delivery confirmations (DSN NOTIFY=SUCCESS): Postfix creates a new mail to the original sender;
    # sent to another server, they mostly answer spam with a forged sender
    /postfix\/bounce\[/ && / sender delivery status notification: / { c_ = $NF; dsnq[c_] = 1 }
    # a full mailbox here: Plesk rejects with its milter ("4.2.2 Mailbox full"), Dovecot/local delivery
    # logs dsn=4.2.2/5.2.2 or "quota exceeded" – RFC 3463: X.2.2 = mailbox full. Deliveries to other
    # servers (postfix/smtp) are not ours to fix and are left out.
    !/postfix\/smtp\[/ && match($0, /to=<[^>]+>/) && (/[ =]4\.2\.2[ ;,)]|[ =]5\.2\.2[ ;,)]/ || tolower($0) ~ /mailbox (is )?full|over quota|quota exceeded/) && (/milter-reject|status=(deferred|bounced)/) {
      u_ = tolower(substr($0, RSTART+4, RLENGTH-5)); mbf[u_]++ }
    / status=(sent|deferred|bounced)/ && /postfix\/smtp\[/ && (qid($0) in dsnq) && !((qid($0)) in dsnx) {
      dsnx[qid($0)] = 1; dsnn++; if (dsnex == "") dsnex = rdom($0) }
    / status=(sent|deferred|bounced)/ && /postfix\/smtp\[/ {
      p = prov($0); st = ($0 ~ / status=sent/ ? 1 : ($0 ~ / status=deferred/ ? 2 : 3)); pv[p, st]++; pt[p]++
      w = watched(rdom($0))
      if (w != "") { wv[w, st]++
        if (st > 1 && wx[w] == "") { r = $0; sub(/.* status=(deferred|bounced) \(/, "", r); sub(/\)$/, "", r); wx[w] = substr($0, 1, 15) " " rdom($0) ": " substr(r, 1, 200) } }
    }
    / status=sent/     { sent++ }
    / status=deferred/ { def++ }
    / status=bounced/  { bou++ }
    / status=(deferred|bounced)/ {
      l=tolower($0); sub(/.* status=(deferred|bounced) /, "", l)   # only the remote reply, not the addresses
      # blocklists and reputation, plus the wording of the big providers:
      #   Gmail: "likely unsolicited", "unusual rate" (4.7.28), unauthenticated (5.7.26)
      #   Microsoft: "block list", "rate limited" (4.7.650)
      #   Apple iCloud: "local policy" [CS01]/[HM08], SPF+DKIM failed [HME1], "excessive volume", Proofpoint DNSBL
      #   Yahoo/AOL: [TSS04] "unexpected volume or user complaints"
      #   GMX/web.de: "policy restrictions"; T-Online: "contact tosa@rx.t-online.de"; any DMARC rejection
      if (l ~ /blacklist|blocklist|block list|blocked|spamhaus|barracuda|spamcop|listed|reputation|poor ip|banned|unsolicited|spam|rate limit|rate-limit|unusual rate|4\.7\.28|5\.7\.26|4\.7\.650|local policy|\[cs0[0-9]\]|\[hm0[0-9]\]|\[hme[0-9]\]|excessive volume|unexpected volume|user complaints|\[ts+[0-9]+\]|dnsbl|policy restrictions|tosa@rx\.t-online|dmarc|spf and dkim/) {
        # example: time, recipient domain and the remote reply (without the delivery details)
        if (blx < 3) { d=$0
          e=substr($0, 1, 15); sub(/.* to=<[^@>]*@?/, "", d); sub(/>.*/, "", d); r=$0; sub(/.* status=(deferred|bounced) \(/, "", r)
          bex[++blx]=e " " d ": " substr(r, 1, 220) }
        bl++
      }
    }
    # SpamAssassin skipped a message because it is larger than the scan limit (Plesk: SA_MAX_MAIL_SIZE)
    /spamc\[[0-9]+\]: skipped message, greater than max message size/ {
      sk++; if (match($0, /\([0-9]+ bytes\)/)) skl = substr($0, RSTART+1, RLENGTH-8)
    }
    # SpamAssassin results: rules ending in _BLOCKED (URIBL_BLOCKED, URIBL_DBL_BLOCKED_OPENDNS …) mean
    # a blocklist refused to answer – usually because the DNS resolver is shared and over its free limit
    /spamd: result: / && match($0, / - [A-Z0-9_,]+ scantime=/) {
      sas++; t_ = substr($0, RSTART+3, RLENGTH-13); nb_ = 0
      n_ = split(t_, a_, ","); for (i = 1; i <= n_; i++) if (a_[i] ~ /_BLOCKED/) { sbr[a_[i]]++; nb_ = 1 }
      sab += nb_
    }
    /SASL [A-Z0-9-]+ authentication failed/ {
      sf++; sip[ipof($0)]++
      if (match($0, /sasl_username=[^ ,]+/)) { u_ = tolower(substr($0, RSTART+14, RLENGTH-14)); fu[u_]++; fp[u_ SUBSEP ipof($0)]++ }   # Office@ = office@
    }
    # login names that do not exist (Plesk: authpsa for IMAP/POP3, plesk_saslauthd for SMTP; Dovecot: "unknown user")
    /in mail authorization database/ && index($0, "No such user " apo) { r = $0; sub(".*No such user " apo, "", r); sub(apo ".*", "", r); if (r != "") nu[tolower(r)]++ }
    /auth.*\([^,()]+,[^()]*\): unknown user/ { match($0, /\([^,()]+,/); nu[tolower(substr($0, RSTART+1, RLENGTH-2))]++ }
    # plausibility check: lines of the IMAP/POP3 server vs. login lines recognized (ok or failed)
    /(dovecot|imap-login|pop3-login|imap[ds]|pop3[ds])/ { imapl++ }
    /(imap|pop3)-login: Login: / || /(imap|pop3)[ds](-ssl)?(\[[0-9]+\])?: LOGIN, user=/ { imapok++ }
    # successful IMAP/POP3 logins per mailbox and client IP (country check)
    /(imap|pop3)-login: Login: user=<[^>]+>.*rip=/ {
      u=$0; sub(/.*user=</, "", u); sub(/>.*/, "", u); r=$0; sub(/.*rip=/, "", r); sub(/[, ].*/, "", r); iok[u SUBSEP r]++
      if (match($0, /session=<[^>]+>/)) dses[substr($0, RSTART+9, RLENGTH-10)] = u SUBSEP r
    }
    # how much mail a session read, for the country check ("no mail read" vs. "3.4 MB read"):
    # Courier: "DISCONNECTED|LOGOUT, user=x, ip=[…], headers=N, body=N" (IMAP) or "retr=N, top=N" (POP3)
    /(imap|pop3)[ds](-ssl)?(\[[0-9]+\])?: (DISCONNECTED|LOGOUT|TIMEOUT), user=[^,]+, ip=\[/ {
      u=$0; sub(/.*, user=/, "", u); sub(/,.*/, "", u); r=$0; sub(/.*ip=\[/, "", r); sub(/\].*/, "", r); sub(/^::ffff:/, "", r)
      b = 0
      if (match($0, /headers=[0-9]+/)) b += substr($0, RSTART+8, RLENGTH-8)
      if (match($0, /body=[0-9]+/))    b += substr($0, RSTART+5, RLENGTH-5)
      if (match($0, /retr=[0-9]+/))    b += substr($0, RSTART+5, RLENGTH-5)
      if (match($0, /top=[0-9]+/))     b += substr($0, RSTART+4, RLENGTH-4)
      ird[u SUBSEP r] += b; irs[u SUBSEP r] = 1
    }
    # Dovecot: "imap(x)<pid><session>: Disconnected: … hdr_bytes=N body_bytes=N" / pop3 "retr=n/bytes"
    /(imap|pop3)\([^)]+\)<[0-9]+><[^>]+>: Disconnected/ {
      s_ = $0; sub(/.*\)<[0-9]+></, "", s_); sub(/>.*/, "", s_)
      if (s_ in dses) {
        b = 0
        if (match($0, /hdr_bytes=[0-9]+/))  b += substr($0, RSTART+10, RLENGTH-10)
        if (match($0, /body_bytes=[0-9]+/)) b += substr($0, RSTART+11, RLENGTH-11)
        if (match($0, /retr=[0-9]+\/[0-9]+/)) { x = substr($0, RSTART, RLENGTH); sub(/.*\//, "", x); b += x }
        ird[dses[s_]] += b; irs[dses[s_]] = 1
      }
    }
    /(imap|pop3)[ds](-ssl)?(\[[0-9]+\])?: LOGIN, user=[^,]+, ip=\[/ {
      u=$0; sub(/.*LOGIN, user=/, "", u); sub(/,.*/, "", u); r=$0; sub(/.*ip=\[/, "", r); sub(/\].*/, "", r); sub(/^::ffff:/, "", r)
      iok[u SUBSEP r]++
    }
    # IMAP/POP3 – Dovecot: "imap-login: Disconnected (auth failed, …): user=<x>, …, rip=1.2.3.4"
    /(imap|pop3)-login: .*(auth failed|Authentication failed)/ {
      df++; r=$0; ip_ = ""; if (match(r, /rip=[0-9a-fA-F:.]+/)) { ip_ = substr(r, RSTART+4, RLENGTH-4); dip[ip_]++ }
      if (match($0, /user=<[^>]+>/)) { u_ = tolower(substr($0, RSTART+6, RLENGTH-7)); fu[u_]++; if (ip_ != "") fp[u_ SUBSEP ip_]++ }
    }
    # IMAP/POP3 – Courier (Plesk alternative): one line per failed attempt,
    # "imapd: LOGIN FAILED, user=x, ip=[::ffff:1.2.3.4], port=[…]" (user= is not always logged)
    /(imap|pop3)[ds](-ssl)?(\[[0-9]+\])?: LOGIN FAILED/ {
      df++; r = ""
      if (match($0, /ip=\[[^]]+\]/)) { r=substr($0, RSTART+4, RLENGTH-5); sub(/^::ffff:/, "", r); dip[r]++ }
      if (match($0, /user=[^,]+/)) { u_ = tolower(substr($0, RSTART+5, RLENGTH-5)); fu[u_]++; if (r != "") fp[u_ SUBSEP r]++ }
    }
    END {
      printf "TOT\t%d\t%d\t%d\t%d\t%d\t%d\n", sent, def, bou, bl, sf, df
      printf "IMAPCHK\t%d\t%d\n", imapl, imapok + df
      printf "SKIP\t%d\t%s\n", sk, skl
      rl_ = ""; for (r in sbr) rl_ = rl_ (rl_ == "" ? "" : ", ") r " ×" sbr[r]
      printf "SADNS\t%d\t%d\t%s\n", sas, sab, rl_
      for (p in pt) printf "PROV\t%d\t%d\t%d\t%d\t%s\n", pt[p], pv[p, 1], pv[p, 2], pv[p, 3], p
      printf "DSNOUT\t%d\t%s\n", dsnn, dsnex
      for (u in mbf) printf "MBFULL\t%d\t%s\n", mbf[u], u
      nw = split(watch, ww, " "); for (i = 1; i <= nw; i++) { w = tolower(ww[i]); printf "WATCH\t%d\t%d\t%d\t%s\t%s\n", wv[w, 1], wv[w, 2], wv[w, 3], w, wx[w] }
      for (k in iok) { split(k, kk, SUBSEP); printf "IMOK\t%d\t%s\t%s\n", iok[k], kk[1], kk[2] }
      for (k in irs) { split(k, kk, SUBSEP); printf "IMRD\t%d\t%s\t%s\n", ird[k], kk[1], kk[2] }
      for (u in sasl) printf "SASL\t%d\t%d\t%s\t%s\n", sasl[u], nip[u], u, ipl[u]
      for (k in sic) { split(k, kk, SUBSEP); printf "SAIP\t%d\t%s\t%s\n", sic[k], kk[1], kk[2] }
      for (m in pick) printf "PICK\t%d\t%s\n", pick[m], m
      for (f in rc)   printf "RCPT\t%d\t%s\n", rc[f], f
      for (f in orc)  printf "ORCP\t%d\t%s\n", orc[f], f
      for (i in sip)  printf "SFIP\t%d\t%s\n", sip[i], i
      for (i in dip)  printf "DFIP\t%d\t%s\n", dip[i], i
      for (u in fu)   printf "FUSR\t%d\t%s\n", fu[u], u
      for (k in fp)   { split(k, kk, SUBSEP); printf "FPAIR\t%d\t%s\t%s\n", fp[k], kk[1], kk[2] }
      for (u in nu)   printf "NOUSR\t%d\t%s\n", nu[u], u
      for (u in mm)   printf "MISM\t%d\t%s\t%s\n", mm[u], u, mml[u]
      for (i=1; i<=blx; i++) printf "BLEX\t%s\n", bex[i]
      if (ownn) printf "OWNF\t%d\t%s\n", ownn, ownx
      else if (bnc) printf "OWNF\t%d\t%s\n", bnc, "a mail to the sender address " self " arrived – probably a later bounce from the receiving server"
    }' "$TMP")

  read -r _ SENT DEF BOU BL SF DF <<<"$(grep '^TOT' <<<"$MAILSTATS")"
  QUEUE=$(T "$CMD_TIMEOUT" postqueue -j 2>/dev/null | wc -l)
  out "Delivered: $SENT | deferred: $DEF | bounced: $BOU | queue: $QUEUE"
  out "Rejections mentioning blocklist/reputation/spam/rate limit: $BL"
  (( DEF > WARN_DEFERRED )) && alert "Mail: $DEF deferred deliveries"
  (( BL >= WARN_BLOCKLIST )) && alert "Mail: $BL rejections by remote servers mentioning a blocklist, reputation, spam or rate limit – check the server IP and the examples"
  (( QUEUE > WARN_QUEUE )) && alert "Mail: $QUEUE messages in the queue"
  while IFS=$'\t' read -r _ n ex; do
    [[ -n $n ]] && alert "Mail: the report mail (REPORT_MAIL_TO) could not be delivered ($n×) – check the address: $ex"
  done < <(grep '^OWNF' <<<"$MAILSTATS")
  grep '^BLEX' <<<"$MAILSTATS" | cut -f2- | sed 's/^/  example: /' >>"$BODY"
  # outgoing deliveries per receiving mail server: shows trouble with a big provider whatever its
  # reply says. Grouped by the MX host, not the recipient's domain: a forged sender's domain shows
  # up under the name of its (often unreachable) mail server.
  if grep -q '^PROV' <<<"$MAILSTATS"; then
    out "Outgoing deliveries per receiving mail server (provider or MX host; sent / deferred / bounced):"
    grep '^PROV' <<<"$MAILSTATS" | sort -t$'\t' -k2,2nr | head -10 |
      awk -F'\t' '{printf "  %-22s %5d / %d / %d\n", $6, $3, $4, $5}' >>"$BODY"
  fi
  # full mailboxes: mail to them is rejected – the customer often notices only days later
  while IFS=$'\t' read -r _ n k; do
    [[ -n $k ]] || continue
    out "Mailbox full: $k – $n delivery attempt(s) rejected"
    alert "Mail: mailbox $k is full – $n delivery attempt(s) rejected since the last run (senders retry for a few days after 4.2.2, 5.2.2 returns the mail at once). Raise its size limit, or have the customer delete or archive mail"
  done < <(grep '^MBFULL' <<<"$MAILSTATS" | sort -t$'\t' -k2,2nr)
  # delivery confirmations to other servers: Postfix offers DSN to everyone by default
  read -r _ n k <<<"$(grep '^DSNOUT' <<<"$MAILSTATS" | tr '\t' ' ')"
  if (( ${n:-0} > 0 )); then
    out "Delivery confirmations (DSN) sent to other servers: $n${k:+ (e.g. to $k)}"
    (( WARN_DSN > 0 && n >= WARN_DSN )) && alert "Mail: $n delivery confirmation(s) (DSN) sent to other servers${k:+, e.g. to $k} – spammers request them to verify addresses, and they go to forged senders. Offer DSN to the server itself only: smtpd_discard_ehlo_keyword_address_maps (see README)"
  fi
  # watched recipient domains (WATCH_RECIPIENT_DOMAINS): every deferral or bounce is an alert
  while IFS=$'\t' read -r _ n c k who ex; do
    [[ -n $who ]] || continue
    out "Watched recipient domain $who: $n sent, $c deferred, $k bounced"
    [[ -n $ex ]] && out "  example (watched): $ex"
    (( c + k > 0 )) && alert "Mail: deliveries to watched domain $who: $c deferred, $k bounced – check the examples (customer process affected?)"
  done < <(grep '^WATCH' <<<"$MAILSTATS")
  read -r _ n c <<<"$(grep '^SKIP' <<<"$MAILSTATS")"
  # current limit: from the log line, else from Plesk's configuration (default 256000 bytes)
  [[ -n ${c:-} ]] || c=$(awk '$1 == "SA_MAX_MAIL_SIZE" {print $2; exit}' /etc/psa/psa.conf /etc/psa/psa.conf.default 2>/dev/null)
  local lim=""
  [[ $c =~ ^[0-9]+$ ]] && lim="limit $(awk -v b="$c" 'BEGIN{printf "%.1f MB", b/1048576}') = $c bytes, Plesk: SA_MAX_MAIL_SIZE in /etc/psa/psa.conf"
  if (( ${n:-0} > 0 )); then
    out "Spam filter: $n mail(s) not scanned – larger than the size limit (${lim:-limit unknown})"
  else
    out "Spam filter: all mails scanned – none above the size limit${lim:+ ($lim)}"
  fi
  # blocklist lookups of SpamAssassin refused (URIBL_BLOCKED …): spam with such links gets through
  read -r _ n c k <<<"$(grep '^SADNS' <<<"$MAILSTATS" | tr '\t' ' ')"
  if (( ${c:-0} > 0 )); then
    out "Spam filter: blocklist lookups refused in $c of $n scanned mail(s) – $k"
    alert "Mail: SpamAssassin's blocklist lookups are refused ($c of $n mails: $k) – the DNS resolver is shared and over the lists' free limit, so links in spam are not checked. Let SpamAssassin ask a local resolver: 'dns_server 127.0.0.1' in a file of its own in the SpamAssassin configuration (Plesk: BIND answers on 127.0.0.1; test: dig @127.0.0.1 test.uribl.com.multi.uribl.com → 127.0.0.14), then restart spamd"
  elif (( ${n:-0} > 0 )); then
    out "Spam filter: blocklist lookups answered ($n mail(s) scanned)"
  fi

  if is_public_ipv4 "$PUBIP"; then
    REV=$(awk -F. '{print $4"."$3"."$2"."$1}' <<<"$PUBIP")
    BLRES=""
    for bl in $DNSBL_LISTS; do
      r=$(getent ahostsv4 "$REV.$bl" 2>/dev/null | awk 'NR==1{print $1}')
      if [[ -z $r ]]; then BLRES+=" $bl:clean"
      elif [[ $r == 127.255.255.* ]]; then BLRES+=" $bl:query-refused"
      else BLRES+=" $bl:LISTED($r)"; alert "Mail: server IP $PUBIP is listed on $bl"
      fi
    done
    out "DNS blocklists for $PUBIP:$BLRES"
  fi

  out ""; out "Top senders (total recipients):"
  grep '^RCPT' <<<"$MAILSTATS" | sort -t$'\t' -k2,2nr | head -10 |
    awk -F'\t' '{printf "  %6d  %s\n", $2, $3}' >>"$BODY"
  # alert only on mail sent FROM this server (login or script) – the list above also
  # contains incoming mail, e.g. a shop sending many invoices to a customer's mailbox
  while IFS=$'\t' read -r _ n who; do
    [[ $who == "<> (bounce)" ]] && continue
    (( n > WARN_MAILS_PER_SENDER )) && alert "Mail: $who sent to $n recipients from this server (mailbox login or script)"
  done < <(grep '^ORCP' <<<"$MAILSTATS")

  out ""; out "Authenticated mailboxes (mails, distinct IPs; IPs with country/operator, mails per IP):"
  SAIP=$(grep '^SAIP' <<<"$MAILSTATS" | sort -t$'\t' -k2,2nr)
  while IFS=$'\t' read -r _ n nip who _; do
    printf '  %6d  %2d IPs  %s\n' "$n" "$nip" "$who" >>"$BODY"
    line=""; k=0
    while IFS=$'\t' read -r _ c _ ip; do
      k=$((k + 1)); (( k > 5 )) && { line+=", …"; break; }
      geo "$ip"; line+="${line:+, }$ip${GEO_LABEL:+ ($GEO_LABEL)} ×$c"
    done < <(awk -F'\t' -v u="$who" '$3 == u' <<<"$SAIP")
    [[ -n $line ]] && printf '          %s\n' "$line" >>"$BODY"
  done < <(grep '^SASL' <<<"$MAILSTATS" | sort -t$'\t' -k2,2nr | head -10)
  # country alerts: mailbox submitted mails after a login from an unexpected country
  local -A FOREIGN_N=() FOREIGN_W=()
  while IFS=$'\t' read -r _ c who ip; do
    [[ -n $ip ]] || continue
    geo "$ip"
    if geo_foreign; then
      FOREIGN_N[$who]=$(( ${FOREIGN_N[$who]:-0} + c ))
      [[ ${FOREIGN_W[$who]:-} == *"$ip "* ]] || FOREIGN_W[$who]+="$ip ($GEO_LABEL) "
    fi
  done <<<"$SAIP"
  for who in "${!FOREIGN_N[@]}"; do
    alert "Mail: mailbox $who submitted ${FOREIGN_N[$who]} mails after logins from outside $ALLOWED_COUNTRIES: ${FOREIGN_W[$who]% } – password compromised?"
  done
  while IFS=$'\t' read -r _ n nip who _; do
    (( n > WARN_MAILS_PER_SASL )) && alert "Mail: mailbox $who submitted $n mails"
    (( nip > WARN_IPS_PER_MAILBOX )) && alert "Mail: mailbox $who used from $nip different IPs – password compromised?"
  done < <(grep '^SASL' <<<"$MAILSTATS")

  # successful IMAP/POP3 logins: a mailbox read from an unexpected country sends nothing, so the
  # sending checks above don't see it. Every login from outside ALLOWED_COUNTRIES is listed, but
  # the alert comes only once per mailbox and country: someone on holiday triggers one alert, not
  # one per run. State: known_imap_countries ("mailbox CC last-seen-epoch"); a country not seen
  # for IMAP_COUNTRY_KEEP_DAYS is forgotten, so the next trip alerts again. First run: silent.
  out ""; out "IMAP/POP3 logins (logins, mailbox, IP) from outside ALLOWED_COUNTRIES:"
  local -A IMF=() IMU=() IMI=() KC=() RD=()
  local DCL="" imn=0 KNOWNC="$STATE_DIR/known_imap_countries" firstc=0 isnew km kc kt now rd b
  now=$(date +%s)
  # bytes of mail read per mailbox and IP (sessions that ended in this run)
  while IFS=$'\t' read -r _ b who ip; do RD["$who $ip"]=$b; done < <(grep '^IMRD' <<<"$MAILSTATS")
  if [[ -f $KNOWNC ]]; then
    while read -r km kc kt; do
      [[ -n $kc ]] || continue
      kt=${kt:-$now}
      (( IMAP_COUNTRY_KEEP_DAYS > 0 && now - kt > IMAP_COUNTRY_KEEP_DAYS * 86400 )) && continue   # expired
      KC["$km $kc"]=$kt
    done <"$KNOWNC"
  else
    firstc=1
  fi
  while IFS=$'\t' read -r _ c who ip; do
    [[ -n $ip ]] || continue
    imn=$((imn + c)); IMU[$who]=1; IMI[$ip]=1
    geo "$ip"
    if geo_foreign; then
      isnew=""
      [[ -n ${KC["$who $GEO_CC"]+x} ]] || { (( firstc )) || isnew=1; }
      KC["$who $GEO_CC"]=$now
      rd=""
      if [[ -n ${RD["$who $ip"]+x} ]]; then
        b=${RD["$who $ip"]}
        if (( b == 0 )); then rd="no mail read"
        else rd="$(awk -v b="$b" 'BEGIN { if (b >= 1048576) printf "%.1f MB", b/1048576; else printf "%d KB", (b+1023)/1024 }') of mail read"; fi
      fi
      printf '  %6d  %s  from %s (%s)%s%s\n' "$c" "$who" "$ip" "$GEO_LABEL" "${rd:+  – $rd}" "${isnew:+  – first login from $GEO_CC}" >>"$BODY"
      [[ -n $isnew && ${IMF[$who]:-} != *"$ip "* ]] && IMF[$who]+="$ip ($GEO_LABEL${rd:+, $rd}) "
    elif [[ $GEO_LABEL == *"[datacenter]"* ]] && ! { [[ -n $GEO_TRUSTED_ORGS ]] && grep -qiE "$GEO_TRUSTED_ORGS" <<<"$GEO_ORG"; }; then
      DCL+="$(printf '  %6d  %s  from %s (%s)  – IMAP/POP3' "$c" "$who" "$ip" "$GEO_LABEL")"$'\n'
    fi
  done < <(grep '^IMOK' <<<"$MAILSTATS" | sort -t$'\t' -k2,2nr)
  if can_write_state; then
    for km in "${!KC[@]}"; do printf '%s %s\n' "$km" "${KC[$km]}"; done | sort >"$KNOWNC.new" && mv "$KNOWNC.new" "$KNOWNC"
  fi
  (( firstc )) && out "  (first run: countries listed here are stored as known for these mailboxes, list: $KNOWNC)"
  if (( GEO_OK )) && [[ -n $ALLOWED_COUNTRIES ]]; then
    out "  ($imn logins of ${#IMU[@]} mailboxes from ${#IMI[@]} IPs checked)"
  else
    out "  ($imn logins of ${#IMU[@]} mailboxes – country check off: needs GeoIP and ALLOWED_COUNTRIES)"
  fi
  for who in "${!IMF[@]}"; do
    alert "Mail: mailbox $who logged in via IMAP/POP3 from a new country outside $ALLOWED_COUNTRIES: ${IMF[$who]% } – travelling, or password compromised?"
  done
  # inside the allowed countries, but from a datacenter: mail apps that fetch through their own
  # servers, VPNs – or a stolen password used from a rented server. Listed for information only.
  if (( GEO_OK )) && [[ -n $ALLOWED_COUNTRIES ]]; then
    while IFS=$'\t' read -r _ c who ip; do
      [[ -n $ip ]] || continue
      geo "$ip"; geo_foreign && continue
      [[ $GEO_LABEL == *"[datacenter]"* ]] || continue
      [[ -n $GEO_TRUSTED_ORGS ]] && grep -qiE "$GEO_TRUSTED_ORGS" <<<"$GEO_ORG" && continue
      DCL+="$(printf '  %6d  %s  from %s (%s)  – SMTP, mails sent' "$c" "$who" "$ip" "$GEO_LABEL")"$'\n'
    done <<<"$SAIP"
    if [[ -n $DCL ]]; then
      out "Mail logins from datacenters inside ALLOWED_COUNTRIES (info: mail apps fetching through their servers, VPNs – or a password used from a rented server):"
      sort -k2,2 -k1,1nr <<<"${DCL%$'\n'}" | head -10 >>"$BODY"
    fi
  fi
  remember_mail_ips

  out ""; out "Mailboxes sending with a foreign sender domain (login ≠ from):"
  while IFS=$'\t' read -r _ n who ex; do
    printf '  %6d  %s – e.g.%s\n' "$n" "$who" "$ex" >>"$BODY"
    (( n >= WARN_FROM_MISMATCH )) && alert "Mail: mailbox $who sent $n mails with a foreign sender domain – spam?"
  done < <(grep '^MISM' <<<"$MAILSTATS" | sort -t$'\t' -k2,2nr | head -10)

  out ""; out "Mails sent by scripts (system user = subscription):"
  while IFS=$'\t' read -r _ n uid; do
    user=$(getent passwd "$uid" | cut -d: -f1); home=$(getent passwd "$uid" | cut -d: -f6)
    printf '  %6d  uid %s  %s  %s\n' "$n" "$uid" "${user:-?}" "${home:-}" >>"$BODY"
    (( n > WARN_MAILS_PER_SCRIPT )) && alert "Mail: scripts of ${user:-uid $uid} ($home) sent $n mails"
  done < <(grep '^PICK' <<<"$MAILSTATS" | sort -t$'\t' -k2,2nr | head -10)

  # IMAP/POP3 server active, but none of its login lines recognized → unknown log format, counts would be 0
  read -r _ n c <<<"$(grep '^IMAPCHK' <<<"$MAILSTATS")"
  (( ${n:-0} > 0 && ${c:-0} == 0 )) &&
    note "mail: $n log lines of the IMAP/POP3 server, but no login recognized – log format unknown (supported: Dovecot, Courier), IMAP/POP3 figures are 0"
  out ""; out "Failed mail logins: SMTP $SF | IMAP/POP3 $DF – top IPs:"
  (( SF + DF > WARN_AUTH_FAIL )) && alert "Mail: $((SF + DF)) failed mail logins (brute force?)"
  while IFS=$'\t' read -r c ip; do
    geo "$ip"; printf '  %6d  %s%s\n' "$c" "$ip" "${GEO_LABEL:+ ($GEO_LABEL)}" >>"$BODY"
  done < <(grep -E '^(SFIP|DFIP)' <<<"$MAILSTATS" | awk -F'\t' '{a[$3]+=$2} END{for(i in a) print a[i]"\t"i}' | sort -nr | head -5)
  out "Most attacked mailboxes (failed SMTP/IMAP/POP3 logins):"
  # mark login names that don't exist: guessing, or a device of a deleted mailbox
  local -A NOU=()
  while IFS=$'\t' read -r _ n who; do [[ -n $who ]] && NOU[$who]=$n; done < <(grep '^NOUSR' <<<"$MAILSTATS")
  while IFS=$'\t' read -r _ n who; do
    printf '  %6d  %s%s\n' "$n" "$who" "${NOU[$who]+  – no such mailbox}" >>"$BODY"
  done < <(grep '^FUSR' <<<"$MAILSTATS" | sort -t$'\t' -k2,2nr | head -5)
  if (( ${#NOU[@]} )); then
    n=0; for who in "${!NOU[@]}"; do n=$(( n + NOU[$who] )); done
    out "  Login names that don't exist: ${#NOU[@]} (${n} attempts) – guessed by attackers, or a device of a deleted mailbox"
  fi
  old_password_check

}

# A customer's device with an outdated password (changed in Plesk, not on the phone/tablet) retries
# again and again from the same IP – until fail2ban bans the IP and with it the whole office or
# home connection. Attackers rarely come from an IP that has logged in successfully before, so
# failed logins of one mailbox from such an IP are reported before the ban (WARN_OLD_PASSWORD).
old_password_check() {
  local KM="$STATE_DIR/known_mail_ips" ip who t n line="" k q
  local -A KW=() KT=()
  (( WARN_OLD_PASSWORD > 0 )) || return 0
  if [[ -r $KM ]]; then
    while read -r ip who t; do
      [[ -n $t ]] || continue
      KW[$ip]+=" $who "; (( t > ${KT["$ip $who"]:-0} )) && KT["$ip $who"]=$t
    done <"$KM"
  fi
  while IFS=$'\t' read -r _ _ who ip; do   # successful logins of this run
    ip=${ip#::ffff:}; [[ -n $ip ]] || continue
    [[ ${KW[$ip]:-} == *" $who "* ]] || KW[$ip]+=" $who "; KT["$ip $who"]=$(date +%s)
  done < <(grep -E '^(IMOK|SAIP)' <<<"$MAILSTATS")
  while IFS=$'\t' read -r _ n who ip; do
    ip=${ip#::ffff:}
    if [[ -z ${KW[$ip]:-} ]] || (( n < WARN_OLD_PASSWORD )); then continue; fi
    geo "$ip"
    if [[ ${KW[$ip]} == *" $who "* ]]; then
      k="this mailbox logged in successfully from there before (last $(date -d "@${KT["$ip $who"]}" '+%Y-%m-%d'))"
    else
      k="other mailboxes logged in successfully from there:$(tr -s ' ' <<<"${KW[$ip]}" | sed 's/ $//' | tr ' ' ',' | sed 's/^,/ /; s/,/, /g')"
    fi
    if [[ -n ${NOU[$who]+x} ]]; then
      k+="; the mailbox doesn't exist (any more)"; q="A device still set up for a deleted mailbox? Remove the account from the device"
    else
      q="A device with an outdated password? Correct it on the device"
    fi
    line+="  $(printf '%6d' "$n")  $who from $ip${GEO_LABEL:+ ($GEO_LABEL)} – $k"$'\n'
    alert "Mail: $n failed logins of $who from $ip${GEO_LABEL:+ ($GEO_LABEL)} – $k. $q before fail2ban bans the IP (and with it the whole connection)"
  done < <(grep '^FPAIR' <<<"$MAILSTATS" | sort -t$'\t' -k2,2nr | head -10)
  if [[ -n $line ]]; then
    out "Failed logins from IPs with earlier successful mail logins (device with an outdated password?):"
    printf '%s' "$line" >>"$BODY"
  fi
  return 0
}

check_webmail() {   # Roundcube: mails sent per mailbox with real client IP, failed webmail logins
  local RC_DIR d WEBMAIL WSIP n nr who nip line k c ip fails WFL
  # Roundcube connects to Postfix/Dovecot from localhost, so the mail log shows neither
  # the real client IP nor (on Plesk) the mailbox. Roundcube's own logs have both:
  #   sendmail: "User <mailbox> [<ip>]; Message <id> for <rcpt>, <rcpt>; 250: ..."
  #   errors:   "Login failed for <mailbox> against localhost from <ip>."
  RC_DIR=$ROUNDCUBE_LOG_DIR
  if [[ -z $RC_DIR ]]; then
    for d in /var/log/plesk-roundcube /usr/share/psa-roundcube/logs; do [[ -d $d ]] && { RC_DIR=$d; break; }; done
  fi
  out ""; out "Webmail (Roundcube) – mails sent (mails, recipients, IPs):"
  if [[ -n $RC_DIR && -d $RC_DIR ]]; then
    WEBMAIL=$( { new_lines "$RC_DIR/sendmail" | sed 's/^/S /'; new_lines "$RC_DIR/errors" | sed 's/^/E /'; } | awk '
      $1 == "S" && / User [^ ]+ \[[0-9a-fA-F:.]+\]; Message / {
        u=$0; sub(/.* User /, "", u); ip=u; sub(/ .*/, "", u); sub(/^[^[]*\[/, "", ip); sub(/\].*/, "", ip)
        r=$0; sub(/.*; Message [^ ]+ for /, "", r); sub(/; [0-9][0-9][0-9]:.*/, "", r); nr=split(r, x, ",")
        ms[u]++; rcp[u]+=nr; mip[u SUBSEP ip]++
      }
      $1 == "E" && /Login failed for .* from / {
        u=$0; sub(/.*Login failed for /, "", u); sub(/ against .*/, "", u); u=tolower(u)
        ip=$0; sub(/.* from /, "", ip); sub(/ .*/, "", ip); sub(/\.$/, "", ip)
        fl++; fip[ip]++; fu[u]++; fui[u SUBSEP ip]++
      }
      END {
        printf "WTOT\t%d\n", fl
        for (u in ms) printf "WSND\t%d\t%d\t%s\n", ms[u], rcp[u], u
        for (k in mip) { split(k, kk, SUBSEP); printf "WSIP\t%d\t%s\t%s\t%d\n", mip[k], kk[1], kk[2], fui[k] + 0 }
        for (i in fip) printf "WFIP\t%d\t%s\n", fip[i], i
        for (u in fu)  printf "WFUS\t%d\t%s\n", fu[u], u
      }')
    WSIP=$(grep '^WSIP' <<<"$WEBMAIL" | sort -t$'\t' -k2,2nr)
    while IFS=$'\t' read -r _ n nr who; do
      nip=$(awk -F'\t' -v u="$who" '$3 == u' <<<"$WSIP" | grep -c .)
      printf '  %6d  %5d rcpt  %2d IPs  %s\n' "$n" "$nr" "$nip" "$who" >>"$BODY"
      line=""; k=0
      while IFS=$'\t' read -r _ c _ ip _; do
        k=$((k + 1)); (( k > 5 )) && { line+=", …"; break; }
        geo "$ip"; line+="${line:+, }$ip${GEO_LABEL:+ ($GEO_LABEL)} ×$c"
      done < <(awk -F'\t' -v u="$who" '$3 == u' <<<"$WSIP")
      [[ -n $line ]] && printf '          %s\n' "$line" >>"$BODY"
      (( n > WARN_MAILS_PER_SASL )) && alert "Mail: webmail user $who sent $n mails"
      (( nr > WARN_MAILS_PER_SENDER )) && alert "Mail: webmail user $who sent to $nr recipients"
      (( nip > WARN_IPS_PER_MAILBOX )) && alert "Mail: webmail user $who used from $nip different IPs – password compromised?"
    done < <(grep '^WSND' <<<"$WEBMAIL" | sort -t$'\t' -k2,2nr | head -10)
    local -A WFOREIGN=()
    while IFS=$'\t' read -r _ c who ip fails; do
      [[ -n $ip ]] || continue
      geo "$ip"
      geo_foreign && WFOREIGN[$who]+="$ip ($GEO_LABEL) "
      (( fails >= WARN_LOGIN_BRUTE_FAILS )) &&
        alert "Mail: webmail user $who sent $c mails from $ip${GEO_LABEL:+ ($GEO_LABEL)} after $fails failed logins from that IP – password guessed?"
    done <<<"$WSIP"
    for who in "${!WFOREIGN[@]}"; do
      alert "Mail: webmail user $who sent mails from outside $ALLOWED_COUNTRIES: ${WFOREIGN[$who]% } – password compromised?"
    done
    WFL=$(grep '^WTOT' <<<"$WEBMAIL" | cut -f2)
    out "Failed webmail logins: ${WFL:-0} – top IPs:"
    (( ${WFL:-0} > WARN_AUTH_FAIL )) && alert "Mail: ${WFL} failed webmail logins (brute force?)"
    while IFS=$'\t' read -r _ c ip; do
      geo "$ip"; printf '  %6d  %s%s\n' "$c" "$ip" "${GEO_LABEL:+ ($GEO_LABEL)}" >>"$BODY"
    done < <(grep '^WFIP' <<<"$WEBMAIL" | sort -t$'\t' -k2,2nr | head -5)
    out "Most attacked mailboxes (failed webmail logins):"
    grep '^WFUS' <<<"$WEBMAIL" | sort -t$'\t' -k2,2nr | head -5 | awk -F'\t' '{printf "  %6d  %s\n", $2, $3}' >>"$BODY"
  else
    out "  (no Roundcube log directory found)"
    note "webmail: no Roundcube log directory found (ROUNDCUBE_LOG_DIR) – webmail not checked"
  fi
}

check_system() {   # load, CPU per system user, top processes, RAM, filesystems
  local CORES L1 L5 L15 LIMIT pct user MEM MT MA MP SWAP mnt p ip
  section "SYSTEM"
  CORES=$(nproc)
  read -r L1 L5 L15 _ </proc/loadavg
  out "Load: $L1 / $L5 / $L15 (1/5/15 min) on $CORES cores | $(uptime -p)"
  LIMIT=$(awk -v c="$CORES" -v f="$WARN_LOAD_FACTOR" 'BEGIN{print c*f}')
  num_gt "$L5" "$LIMIT" && alert "CPU: load $L5 above $LIMIT"

  # 3-second snapshot (second top iteration = current values)
  top -b -n 2 -d 3 -w 512 2>/dev/null | awk '/^top -/{n++} n==2' >"$TMP"
  out "$(grep -E '^%?Cpu' "$TMP" | head -1)"
  out ""; out "CPU per system user (snapshot):"
  awk 'p && $9 ~ /^[0-9.]+$/ {u[$2]+=$9} /PID +USER/{p=1} END{for(k in u) if (u[k]>=1) printf "%.1f\t%s\n", u[k], k}' "$TMP" |
    sort -nr | head -8 >"$TMP.u"
  while IFS=$'\t' read -r pct user; do
    printf '  %6s %%  %s\n' "$pct" "$user" >>"$BODY"
    num_gt "$pct" "$WARN_CPU_USER_PCT" && alert "CPU: user $user is using $pct % CPU"
  done <"$TMP.u"
  out ""; out "Top processes:"
  awk '/PID +USER/{p=1; next} p {printf "  %5s %%  %-12s %s\n", $9, $2, $12}' "$TMP" | head -8 >>"$BODY"

  MEM=$(free -m | awk '/^Mem:/{printf "%d %d %d", $2, $7, ($7*100)/$2}')
  read -r MT MA MP <<<"$MEM"
  SWAP=$(free -m | awk '/^Swap:/{print $3"/"$2}')
  out ""; out "RAM: $MA of $MT MB available ($MP %) | swap used: $SWAP MB"
  (( MP < WARN_MEM_AVAIL_PCT )) && alert "RAM: only $MP % available"

  # space and inodes: a filesystem with many small files (sessions, mails, caches) can run out
  # of inodes – "no space left on device" – while df still shows free space
  out ""; out "Filesystems (space used, inodes used):"
  local -A INO=()
  while read -r pct mnt; do INO[$mnt]=${pct%\%}; done < <(df -P -i -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | awk 'NR>1{print $5, $6}')
  while read -r pct mnt; do
    p=${pct%\%}; ip=${INO[$mnt]:-}
    [[ $ip =~ ^[0-9]+$ ]] || ip=""                    # "-" on filesystems without a fixed number of inodes
    printf '  %4s  %s%s\n' "$pct" "$mnt" "${ip:+  (inodes $ip%)}" >>"$BODY"
    (( p > WARN_DISK_PCT )) && alert "Disk: $mnt is $pct full"
    [[ -n $ip ]] && (( ip > WARN_DISK_PCT )) && alert "Disk: $mnt has used $ip% of its inodes (too many small files) – no new files can be created when they run out"
  done < <(df -P -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | awk 'NR>1{print $5, $6}')
}

# known_mail_ips ("IP mailbox last-seen-epoch"): client IPs of successful IMAP/POP3 and SMTP
# logins. check_fail2ban warns when a jail bans one of them – usually a customer's device with
# an outdated password, which retries until its whole connection is banned. Once banned, its
# attempts no longer reach the server, so the failed-login figures don't show it any more.
remember_mail_ips() {
  local f="$STATE_DIR/known_mail_ips" now tag who ip t
  local -A M=()
  can_write_state || return 0
  now=$(date +%s)
  if [[ -f $f ]]; then
    while read -r ip who t; do
      [[ -n $t ]] || continue
      (( KNOWN_MAIL_IP_DAYS > 0 && now - t > KNOWN_MAIL_IP_DAYS * 86400 )) && continue
      M["$ip $who"]=$t
    done <"$f"
  elif [[ -n ${MAILLOG:-} ]]; then
    # first run: learn from the rotated mail logs too, so a customer banned before the
    # update is recognized (the current run only sees logins since the previous run)
    while read -r ip who; do M["$ip $who"]=$now; done < <(
      for t in "$MAILLOG"*; do [[ -f $t && -r $t ]] && T "$CMD_TIMEOUT" zcat -f -- "$t" 2>/dev/null; done | awk '
        /(imap|pop3)-login: Login: user=<[^>]+>.*rip=/ {
          u=$0; sub(/.*user=</, "", u); sub(/>.*/, "", u); r=$0; sub(/.*rip=/, "", r); sub(/[, ].*/, "", r); k[r " " u]=1 }
        /(imap|pop3)[ds](-ssl)?(\[[0-9]+\])?: LOGIN, user=[^,]+, ip=\[/ {
          u=$0; sub(/.*LOGIN, user=/, "", u); sub(/,.*/, "", u); r=$0; sub(/.*ip=\[/, "", r); sub(/\].*/, "", r); sub(/^::ffff:/, "", r); k[r " " u]=1 }
        /postfix\/.*smtpd.*sasl_username=/ && !/authentication failed/ && match($0, /client=[^ ,]*\[[0-9a-fA-F:.]+\]/) {
          r=substr($0, RSTART, RLENGTH); sub(/.*\[/, "", r); sub(/\]$/, "", r); sub(/^::ffff:/, "", r); u=$0; sub(/.*sasl_username=/, "", u); sub(/[ ,].*/, "", u); k[r " " u]=1 }
        END { for (x in k) print x }' | grep -vE '^(127\.0\.0\.1|::1) ')
  fi
  while IFS=$'\t' read -r tag _ who ip; do
    [[ $tag == IMOK || $tag == SAIP ]] || continue
    ip=${ip#::ffff:}
    [[ -n $ip && -n $who && $ip != 127.0.0.1 && $ip != ::1 ]] || continue
    M["$ip $who"]=$now
  done < <(grep -E '^(IMOK|SAIP)' <<<"$MAILSTATS")
  for t in "${!M[@]}"; do printf '%s %s\n' "$t" "${M[$t]}"; done | sort >"$f.new" && mv "$f.new" "$f"
}

check_fail2ban() {
  local JAILS j s cb tb cf ip k who t ban="" KM="$STATE_DIR/known_mail_ips" KL="$STATE_DIR/known_login_ips"
  local -A MW=() ML=()
  section "FAIL2BAN"
  if command -v fail2ban-client >/dev/null; then
    # IPs with earlier successful logins: mail clients (mailbox, last seen) and SSH/panel
    if [[ -r $KM ]]; then
      while read -r ip who t; do
        [[ -n $t ]] || continue
        MW[$ip]+="$who, "; (( t > ${ML[$ip]:-0} )) && ML[$ip]=$t
      done <"$KM"
    fi
    JAILS=$(T "$CMD_TIMEOUT" fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ' ' | tr ',' ' ')
    for j in $JAILS; do
      s=$(T "$CMD_TIMEOUT" fail2ban-client status "$j" 2>/dev/null)
      cb=$(sed -n 's/.*Currently banned:[[:space:]]*//p' <<<"$s")
      tb=$(sed -n 's/.*Total banned:[[:space:]]*//p' <<<"$s")
      cf=$(sed -n 's/.*Currently failed:[[:space:]]*//p' <<<"$s")
      [[ ${cb:-0} -gt 0 || ${cf:-0} -gt 0 ]] && printf '  %-28s banned: %3s (total %s), currently failed: %s\n' "$j" "$cb" "$tb" "$cf" >>"$BODY"
      # banned IPs that logged in successfully before – a device with an outdated password?
      local -a banned=()
      read -ra banned <<<"$(sed -n 's/.*Banned IP list:[[:space:]]*//p' <<<"$s")"
      for ip in "${banned[@]}"; do
        k=""
        [[ -n ${MW[$ip]:-} ]] && k="mail logins of ${MW[$ip]%, } (last $(date -d "@${ML[$ip]}" '+%Y-%m-%d'))"
        known_login_ip "$ip" "$KL" && k="${k:+$k; }SSH/Plesk logins"
        [[ -n $k ]] || continue
        geo "$ip"
        ban+="    $j: $ip${GEO_LABEL:+ ($GEO_LABEL)} – earlier successful $k"$'\n'
        alert "fail2ban: jail $j bans $ip${GEO_LABEL:+ ($GEO_LABEL)}, which had successful logins before ($k) – a device with an outdated password? Unban: fail2ban-client set $j unbanip $ip"
      done
    done
    out "  (jails without bans/failures hidden)"
    if [[ -n $ban ]]; then
      out "  Banned IPs with earlier successful logins (customer or own device with an outdated password?):"
      printf '%s' "$ban" >>"$BODY"
    fi
  else
    out "fail2ban not installed"; alert "fail2ban is not running"
  fi
}

check_web() {   # requests, 5xx, WordPress logins, PHP errors, attack patterns, peaks, ModSecurity
  local dir dom lf n e5 lp top wl ws xr xb nl lt succ brute sline tok sip xnote ex
  local sq sq2 tr tr2 rc rc2 xs xs2 sf sf2 sfl pk pkm dp dn root f h b
  section "WEB (since last run)"
  if [[ -z $VHOST_LOGS || ! -d $VHOST_LOGS ]]; then
    out "  skipped – log directory not found"
    note "web: log directory VHOST_LOGS=\"$VHOST_LOGS\" not found – web figures are 0"
    return 0
  fi
  : >"$TMP"; : >"$TMP.php"; : >"$TMP.att"; : >"$TMP.modsec"; : >"$TMP.scan"
  for dir in "$VHOST_LOGS"/*/logs; do
    [[ -d $dir ]] || continue
    dom=$(basename "$(dirname "$dir")")
    for lf in "$dir/access_ssl_log" "$dir/access_log"; do
      new_lines "$lf"
    done | awk -v d="$dom" '
      { n++; ip[$1]++ }
      $9 ~ /^5[0-9][0-9]$/ { e5++ }
      # WordPress logins: a successful wp-login.php POST answers 302 (redirect to
      # wp-admin), a failed one 200. Requests with ?action= (lost password, ...) are ignored.
      $6 == "\"POST" && $7 ~ /wp-login\.php/ {
        lp++; wl++; lip[$1]++
        if ($7 !~ /action=/) { if ($9 == 302) ws[$1]++; else if ($9 == 200) wf[$1]++ }
      }
      $6 == "\"POST" && $7 ~ /xmlrpc\.php/ { lp++; xr++; lip[$1]++; if ($9 ~ /^40[0-9]$/) xb++ }
      # ---- attack patterns, sensitive-file probes, traffic peaks, distributed requests
      as {
        u=tolower($7); ok=($9 == 200)
        pm[substr($4, 2, 17)]++                                   # requests per minute
        path=$7; sub(/\?.*/, "", path)
        if (path !~ /\.(css|js|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|map)$/ && !((path SUBSEP $1) in pseen)) { pseen[path SUBSEP $1]=1; pn[path]++ }
        if (u ~ /union(\+|%20| |\/\*\*\/)+(all(\+|%20| )+)?select|information_schema|(sleep|benchmark)(\(|%28)|%27(\+|%20)*(or|and)(\+|%20)|select(\+|%20)+.*(\+|%20)from(\+|%20)/) { sq++; if (ok) sq2++ }
        else if (u ~ /\.\.\/|\.\.%2f|%2e%2e|\/etc\/passwd|php:\/\/|file:\/\/|\/proc\/self/) { tr++; if (ok) tr2++ }
        else if (u ~ /\$\{jndi|\/bin\/(ba)?sh|(cmd|exec|command)=|system(\(|%28)|shell_exec|passthru|eval(\(|%28)|wget(\+|%20)|curl(\+|%20)|;id;|%3bid%3b/) { rc++; if (ok) rc2++ }
        else if (u ~ /<script|%3cscript|javascript:|onerror(=|%3d)|onload(=|%3d)|alert(\(|%28)/) { xs++; if (ok) xs2++ }
        lp_=tolower(path)
        if (lp_ ~ /\/\.env(\.|$)|\/\.git\/|\/\.svn\/|\/\.hg\/|\.sql(\.gz|\.zip|\.bz2)?$|\/(backup|backups|dump|db|database|site|www|httpdocs|wordpress)[^\/]*\.(zip|tar|tgz|tar\.gz|gz|7z|rar)$|wp-config\.php[._~-]|\.(bak|old|orig|save|swp)$|\/\.htpasswd$|\/\.aws\/|\/\.ssh\/|id_rsa|\/\.ds_store$|\/phpinfo\.php$|\/info\.php$|\/adminer[^\/]*\.php$|\/\.vscode\/|\/\.idea\//) {
          sf++; if (ok && $10 + 0 > 0) { sf2++; if (!(path in sfp) && sfn < 5) { sfp[path]=1; sfn++; sfl=sfl " " path } } }
      }
      END { if (as && n) {
              pk=0; pkm="-"; for (m in pm) if (pm[m] > pk) { pk=pm[m]; pkm=m }
              dp="-"; dn=0; for (x in pn) if (pn[x] > dn) { dn=pn[x]; dp=x }
              if (sfl == "") sfl="-"
              printf "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%d\t%s\t%s\t%d\n", d, sq, sq2, tr, tr2, rc, rc2, xs, xs2, sf, sf2, sfl, pk, pkm, dp, dn >> attf
            }
            if (n) { top=""; m=0; for (i in ip) if (ip[i]>m) { m=ip[i]; top=i }
                     nl=0; lt="-"; lm=0; for (i in lip) { nl++; if (lip[i]>lm) { lm=lip[i]; lt=i } }
                     succ=""; nsucc=0; brute=""
                     for (i in ws) { nsucc+=ws[i]; succ=succ " " i "=" (wf[i]+0)
                                     if (wf[i] >= bf) brute=brute " " i }
                     if (succ == "") succ="-"; if (brute == "") brute="-"
                     printf "%d\t%d\t%d\t%s\t%s (%d)\t%d\t%d\t%d\t%d\t%d\t%s (%d)\t%s\t%s\n",
                            n, e5+0, lp+0, d, top, m, wl+0, nsucc, xr+0, xb+0, nl, lt, lm, succ, brute } }' \
      bf="$WARN_LOGIN_BRUTE_FAILS" as="$ATTACK_STATS" attf="$TMP.att" >>"$TMP"
    new_lines "$dir/error_log" | awk -v d="$dom" -v msf="$TMP.modsec" -v scf="$TMP.scan" '
      # A scanner that requests a theme, plugin or wp-admin file directly runs it without WordPress:
      # "Call to undefined function <WordPress core function>()" / undefined constant ABSPATH. Not an
      # error of the site – counted separately, not towards WARN_PHP_FATAL.
      /PHP Fatal error/ && (/Call to undefined function (add_action|add_filter|add_shortcode|apply_filters|do_action|get_header|get_footer|get_sidebar|get_template_part|get_locale|load_textdomain|load_theme_textdomain|load_plugin_textdomain|language_attributes|get_bloginfo|bloginfo|wp_head|wp_footer|wp_die|is_admin|get_option|plugin_dir_path|plugin_dir_url|plugins_url|register_activation_hook|get_template_directory|get_template_directory_uri|get_stylesheet_directory|wp_enqueue_script|wp_enqueue_style|esc_html|esc_attr|esc_html__|esc_html_e|__|_e)\(\)/ || /Undefined constant "?ABSPATH/) { ns++; next }
      /PHP Fatal error/ { n++; if (ex == "") { ex=$0; sub(/.*PHP Fatal error: */, "", ex); ex=substr(ex, 1, 160) } }
      /ModSecurity: / {
        if (/Access denied/) mb++; else mw++
        id="?"; if (match($0, /\[id "[0-9]+"\]/)) id=substr($0, RSTART+5, RLENGTH-7)
        msg="";  if (match($0, /\[msg "[^"]*"\]/)) msg=substr($0, RSTART+6, RLENGTH-8)
        r[id]++; rm[id]=substr(msg, 1, 70)
      }
      END { if (n) printf "%d\t%s\t%s\n", n, d, ex
            if (ns) printf "%d\t%s\n", ns, d >> scf
            if (mb + mw) { top=""; for (k=0; k<3; k++) { b=""; c=0; for (i in r) if (r[i] > c) { c=r[i]; b=i }
                                                       if (b == "") break; top=top (top==""?"":"; ") b " " rm[b] " ×" c; delete r[b] }
                           printf "%d\t%d\t%s\t%s\n", mb+mw, mb, d, top >> msf } }' >>"$TMP.php"
  done
  out "requests | 5xx | login POSTs | domain | busiest IP"
  sort -t$'\t' -k1,1nr "$TMP" | head -10 | awk -F'\t' '{printf "  %7d %5d %6d  %s  %s\n", $1, $2, $3, $4, $5}' >>"$BODY"
  while IFS=$'\t' read -r n e5 lp dom _; do
    ignored_domain "$dom" && continue
    (( e5 > WARN_5XX_PER_DOMAIN )) && alert "Web: $dom returned $e5 server errors (5xx)"
    (( lp > WARN_LOGIN_POSTS )) && alert "Web: $dom received $lp login attempts (wp-login/xmlrpc)"
  done <"$TMP"

  out ""; out "WordPress login attacks (domains with at least $WARN_LOGIN_DETAIL login POSTs):"
  while IFS=$'\t' read -r n e5 lp dom top wl ws xr xb nl lt succ brute; do
    sline=""
    if [[ $succ != - ]]; then
      for tok in $succ; do
        sip=${tok%=*}; geo "$sip"
        sline+="${sline:+, }$sip${GEO_LABEL:+ ($GEO_LABEL)}, ${tok##*=} failures before"
        if geo_foreign && ! ignored_domain "$dom"; then
          alert "Web: $dom – successful WordPress login from $sip ($GEO_LABEL), outside $ALLOWED_COUNTRIES"
        fi
      done
    fi
    if [[ $brute != - ]] && ! ignored_domain "$dom"; then
      alert "Web: $dom – successful WordPress login from$brute after repeated failures – brute force succeeded? Check the users of this site"
    fi
    (( lp >= WARN_LOGIN_DETAIL )) || continue
    xnote=""; (( xr > 0 && xb == 0 )) && xnote=" – xmlrpc.php is NOT blocked"
    printf '  %s: %d POSTs from %d IPs (busiest %s)\n    wp-login.php: %d, successful (302): %d | xmlrpc.php: %d, blocked (4xx): %d%s\n' \
      "$dom" "$lp" "$nl" "$lt" "$wl" "$ws" "$xr" "$xb" "$xnote" >>"$BODY"
    [[ $succ != - ]] && printf '    successful wp-login from: %s\n' "$sline" >>"$BODY"
  done < <(sort -t$'\t' -k3,3nr "$TMP")
  out ""; out "PHP fatal errors (count, domain, first message):"
  sort -t$'\t' -k1,1nr "$TMP.php" | head -8 | while IFS=$'\t' read -r n dom ex; do
    printf '  %5d  %s – %s\n' "$n" "$dom" "$ex" >>"$BODY"
  done
  while IFS=$'\t' read -r n dom _; do
    ignored_domain "$dom" && continue
    (( n > WARN_PHP_FATAL )) && alert "Web: $dom logged $n PHP fatal errors"
  done <"$TMP.php"
  [[ -s $TMP.scan ]] &&
    out "  not counted – scanners calling WordPress files directly (undefined WordPress function/ABSPATH): $(sort -t$'\t' -k1,1nr "$TMP.scan" | head -8 | awk -F'\t' '{ printf "%s%s ×%d", (NR > 1 ? ", " : ""), $2, $1 }')"

  if (( ATTACK_STATS )); then
    out ""; out "Attack patterns & sensitive-file probes (count, of which answered 200):"
    while IFS=$'\t' read -r dom sq sq2 tr tr2 rc rc2 xs xs2 sf sf2 sfl pk pkm dp dn; do
      (( sq + tr + rc + xs + sf > 0 )) || continue
      printf '  %-26s SQLi %d/%d | traversal %d/%d | code exec %d/%d | XSS %d/%d | sensitive files %d/%d\n' \
        "$dom" "$sq" "$sq2" "$tr" "$tr2" "$rc" "$rc2" "$xs" "$xs2" "$sf" "$sf2" >>"$BODY"
      if [[ $sfl != - ]]; then
        root=$(docroot_of "$dom")
        for f in $sfl; do
          if [[ -n $root && -e $root$f ]]; then
            printf '      served with 200 AND present on disk: %s\n' "$f" >>"$BODY"
            ignored_domain "$dom" || alert "Web: $dom served the sensitive file $f (HTTP 200, file exists) – a request in the access log since the last run; remove the file or block access, and assume it was downloaded"
          else
            printf '      200 without such file (catch-all route?): %s\n' "$f" >>"$BODY"
          fi
        done
      fi
    done < <(sort -t$'\t' -k10,10nr "$TMP.att" | awk -F'\t' '($2+$4+$6+$8+$10) > 0' | head -12)
    out ""; out "Traffic peaks & distributed requests (busiest minute; URL requested by most different IPs):"
    while IFS=$'\t' read -r dom sq sq2 tr tr2 rc rc2 xs xs2 sf sf2 sfl pk pkm dp dn; do
      (( pk >= WARN_REQ_PER_MIN / 4 || dn >= WARN_DISTRIBUTED_IPS / 2 )) || continue
      printf '  %-26s peak %d req/min at %s | %s from %d IPs\n' "$dom" "$pk" "${pkm#*:}" "$dp" "$dn" >>"$BODY"
      ignored_domain "$dom" && continue
      (( pk > WARN_REQ_PER_MIN )) && alert "Web: $dom peaked at $pk requests/minute (${pkm#*:} UTC) – load spike or application-layer flood?"
      (( dn >= WARN_DISTRIBUTED_IPS )) && alert "Web: $dom – $dp requested by $dn different IPs within one run – distributed (botnet) traffic?"
    done < <(sort -t$'\t' -k13,13nr "$TMP.att" | head -10)
    out ""; out "ModSecurity (hits, of which blocked; top rules):"
    if [[ -s $TMP.modsec ]]; then
      sort -t$'\t' -k1,1nr "$TMP.modsec" | head -8 | while IFS=$'\t' read -r h b dom top; do
        printf '  %6d %6d  %s – %s\n' "$h" "$b" "$dom" "$top" >>"$BODY"
      done
    else
      out "  none (or ModSecurity not active)"
    fi
  fi
  rm -f "$TMP.att" "$TMP.modsec" "$TMP.scan"
}

check_uploads() {   # new PHP files in wp-content/uploads
  local SCAN_STAMP up CNT nto
  section "WEBROOTS: PHP files in upload folders"
  if [[ -z $VHOST_LOGS || ! -d $VHOST_LOGS ]]; then
    out "  skipped – VHOST_LOGS not found"
    note "web: log directory VHOST_LOGS=\"$VHOST_LOGS\" not found – web figures are 0"
    return 0
  fi
  SCAN_STAMP="$STATE_DIR/last_scan"
  nto=$(timeouts_seen)
  can_write_state && touch "$SCAN_STAMP.new"   # remember the time before scanning
  while IFS= read -r up; do
    if [[ -f $SCAN_STAMP ]]; then
      # changed since the last scan – by file date (mtime) OR by inode change time (ctime): malware
      # sets the file date back (PHP touch()) to look old; the change time can't be set by a user
      T "$FIND_TIMEOUT" find "$up" -type f \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.phar' \) \( -newer "$SCAN_STAMP" -o -cnewer "$SCAN_STAMP" \) 2>/dev/null
    else
      T "$FIND_TIMEOUT" find "$up" -type f \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.phar' \) ! -name 'index.php' 2>/dev/null
    fi
  done < <(T "$FIND_TIMEOUT" find "$(dirname "$VHOST_LOGS")" -mindepth 2 -maxdepth 7 -type d -path '*/wp-content/uploads' ! -path '*/system/*' 2>/dev/null) |
    grep -vE "$UPLOADS_PHP_IGNORE" >"$TMP"
  CNT=$(wc -l <"$TMP")
  if [[ -f $SCAN_STAMP ]]; then
    out "New since last run: $CNT"
    (( CNT > 0 )) && alert "Web: $CNT new PHP file(s) in wp-content/uploads – possible malware"
  else
    out "First run – existing PHP files (excluding index.php): $CNT"
    (( CNT > 0 )) && alert "Web: $CNT PHP file(s) found in wp-content/uploads – check whether legitimate"
  fi
  local st=0 fm
  [[ -f $SCAN_STAMP ]] && st=$(stat -c %Y "$SCAN_STAMP")
  head -15 "$TMP" | while IFS= read -r up; do
    fm=$(stat -c %Y "$up" 2>/dev/null || echo 0)
    if (( st > 0 && fm > 0 && fm < st )); then     # found by its change time only
      printf '  %s  (file date %s is older than its last change – set back, or the file was moved/its permissions changed)\n' "$up" "$(date -d "@$fm" +%F)" >>"$BODY"
    else printf '  %s\n' "$up" >>"$BODY"; fi
  done
  # after a timeout the scan was incomplete: keep the old stamp, so the next run looks again
  if [[ $(timeouts_seen) == "$nto" ]]; then can_write_state && mv "$SCAN_STAMP.new" "$SCAN_STAMP"; fi
  return 0
}

# known_login_ips: "IP last-seen-epoch" per line (older versions wrote only "IP").
known_login_ip() { [[ -r $2 ]] && awk -v ip="$1" '$1 == ip { f = 1; exit } END { exit !f }' "$2"; }
# keep the newest line per IP, drop IPs not seen for KNOWN_LOGIN_IP_DAYS; old lines without a
# date count as seen now, so an update doesn't forget them at once
compact_login_ips() {
  local f=$1 now
  can_write_state && [[ -f $f ]] || return 0
  now=$(date +%s)
  awk -v now="$now" -v keep=$(( KNOWN_LOGIN_IP_DAYS * 86400 )) '
    NF { t = ($2 ~ /^[0-9]+$/) ? $2 : now; if (t > last[$1]) last[$1] = t }
    END { for (ip in last) if (keep == 0 || now - last[ip] <= keep) print ip, last[ip] }' "$f" | sort >"$f.new" &&
    mv "$f.new" "$f"
}

check_logins() {   # successful SSH and Plesk panel logins, alert for previously unknown IPs
  local KNOWN NEWLOGINS FIRST_LOGIN_RUN cnt rest kind user ip meth fnote a
  section "SUCCESSFUL LOGINS (SSH, Plesk panel)"
  KNOWN="$STATE_DIR/known_login_ips"
  NEWLOGINS=$TMPD/new_login_alerts
  [[ -n $PLESK_PANEL_LOG && -r $PLESK_PANEL_LOG ]] ||
    note "logins: Plesk panel log PLESK_PANEL_LOG=\"$PLESK_PANEL_LOG\" not found – panel logins not checked"
  FIRST_LOGIN_RUN=0; [[ -f $KNOWN ]] || { FIRST_LOGIN_RUN=1; can_write_state && : >"$KNOWN"; }
  {
    if [[ -r /var/log/auth.log ]]; then new_lines /var/log/auth.log
    elif [[ -r /var/log/secure ]]; then new_lines /var/log/secure
    elif command -v journalctl >/dev/null; then T "$CMD_TIMEOUT" journalctl --since "@$SINCE" -u ssh -u sshd -o short 2>/dev/null
    else note "logins: no SSH log (/var/log/auth.log, /var/log/secure) and no journal – SSH logins not checked"; fi |
      awk '/sshd.*Accepted / { for (i=1;i<=NF;i++) { if ($i=="Accepted") m=$(i+1); if ($i=="for") u=$(i+1); if ($i=="from") ip=$(i+1) }
                               print "SSH\t" u "\t" ip "\t" m }'
    # Plesk panel: Plesk logs no login events, but its access log shows them: a login is a
    # "POST /login_up.php", and only a successful one is followed by a page of the panel
    # (/admin/, /smb/, /cp/) with login_up.php as referrer. The user name is not logged.
    # Requests proxied through a domain (https://domain/login.php) come from 127.0.0.1 with
    # the real client IP in the last quoted field.
    new_lines "$PLESK_PANEL_LOG" | awk -F'"' -v failf="$TMPD/panel_fail" '
      { ip = $1; sub(/ .*/, "", ip)
        if ((ip == "127.0.0.1" || ip == "::1") && $(NF-1) ~ /^[0-9a-fA-F:.]+$/) ip = $(NF-1)
        split($2, rq, " "); st = $3; sub(/^ /, "", st); sub(/ .*/, "", st) }
      rq[1] == "POST" && rq[2] ~ /^\/login_up\.php/ { pend[ip]++; next }
      (ip in pend) && rq[1] == "GET" && rq[2] ~ /^\/(admin|smb|cp)\// && $4 ~ /login_up\.php/ && st ~ /^(200|30[0-9])$/ {
        print "Plesk\t-\t" ip "\tpanel, user not logged"; delete pend[ip] }
      END { for (i in pend) f += pend[i]; print f + 0 > failf }'
  } | sort | uniq -c | while read -r cnt rest; do
    IFS=$'\t' read -r kind user ip meth <<<"$rest"
    geo "$ip"
    printf '  %4d× %-5s %-14s from %-16s (%s)%s\n' "$cnt" "$kind" "$user" "$ip" "$meth" "${GEO_LABEL:+  $GEO_LABEL}" >>"$BODY"
    if known_login_ip "$ip" "$KNOWN"; then
      can_write_state && echo "$ip $(date +%s)" >>"$KNOWN"      # last seen; compacted below
    else
      can_write_state && echo "$ip $(date +%s)" >>"$KNOWN"
      fnote=""; geo_foreign && fnote=" – OUTSIDE $ALLOWED_COUNTRIES"
      (( FIRST_LOGIN_RUN )) || echo "$( [[ $kind == Plesk ]] && echo "Plesk panel login" || echo "$kind login as $user") from previously unknown IP $ip${GEO_LABEL:+ ($GEO_LABEL)}$fnote" >>"$NEWLOGINS"
    fi
  done
  compact_login_ips "$KNOWN"
  if [[ -s $NEWLOGINS ]]; then
    while IFS= read -r a; do alert "Login: $a"; done <"$NEWLOGINS"
  fi
  # without Plesk's own log, the access log gives at least the number of failed panel logins
  local panel_runs=0
  if [[ -r $PLESK_ERROR_LOG ]]; then
    if (( ONLY_MODE )); then [[ " ${ONLY//,/ } " == *" panel "* ]] && panel_runs=1
    else [[ " $HOURLY_CHECKS " == *" panel "* ]] && panel_runs=1; fi
  fi
  (( ! panel_runs )) && [[ -s $TMPD/panel_fail ]] && (( $(cat "$TMPD/panel_fail") > 0 )) &&
    out "  Plesk panel: $(cat "$TMPD/panel_fail") failed login attempt(s) (fail2ban jail plesk-panel)"
  (( FIRST_LOGIN_RUN )) && out "  (first run: all IPs stored as known; from now on new IPs raise an alert. List: $KNOWN)"
  return 0
}

# Plesk's own log (panel.log): failed panel logins with the login name, and failed automatic
# certificate renewals (Let's Encrypt via SSL It!) with Let's Encrypt's reason. Plesk renews
# 30 days before expiry and retries daily, so a failure shows up weeks before the certificate
# check warns – usually a domain whose DNS points elsewhere, or a blocked challenge URL.
check_panel() {
  local PL n who ip d r line="" k
  section "PLESK PANEL LOG"
  PL=$PLESK_ERROR_LOG
  if [[ -z $PL || ! -r $PL ]]; then out "Plesk log PLESK_ERROR_LOG=\"$PL\" not found (no Plesk?) – skipped"; return 0; fi
  new_lines "$PL" | awk -v apo="'" '
    /\[Action Log\] Failed login attempt with login / {
      l = $0; sub(".*with login " apo, "", l); sub(apo ".*", "", l)
      i = $0; sub(/.* from IP /, "", i); sub(/[ ,].*/, "", i)
      fl[l]++; fi_[i]++; nf++ }
    # one line per failed renewal; the reason of Lets Encrypt follows as "Type:" and "Detail:"
    /\[extension\/sslit\] Failed to renew certificate of domain / {
      d = $0; sub(".*of domain " apo, "", d); sub(apo ".*", "", d); fr[d]++; cur = d; wait = 6; next }
    wait > 0 { wait--
      if (/^Detail: /) { r = $0; sub(/^Detail: /, "", r); sub(/: ".*/, "", r); sub(/ - check that .*/, "", r); sub(/; DNS problem.*/, "", r)
        gsub(/acme-challenge\/[A-Za-z0-9_-]+/, "acme-challenge/…", r); why[cur] = substr(r, 1, 160); wait = 0 }
      else if (/^\[/) wait = 0 }
    END {
      printf "PFAIL\t%d\n", nf
      for (l in fl) printf "PLOG\t%d\t%s\n", fl[l], l
      for (i in fi_) printf "PIP\t%d\t%s\n", fi_[i], i
      for (d in fr) printf "CERT\t%d\t%s\t%s\n", fr[d], d, why[d] }' >"$TMP.panel"

  read -r _ n <<<"$(grep '^PFAIL' "$TMP.panel")"
  out "Failed panel logins: ${n:-0}"
  if (( ${n:-0} > 0 )); then
    out "  login names: $(grep '^PLOG' "$TMP.panel" | sort -t$'\t' -k2,2nr | head -5 | awk -F'\t' '{printf "%s%s ×%d", (NR > 1 ? ", " : ""), $3, $2}')"
    while IFS=$'\t' read -r _ n ip; do
      geo "$ip"; line+="${line:+, }$ip${GEO_LABEL:+ ($GEO_LABEL)} ×$n"
    done < <(grep '^PIP' "$TMP.panel" | sort -t$'\t' -k2,2nr | head -5)
    out "  top IPs: $line"
  fi
  out "Failed automatic certificate renewals (Let's Encrypt):"
  k=0
  while IFS=$'\t' read -r _ n d r; do
    [[ -n $d ]] || continue
    ignored_domain "$d" && continue
    k=$((k + 1))
    out "  $d: ${n}× – ${r:-no reason logged}"
    alert "Certificate: automatic renewal for $d failed${r:+ – $r}. Let's Encrypt must reach the domain on this server: DNS pointing elsewhere (remove the domain or its certificate), or the challenge URL blocked"
  done < <(grep '^CERT' "$TMP.panel" | sort -t$'\t' -k3,3)
  (( k )) || out "  none"
  return 0
}

# ---------------------------------------------------------------- access & persistence
# What an attacker leaves behind after a break-in, to come back or to use the server: an SSH
# key, an account with a login shell, sudo rights, a cron job or autostart entry, a process
# started from /tmp, a port listening for him. Read only – the script changes and blocks nothing.
# Each list is compared with the previous run's ($STATE_DIR/baseline/); the first run stores
# them silently. Stored are fingerprints, names, checksums and cron lines with passwords masked.

# content that has no business in a cron job or autostart file: download piped into a shell,
# base64 decoding, reverse shells, interpreter one-liners, known miners – and programs in /tmp:
# in a cron line any path there (a cron job has no reason to use /tmp but to start something),
# in an autostart script only a program started from there (scripts use temporary files)
PERSIST_SUSPICIOUS='(curl|wget|fetch)[^|;]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|da|z|k)?sh([[:space:]]|$)|base64[[:space:]]+(-d|--decode)|python[0-9.]*[[:space:]]+-c[[:space:]]|(perl|ruby)[[:space:]]+-e[[:space:]]|php[0-9.]*[[:space:]]+-r[[:space:]]|(^|[[:space:];&|])nc(at)?[[:space:]].*-[ec][[:space:]]|xmrig|minerd|kdevtmpfsi|kinsing'
PERSIST_TMP_LINE='(^|[[:space:];&|`(=])/(tmp|var/tmp|dev/shm)/'
PERSIST_TMP_SCRIPT='(^[[:space:]]*|[;&|`(][[:space:]]*|(exec|nohup|sh|bash|setsid)[[:space:]]+)/(tmp|var/tmp|dev/shm)/'
# persist_suspicious TEXT [script] – prints the first suspicious line (passwords masked); output
# redirections (> /tmp/x.log) don't count, except to /dev/tcp (reverse shell)
persist_suspicious() {
  local re="$PERSIST_SUSPICIOUS|$PERSIST_TMP_LINE" n
  [[ ${2:-} == script ]] && re="$PERSIST_SUSPICIOUS|$PERSIST_TMP_SCRIPT"
  n=$(grep -nE '/dev/(tcp|udp)/' <<<"$1" | head -1) ||
    n=$(sed -E 's/[0-9&]*>>?[[:space:]]*[^[:space:];|&]+//g' <<<"$1" | grep -nEi -- "$re" | head -1)
  [[ -n $n ]] || return 1
  sed -n "${n%%:*}p" <<<"$1" | sed 's/^[[:space:]]*//' | persist_mask | cut -c1-160
}
persist_mask() {   # cron lines may hold passwords (mysqldump -pSECRET, https://user:pw@…): mask them
  sed -E 's/(^|[[:space:]])-p[^[:space:]]+/\1-p***/g
          s/(pass(word|wd)?|pwd|token|secret|api_?key)([=:])[^[:space:]&"'"'"']+/\1\3***/Ig
          s/(--pass(word)?[[:space:]]+)[^[:space:]]+/\1***/Ig
          s#(://[^/:@[:space:]]+:)[^@[:space:]]+@#\1***@#g'
}
# baseline_diff NAME FILE – entries of FILE (one per line) not in $STATE_DIR/baseline/NAME go to
# FILE.add, entries gone from it to FILE.del; then FILE becomes the baseline. Returns 1 on the
# first run (no baseline yet: nothing is reported as new).
baseline_diff() {
  local b="$STATE_DIR/baseline/$1" f=$2 rc=0
  sort -u "$f" -o "$f"
  if [[ -f $b ]]; then comm -13 "$b" "$f" >"$f.add"; comm -23 "$b" "$f" >"$f.del"
  else : >"$f.add"; : >"$f.del"; rc=1; fi
  if can_write_state; then
    mkdir -p "$STATE_DIR/baseline" && cp "$f" "$b.new" && chmod 600 "$b.new" && mv "$b.new" "$b"
  fi
  return $rc
}
persist_first_note() {   # persist_first_note FIRST – suffix of a summary line in the first run
  (( $1 )) || return 0
  if can_write_state; then echo " – first run, stored as baseline"
  else echo " – no baseline yet (stored by the next normal run; --only stores nothing)"; fi
}
# persist_finding SIGN TEXT [ALERT] – a report line under the section (+ new, - gone, ~ changed,
# ! finding) and, with ALERT, an alert; findings matching PERSISTENCE_IGNORE are left out (return 1)
persist_finding() {
  [[ -n $PERSISTENCE_IGNORE && $2 =~ $PERSISTENCE_IGNORE ]] && return 1
  out "  $1 $2"
  [[ -n ${3:-} ]] && alert "$3"
  return 0
}

persist_keys() {   # every authorized SSH key: account TAB fingerprint TAB comment
  local user home f
  local -A seen=()
  while IFS=: read -r user _ _ _ _ home _; do
    [[ -n $home && $home != / ]] || continue
    for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [[ -f $f && -z ${seen[$f]:-} ]] || continue
      seen[$f]=1
      if command -v ssh-keygen >/dev/null; then   # "256 SHA256:… comment (ED25519)"; skips options and bad lines
        T "$CMD_TIMEOUT" ssh-keygen -lf "$f" 2>/dev/null |
          awk -v u="$user" '{ c = ""; for (i = 3; i < NF; i++) c = c (c == "" ? "" : " ") $i
                              t = $NF; gsub(/[()]/, "", t); print u "\t" t " " $2 "\t" c }'
      else                                         # no ssh-keygen: key type and the end of the key
        awk -v u="$user" '!/^[[:space:]]*(#|$)/ {
          for (i = 1; i < NF; i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) {
            c = ""; for (j = i + 2; j <= NF; j++) c = c (c == "" ? "" : " ") $j
            print u "\t" $i " …" substr($(i+1), length($(i+1)) - 15) "\t" c; break } }' "$f"
      fi
    done
  done < <(getent passwd 2>/dev/null)
}
persist_access() {   # accounts with a login shell or UID 0, sudo groups, sudoers files, ld.so.preload
  local g f
  getent passwd 2>/dev/null | awk -F: '$3 == 0 || $7 !~ /(nologin|false|sync|shutdown|halt)$/ {
    print "account\t" $1 "\tuid " $3 ", shell " ($7 == "" ? "/bin/sh (default)" : $7) }'
  for g in sudo wheel admin; do
    getent group "$g" 2>/dev/null | awk -F: -v g="$g" '{ n = split($4, m, ","); for (i = 1; i <= n; i++) if (m[i] != "") print "sudo group\t" m[i] "\tmember of " g }'
  done
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f $f ]] && printf 'sudoers file\t%s\tchecksum %s\n' "$f" "$(md5sum <"$f" | cut -c1-12)"
  done
  [[ -s /etc/ld.so.preload ]] && printf 'preload\t/etc/ld.so.preload\t%s\n' "$(grep -v '^[[:space:]]*#' /etc/ld.so.preload | xargs | cut -c1-200)"
  return 0
}
persist_cron() {   # cron lines: "line TAB where TAB line"; autostart files: "file TAB path TAB checksum"
  local f d
  for d in /var/spool/cron/crontabs /var/spool/cron; do   # Debian/Ubuntu | RHEL-based
    for f in "$d"/*; do
      [[ -f $f ]] || continue
      grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | persist_mask | awk -v w="crontab of ${f##*/}" '{ print "line\t" w "\t" $0 }'
    done
  done
  for f in /etc/crontab /etc/cron.d/*; do
    [[ -f $f ]] || continue
    grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | persist_mask | awk -v w="$f" '{ print "line\t" w "\t" $0 }'
  done
  for f in /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /etc/rc.local \
           /etc/systemd/system/*.service /etc/systemd/system/*.timer; do
    [[ -f $f && ! -L $f ]] && printf 'file\t%s\t%s\n' "$f" "$(md5sum <"$f" | cut -c1-12)"
  done
  return 0
}
# One line per port. The process name is information only: several processes share a socket
# (Postfix: master and smtpd), and ss names whichever comes first – it changes from run to run.
persist_addrs() {   # global IP addresses of the server: "address TAB interface"
  T "$CMD_TIMEOUT" ip -o addr show scope global 2>/dev/null |
    awk '$3 == "inet" || $3 == "inet6" { a = $4; sub(/\/.*/, "", a); print a "\t" $2 }'
}
persist_ports() {   # TCP ports listening on a non-loopback address: "port TAB process"
  T "$CMD_TIMEOUT" ss -ltnp 2>/dev/null | awk '$1 == "LISTEN" {
    a = $4; p = a; sub(/.*:/, "", p); h = a; sub(/:[^:]*$/, "", h)
    if (h ~ /^(127\.|\[?::1\]?$|\[?::ffff:127\.)/ || h ~ /%lo$/) next
    n = "?"; if (match($0, /users:\(\("[^"]+"/)) n = substr($0, RSTART + 9, RLENGTH - 10)
    if (!(p in seen)) { seen[p] = 1; print p "\t" n } }'
}
# persist_procs [FILE] – processes whose program lies in /tmp, /var/tmp, /dev/shm or a web folder,
# exists only in memory, was deleted after start (and not replaced by an update), or that pose
# as a kernel thread. Reads "/proc/PID TAB uid TAB program" (from FILE in tests); prints
# "pid TAB uid TAB reason TAB program"
# shellcheck disable=SC2120   # the argument is for tests only
persist_procs() {
  { if [[ -n ${1:-} ]]; then cat "$1"; else find /proc -mindepth 2 -maxdepth 2 -name exe -printf '%h\t%U\t%l\n' 2>/dev/null; fi
    echo "--ps--"
    ps -eo pid=,args= 2>/dev/null | awk '{ p = $1; sub(/^ *[0-9]+ /, ""); print p "\t" $0 }'
  } | awk -F'\t' -v rf="$TMPD/procs_readable" '
    $0 == "--ps--" { ps = 1; next }
    !ps { pid = $1; sub(/.*\//, "", pid); if (pid !~ /^[0-9]+$/ || $3 == "") next
          nr++; exe[pid] = $3; uid[pid] = $2; next }
    ($1 in exe) { args[$1] = $2 }
    END {
      print nr + 0 > rf
      for (p in exe) {
        e = exe[p]; r = ""
        if (e ~ /^\/(tmp|var\/tmp|dev\/shm)\//)            { d = e; sub(/^\//, "", d); sub(/\/.*/, "", d); if (d == "var") d = "var/tmp"; if (d == "dev") d = "dev/shm"; r = "runs from /" d }
        else if (e ~ /^\/var\/www\//)                       r = "runs from a web folder"
        else if (e ~ /^\/memfd:/) { if (uid[p] != 0)        r = "runs from memory only (memfd), no file on disk" }
        else if (e ~ / \(deleted\)$/)                       r = "DELETED"
        if (r == "" && substr(args[p], 1, 1) == "[")      { k = args[p]; sub(/\].*/, "]", k); r = "poses as a kernel thread " k }
        if (r != "") print p "\t" uid[p] "\t" r "\t" e
      }
    }'
}

check_persistence() {   # SSH keys, accounts, sudo, cron/autostart, suspicious processes, listening ports
  local first w k v c n u what nto pid uid why exe user cmd ports key hit
  local -A gone=() before=() said=()
  section "ACCESS & PERSISTENCE (SSH keys, accounts, sudo, cron, autostart, processes, ports, addresses)"
  nto=$(timeouts_seen)

  # without the account database every key and account would look removed, and new in the next run
  if ! getent passwd root >/dev/null 2>&1; then
    out "SSH keys and accounts: not checked (getent passwd root gives no answer)"
  else
  # --- SSH keys
  persist_keys >"$TMP.k"
  if [[ $(timeouts_seen) != "$nto" ]]; then out "SSH keys: incomplete (time limit) – compared again in the next run"
  else
    first=0; baseline_diff keys "$TMP.k" || first=1
    out "SSH keys (authorized_keys): $(wc -l <"$TMP.k") key(s) of $(cut -f1 "$TMP.k" | sort -u | wc -l) account(s)$(persist_first_note "$first")"
    # same account and fingerprint gone and back = only the comment changed: same access, no alert
    while IFS=$'\t' read -r u k c; do gone["$u"$'\t'"$k"]=$c; done <"$TMP.k.del"
    while IFS=$'\t' read -r u k c; do
      key="$u"$'\t'"$k"
      if [[ -n ${gone[$key]+x} ]]; then
        persist_finding '~' "SSH key for $u: $k – comment changed: ${gone[$key]:-no comment} → ${c:-no comment}"
        unset 'gone[$key]'
      else
        persist_finding + "SSH key for $u: $k${c:+ ($c)}" "Access: new SSH key for $u: $k${c:+ ($c)} – added by you?"
      fi
    done <"$TMP.k.add"
    for key in "${!gone[@]}"; do persist_finding - "SSH key removed for ${key%%$'\t'*}: ${key#*$'\t'}${gone[$key]:+ (${gone[$key]})}"; done
    gone=()
  fi

  # --- accounts with a login shell, sudo, sudoers, ld.so.preload
  persist_access >"$TMP.a"
  first=0; baseline_diff access "$TMP.a" || first=1
  out "Accounts with a login shell: $(grep -c '^account' "$TMP.a") | sudo group members: $(grep -c '^sudo group' "$TMP.a") | sudoers files: $(grep -c '^sudoers file' "$TMP.a")$(persist_first_note "$first")"
  while IFS=$'\t' read -r w k v; do
    [[ $w == account && $k != root && $v == "uid 0,"* ]] && persist_finding '!' "account $k has UID 0 – full root rights under another name" "Access: account $k has UID 0 (root rights under another name) – check it"
    [[ $w == preload ]] && persist_finding '!' "/etc/ld.so.preload loads: $v" \
      "$( ((first)) && echo "Access: /etc/ld.so.preload loads $v – a classic rootkit technique, check it")"
  done <"$TMP.a"
  while IFS=$'\t' read -r w k v; do gone["$w"$'\t'"$k"]=$v; done <"$TMP.a.del"
  while IFS=$'\t' read -r w k v; do
    key="$w"$'\t'"$k"
    if [[ -n ${gone[$key]+x} ]]; then
      persist_finding '~' "$w $k: ${gone[$key]} → $v" "Access: $w $k changed: $v – changed by you?"
      unset 'gone[$key]'
    else
      case $w in
        account)        what="new account with a login shell: $k ($v)" ;;
        "sudo group")   what="$k is now ${v} (sudo rights)" ;;
        "sudoers file") what="new sudoers file $k" ;;
        preload)        what="/etc/ld.so.preload now loads $v – a classic rootkit technique" ;;
        *)              what="$w $k $v" ;;
      esac
      persist_finding + "$what" "Access: $what – done by you?"
    fi
  done <"$TMP.a.add"
  for key in "${!gone[@]}"; do
    w=${key%%$'\t'*}; k=${key#*$'\t'}
    case $w in
      account)        persist_finding - "account $k removed or without login shell now (was: ${gone[$key]})" ;;
      "sudo group")   persist_finding - "$k is no longer ${gone[$key]}" ;;
      "sudoers file") persist_finding - "sudoers file removed: $k" ;;
      *)              persist_finding - "$w $k removed" ;;
    esac
  done
  fi

  # --- cron and autostart
  persist_cron >"$TMP.c"
  [[ -f $STATE_DIR/baseline/cron ]] && while IFS=$'\t' read -r w k _; do before["$k"]=1; done <"$STATE_DIR/baseline/cron"
  first=0; baseline_diff cron "$TMP.c" || first=1
  out "Cron jobs: $(grep -c '^line' "$TMP.c") entr(y/ies) | autostart files (cron.hourly…monthly, rc.local, systemd units in /etc): $(grep -c '^file' "$TMP.c")$(persist_first_note "$first")"
  if (( first )); then   # first run: nothing is new, but already present suspicious content is shown
    cp "$TMP.c" "$TMP.c.add"; : >"$TMP.c.del"
  fi
  gone=()
  while IFS=$'\t' read -r w k v; do [[ $w == file ]] && gone["$k"]=1; done <"$TMP.c.del"
  while IFS=$'\t' read -r w k v; do
    if [[ $w == line ]]; then
      if persist_suspicious "$v" >/dev/null; then
        persist_finding '!' "cron ($k): $v" "Cron: $( ((first)) && echo "entry" || echo "new entry") with suspicious content in $k: $(cut -c1-160 <<<"$v") – check it"
      elif (( ! first )); then
        # a new entry of root or the system (not of a customer's subscription) is rare: alert once
        if [[ -z ${said[$k]:-} ]] && [[ $k == "crontab of root" || -z ${before[$k]:-} && $k == /etc/* ]]; then
          said[$k]=1
          persist_finding + "cron ($k): $v" "Cron: new entry in $k: $(cut -c1-160 <<<"$v") – added by you or a package update?"
        else persist_finding + "cron ($k): $v"; fi
      fi
    else
      c=$(grep -vE '^[[:space:]]*(#|$)' "$k" 2>/dev/null | head -c 20000)
      if hit=$(persist_suspicious "$c" script); then
        persist_finding '!' "autostart file $k contains: $hit" "Cron: $( ((first)) && echo "autostart file" || echo "new or changed autostart file") $k contains suspicious commands: $hit – check it"
      elif (( ! first )); then
        if [[ -n ${gone[$k]:-} ]]; then persist_finding '~' "autostart file changed: $k"
        else persist_finding + "new autostart file: $k" "Cron: new autostart file $k – added by you or a package update?"; fi
      fi
      unset 'gone[$k]'
    fi
  done <"$TMP.c.add"
  while IFS=$'\t' read -r w k v; do
    if [[ $w == line ]]; then persist_finding - "cron ($k): $v"
    elif [[ -n ${gone[$k]:-} ]]; then persist_finding - "autostart file removed: $k"; fi
  done <"$TMP.c.del"

  # --- processes (live state, no baseline: reported in every run while they run)
  persist_procs >"$TMP.p"
  n=$(cat "$TMPD/procs_readable" 2>/dev/null || echo 0)
  if (( n == 0 )); then
    out "Processes: program paths not readable (/proc/<pid>/exe – container without that right?) – not checked"
  else
    c=0
    while IFS=$'\t' read -r pid uid why exe; do
      if [[ $why == DELETED ]]; then
        [[ -e ${exe% (deleted)} ]] && continue        # replaced by an update, only a restart is pending
        why="program deleted after start"
      fi
      user=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1); user=${user:-uid $uid}
      cmd=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | cut -c1-120 | sed 's/ *$//')
      persist_finding '!' "process $pid of $user $why: $exe${cmd:+ – $cmd}" "Process: PID $pid of $user $why: $exe – crypto miner or backdoor? Check it" &&
        c=$((c + 1))
    done <"$TMP.p"
    out "Processes: $n checked, $c suspicious (program in /tmp, /dev/shm or a web folder, deleted, memory only, fake kernel thread)"
  fi

  # --- listening ports
  if ! command -v ss >/dev/null; then
    out "Listening ports: not checked (no ss command, package iproute2)"
  else
    nto=$(timeouts_seen)
    persist_ports >"$TMP.o"
    if [[ $(timeouts_seen) != "$nto" || ! -s $TMP.o ]]; then out "Listening ports: could not be read (ss gave no answer) – compared again in the next run"
    else
      # compared by port number only – the process name of a port is not stable (see persist_ports)
      local -A oldp=()
      first=1
      if [[ -f $STATE_DIR/baseline/ports ]]; then
        first=0
        while IFS=$'\t' read -r k v; do [[ -n $k ]] && oldp[$k]=${v:-?}; done <"$STATE_DIR/baseline/ports"
      fi
      baseline_diff ports "$TMP.o"
      ports=$(sort -t$'\t' -k1,1n "$TMP.o" | awk -F'\t' '{ printf "%s%s %s", (NR > 1 ? ", " : ""), $1, $2 }')
      out "Listening TCP ports (not loopback): ${ports:-none}$(persist_first_note "$first")"
      while IFS=$'\t' read -r k v; do
        if (( ! first )) && [[ -z ${oldp[$k]+x} ]]; then
          persist_finding + "listening port $k ($v)" "Ports: new listening TCP port $k ($v) – started by you?"
        fi
        unset 'oldp[$k]'
      done <"$TMP.o"
      for k in "${!oldp[@]}"; do persist_finding - "listening port $k (${oldp[$k]}) closed"; done
    fi
  fi

  # --- IP addresses of the server: a hosting provider may switch on IPv6 (or add an address)
  # without notice, and mail then leaves from an address without reverse DNS and SPF entry
  if command -v ip >/dev/null; then
    persist_addrs >"$TMP.o"
    first=0; baseline_diff addrs "$TMP.o" || first=1
    out "IP addresses (global): $(awk -F'\t' '{ printf "%s%s (%s)", (NR > 1 ? ", " : ""), $1, $2 }' "$TMP.o")$(persist_first_note "$first")"
    while IFS=$'\t' read -r k v; do
      [[ -n $k ]] || continue
      if [[ $k =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|f[cd]) ]]; then
        persist_finding + "address $k on $v (private network)"
      else
        persist_finding + "address $k on $v" "Network: new public address $k on $v – added by you, or by the hosting provider? Mail may now leave from it: check reverse DNS and SPF, or keep the mail server on the old address (Postfix: inet_protocols, smtp_bind_address)"
      fi
    done <"$TMP.o.add"
    while IFS=$'\t' read -r k v; do [[ -n $k ]] && persist_finding - "address $k on $v removed"; done <"$TMP.o.del"
  fi
  return 0
}

check_services() {   # failed systemd units, OOM killer
  local FAILED OOM
  section "SERVICES"
  if command -v systemctl >/dev/null; then
    FAILED=$(T "$CMD_TIMEOUT" systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | xargs)
    out "Failed units: ${FAILED:-none}"
    [[ -n $FAILED ]] && alert "Service(s) failed: $FAILED"
  fi
  if command -v journalctl >/dev/null; then
    OOM=$(T "$CMD_TIMEOUT" journalctl -k --since "@$SINCE" 2>/dev/null | grep -iE 'out of memory|oom-kill|killed process' | grep -oE 'Killed process [0-9]+ \([^)]+\)' | sort | uniq -c | xargs)
    out "OOM killer: ${OOM:-none}"
    [[ -n $OOM ]] && alert "RAM: the kernel killed processes due to low memory: $OOM"
  fi
  return 0
}

check_backups() {   # latest Plesk backup (time, age, errors), Acronis agent – every run, so the age is current
  local pmm last age st now mt
  now=$(date +%s)
  section "BACKUPS"
  for pmm in /var/log/plesk/PMM /usr/local/psa/PMM/logs /opt/psa/PMM/logs; do [[ -d $pmm ]] && break; pmm=""; done
  if [[ -n $pmm ]]; then
    last=$(T "$CMD_TIMEOUT" find -L "$pmm" -maxdepth 2 -type d -name 'backup-*' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)
    if [[ -n $last ]]; then
      mt=$(stat -c %Y "$last"); age=$(( (now - mt) / 3600 ))
      local blog="$last/backup.log" nerr=0 nwarn=0 ec="" ex=""
      if [[ -r $blog ]]; then
        nerr=$(grep -cE '\] (ERROR|CRITICAL|FATAL):' "$blog"); nwarn=$(grep -cE '\] WARNING:' "$blog")
        ec=$(grep -oE 'Exit code: [0-9]+' "$blog" | tail -1 | grep -oE '[0-9]+$')
        ex=$(grep -m1 -E '\] (ERROR|CRITICAL|FATAL):' "$blog" | cut -c1-220)
      fi
      if [[ ! -r $blog ]]; then st="unknown (no backup.log)"
      elif (( nerr > 0 )) || [[ -n $ec && $ec != 0 ]]; then st="ERROR ($nerr error lines, exit code ${ec:-?})"
      elif (( nwarn > 0 )); then st="OK with $nwarn warnings"
      else st="OK (exit code ${ec:-?})"; fi
      out "Plesk backup: last run $(date -d "@$mt" '+%Y-%m-%d %H:%M %Z') ($age h ago, $(basename "$last")), status: $st"
      [[ -n $ex ]] && out "  first error: $ex"
      (( age > WARN_BACKUP_HOURS )) && alert "Backup: latest Plesk backup is $age hours old"
      [[ $st == ERROR* ]] && alert "Backup: latest Plesk backup finished with errors"
    else
      out "Plesk backup: no backup logs found in $pmm"
    fi
  else
    out "Plesk backup: log directory not found"
  fi
  # Acronis agent (used by several hosting providers for image backups) – only if installed
  if pgrep -x aakore >/dev/null || pgrep -f '[a]cronis' >/dev/null; then
    out "Acronis agent: running"
  elif [[ -d /usr/lib/Acronis || -d /opt/acronis || -d /var/lib/Acronis ]]; then
    out "Acronis agent: installed but NOT running"; alert "Backup: Acronis agent is not running"
  fi
  return 0
}

# =============================================================================
# Daily checks – write their section text to stdout, alerts via dalert
# =============================================================================

# A newer kernel is installed than the one running? Fallback where the distribution's own signal
# is missing: /var/run/reboot-required only exists where a package writes it (Debian/Ubuntu:
# unattended-upgrades, update-notifier-common), needs-restarting needs dnf-utils (RHEL family).
# Only if the running kernel is one from /boot – a container or a provider kernel can't be compared.
kernel_reboot_check() {
  local run new k
  run=$(uname -r)
  [[ -e /boot/vmlinuz-$run ]] || return 0
  new=$(for k in /boot/vmlinuz-*; do echo "${k#/boot/vmlinuz-}"; done | sort -V | tail -1)
  if [[ -n $new && $new != "$run" ]]; then
    echo "Reboot required: kernel $run is running, $new is installed"
    dalert "System: reboot required – kernel $new is installed, $run is still running"
  fi
  return 0
}
check_updates() {   # pending (security) updates, reboot required
  local upg sec
  if command -v apt-get >/dev/null; then
    # --with-new-pkgs: plain "upgrade" leaves out every update that needs a new package – on
    # Debian/Ubuntu that is nearly every kernel update (linux-image-<new version>)
    # (an apt too old for the option falls back to the plain simulation)
    upg=$(T "$CMD_TIMEOUT" apt-get -s -o Debug::NoLocking=1 --with-new-pkgs upgrade 2>/dev/null) ||
      upg=$(T "$CMD_TIMEOUT" apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null)
    upg=$(grep '^Inst' <<<"$upg" || true)
    sec=$(grep -ci 'security' <<<"$upg" || true)
    echo "Updates available: $(grep -c . <<<"$upg" || true), security updates: $sec"
    grep -i security <<<"$upg" | awk '{print "  " $2}' | head -10
    (( sec > 0 )) && dalert "Updates: $sec security update(s) pending"
    if [[ -f /var/run/reboot-required ]]; then
      echo "Reboot required (since $(date -r /var/run/reboot-required '+%Y-%m-%d'))"
      dalert "System: reboot required after updates"
    else kernel_reboot_check; fi
  elif command -v dnf >/dev/null; then
    sec=$(T "$CMD_TIMEOUT" dnf -q updateinfo list --security 2>/dev/null | grep -c . || true)
    echo "Security updates available: $sec"
    (( sec > 0 )) && dalert "Updates: $sec security update(s) pending"
    if command -v needs-restarting >/dev/null; then
      if ! needs-restarting -r >/dev/null 2>&1; then
        echo "Reboot required"; dalert "System: reboot required after updates"
      fi
    else kernel_reboot_check; fi                       # needs-restarting (dnf-utils) is not installed
  fi
  (( UPDATE_CHECK )) && script_update_check
  return 0
}

# Is there a newer release of this script? One request to the GitHub API, once a day. Info only,
# no alert: the update is never installed automatically.
SCRIPT_REPO=cmelius/plesk-monitoring-server-Report
script_update_check() {
  local latest newest
  command -v curl >/dev/null || return 0
  latest=$(T 20 curl -fsS --connect-timeout 5 --max-time 15 -H 'Accept: application/vnd.github+json' \
             "https://api.github.com/repos/$SCRIPT_REPO/releases/latest" 2>/dev/null |
           sed -n 's/.*"tag_name": *"v\{0,1\}\.\{0,1\}\([0-9][0-9.]*\)".*/\1/p' | head -1)
  if [[ -z $latest ]]; then
    echo "Script version: $VERSION (update check failed – no answer from GitHub; UPDATE_CHECK=0 switches it off)"
  elif [[ $latest == "$VERSION" ]]; then
    echo "Script version: $VERSION (latest release)"
  else
    newest=$(printf '%s\n%s\n' "$VERSION" "$latest" | sort -V | tail -1)
    if [[ $newest == "$latest" ]]; then
      echo "Script version: $VERSION – version $latest is available: https://github.com/$SCRIPT_REPO/releases/latest"
    else
      echo "Script version: $VERSION (newer than the latest release $latest – development version from main)"
    fi
  fi
}

# Certificates of all sites, fetched live from the server's public IP (cached for this run):
# CERT_INFO[domain] = openssl output (end date, issuer, SAN) or empty; LE_DOMAINS = Let's Encrypt sites
declare -A CERT_INFO=()
cert_scan() {
  local d port
  [[ -n ${LE_DOMAINS+x} ]] && return 0
  LE_DOMAINS=""
  for d in $(site_domains); do
    port=443; [[ $d == "$HOST" ]] && port=8443
    CERT_INFO[$d]=$(echo | timeout 6 openssl s_client -connect "${PUBIP:-127.0.0.1}:$port" -servername "$d" 2>/dev/null | openssl x509 -noout -enddate -issuer -ext subjectAltName 2>/dev/null)
    grep -qi "Let's Encrypt" <<<"${CERT_INFO[$d]}" && LE_DOMAINS+=" $d"
  done
  return 0
}
check_certificates() {   # expiry of all site certificates and the panel certificate
  local now d c end days san soon=0 nossl=""
  echo ""; echo "TLS certificates:"
  cert_scan
  now=$(date +%s)
  for d in $(site_domains); do
    c=${CERT_INFO[$d]}
    [[ -z $c ]] && { nossl+=" $d"; continue; }
    san=$(grep -o 'DNS:[^,]*' <<<"$c" | sed 's/DNS://' | xargs)
    if ! grep -qwF -- "$d" <<<"$san" && ! grep -qF -- "*.${d#*.}" <<<"$san"; then nossl+=" $d"; continue; fi
    end=$(sed -n 's/^notAfter=//p' <<<"$c"); days=$(( ($(date -d "$end" +%s) - now) / 86400 ))
    if (( days < WARN_CERT_DAYS )); then
      echo "  $d: expires in $days days ($end)"; soon=$((soon + 1))
      dalert "TLS: certificate of $d expires in $days days"
    fi
  done
  (( soon == 0 )) && echo "  all valid certificates are good for at least $WARN_CERT_DAYS more days"
  [[ -n $nossl ]] && echo "  no matching certificate (e.g. no SSL, mail-only, redirect):$nossl"
}

# https_head URL DOMAIN – response headers of one request to this server (no redirects followed)
https_head() {
  curl -skI --max-time 6 --resolve "$2:443:$PUBIP" --resolve "www.$2:443:$PUBIP" \
       --resolve "$2:80:$PUBIP" --resolve "www.$2:80:$PUBIP" "$1" 2>/dev/null | tr -d '\r'
}
# same_site URL DOMAIN – true if URL points to DOMAIN or www.DOMAIN (redirects worth following)
same_site() { [[ $1 =~ ^https?://(www\.)?${2//./\\.}(:[0-9]+)?(/|$) ]]; }

check_https() {   # HSTS header and http→https redirect on domains with a valid certificate that point here
  local now d c san end h loc a n=0 skip=0 nohsts="" noredir="" noans=""
  echo ""; echo "HTTPS (HSTS and http→https redirect; domains with a valid certificate that point here):"
  [[ -n ${PUBIP:-} ]] || { echo "  skipped: public IP of the server unknown"; return 0; }
  command -v curl >/dev/null || { echo "  skipped: curl not installed"; return 0; }
  cert_scan
  now=$(date +%s)
  for d in $(site_domains); do
    [[ $d == "$HOST" || $d =~ ^[0-9.]+$ ]] && continue
    # only domains whose certificate is valid for them – the others can't use HSTS (aliases, redirects, mail-only)
    c=${CERT_INFO[$d]}; [[ -z $c ]] && continue
    san=$(grep -o 'DNS:[^,]*' <<<"$c" | sed 's/DNS://' | xargs)
    grep -qwF -- "$d" <<<"$san" || grep -qF -- "*.${d#*.}" <<<"$san" || continue
    end=$(sed -n 's/^notAfter=//p' <<<"$c"); (( $(date -d "$end" +%s 2>/dev/null || echo 0) > now )) || continue
    # only domains that point here – elsewhere (CDN, other hoster) this server's headers don't matter
    a=$(DIGQ A "$d" | grep -E '^[0-9.]+$' | xargs)
    [[ " $a " == *" $PUBIP "* ]] || { skip=$((skip + 1)); continue; }
    n=$((n + 1))
    # HSTS: on the first answer, or after one redirect to the same site (domain ↔ www)
    h=$(https_head "https://$d/" "$d")
    if [[ -z $h ]]; then noans+=" $d"; continue; fi
    if ! grep -qi '^strict-transport-security:' <<<"$h"; then
      loc=$(sed -n 's/^[Ll]ocation: *//p' <<<"$h" | head -1)
      if [[ $loc == https://* ]] && same_site "$loc" "$d"; then h=$(https_head "$loc" "$d"); fi
      grep -qi '^strict-transport-security:' <<<"$h" || nohsts+=" $d"
    fi
    # http → https: a redirect to https (directly or after one hop to www/without www); port 80 closed is fine too
    h=$(https_head "http://$d/" "$d")
    if [[ -n $h ]]; then
      loc=$(sed -n 's/^[Ll]ocation: *//p' <<<"$h" | head -1)
      if [[ $loc == http://* ]] && same_site "$loc" "$d"; then
        h=$(https_head "$loc" "$d"); loc=$(sed -n 's/^[Ll]ocation: *//p' <<<"$h" | head -1)
      fi
      [[ $loc == https://* ]] || noredir+=" $d"
    fi
  done
  [[ -n $noans ]] && echo "  no answer on https (timeout or error):$noans"
  if [[ -z $nohsts && -z $noredir ]]; then
    echo "  $n domain(s) checked, all send HSTS and redirect http to https"
  else
    [[ -n $nohsts ]] && echo "  no HSTS:$nohsts"
    [[ -n $noredir ]] && echo "  no redirect from http to https:$noredir"
    echo "  security can be improved (Plesk: Websites & Domains → SSL/TLS Certificates → HSTS / Redirect from http to https)"
    echo "  $n domain(s) checked"
  fi
  (( skip )) && echo "  $skip domain(s) with a certificate point elsewhere and were skipped"
  return 0
}

check_serverdns() {   # PTR of the server IP, HELO name, IPv6 reverse DNS
  local ptr fwd helo
  echo ""; echo "Server DNS (reverse DNS / HELO):"
  ptr=$(DIGQ -x "$PUBIP" | head -1); ptr=${ptr%.}
  helo=$(postconf -h smtp_helo_name 2>/dev/null)
  # shellcheck disable=SC2016  # the literal Postfix default "$myhostname", not a shell variable
  [[ -z $helo || $helo == '$myhostname' ]] && helo=$(postconf -h myhostname 2>/dev/null)
  if [[ -z $ptr ]]; then
    echo "  $PUBIP: NO PTR record"
    dalert "Mail: server IP $PUBIP has no reverse DNS (PTR) – many receivers (Gmail, Microsoft, T-Online) reject such mail; set it at your hosting provider"
  else
    if host_has_ip "$ptr" "$PUBIP"; then fwd="ok (forward-confirmed)"
    else fwd="does NOT resolve back to $PUBIP"
      dalert "Mail: reverse DNS $PUBIP → $ptr does not resolve back to the IP – fix A record or PTR"
    fi
    echo "  $PUBIP → $ptr: $fwd"
  fi
  if [[ -n $helo ]]; then
    if host_has_ip "$helo" "$PUBIP"; then echo "  Postfix HELO name: $helo (resolves to this server$([[ $helo == "$ptr" ]] && echo ", matches PTR"))"
    else echo "  Postfix HELO name: $helo – does NOT resolve to $PUBIP"
      dalert "Mail: Postfix HELO name $helo does not resolve to $PUBIP – set myhostname/smtp_helo_name to the PTR name ${ptr:-?}"
    fi
  fi
  if [[ -n $PUBIP6 ]]; then
    ptr=$(DIGQ -x "$PUBIP6" | head -1); ptr=${ptr%.}
    if [[ -z $ptr ]]; then
      echo "  $PUBIP6 (IPv6): NO PTR record"
      dalert "Mail: server IPv6 $PUBIP6 has no reverse DNS – Gmail rejects IPv6 mail without it; set the PTR or send over IPv4 only (postconf -e 'inet_protocols = ipv4', restart Postfix; Plesk may reset it after 'plesk repair mail' or updates)"
    elif host_has_ip "$ptr" "$PUBIP6"; then echo "  $PUBIP6 → $ptr: ok (forward-confirmed)"
    else echo "  $PUBIP6 → $ptr: does NOT resolve back (no matching AAAA)"
      dalert "Mail: IPv6 reverse DNS $PUBIP6 → $ptr has no matching AAAA record – Gmail rejects IPv6 mail without it; add the AAAA record (and the address to SPF) or send over IPv4 only (postconf -e 'inet_protocols = ipv4', restart Postfix; Plesk may reset it after 'plesk repair mail' or updates)"
    fi
  else
    echo "  IPv6: not used for mail (CHECK_IPV6=$CHECK_IPV6)"
  fi
}

check_mailtls() {   # certificate of the mail server on the mail ports
  local name=${MAIL_TLS_NAME:-$HOST} p st c end days chk bad=0
  echo ""; echo "Mail server certificates for $name:"
  for p in $MAIL_TLS_PORTS; do
    case $p in 25|587) st="-starttls smtp" ;; 143) st="-starttls imap" ;; 110) st="-starttls pop3" ;; *) st="" ;; esac
    # shellcheck disable=SC2086  # $st is empty or two words ("-starttls smtp") – split on purpose
    c=$(echo | timeout 8 openssl s_client -connect "${PUBIP:-127.0.0.1}:$p" -servername "$name" $st 2>/dev/null | openssl x509 2>/dev/null)
    if [[ -z $c ]]; then echo "  port $p: no TLS certificate (port closed or no TLS)"; continue; fi
    end=$(openssl x509 -noout -enddate <<<"$c" | sed 's/^notAfter=//'); days=$(( ($(date -d "$end" +%s) - $(date +%s)) / 86400 ))
    if openssl x509 -noout -checkhost "$name" <<<"$c" 2>/dev/null | grep -q 'does match'; then chk="name ok"
    else chk="NAME MISMATCH"; bad=1; dalert "TLS: mail certificate on port $p is not valid for $name – mail clients will show certificate warnings"; fi
    if (( days < 0 )); then chk+=", EXPIRED"; bad=1; dalert "TLS: mail certificate on port $p has expired ($end)"
    elif (( days < WARN_CERT_DAYS )); then chk+=", expires in $days days"; bad=1; dalert "TLS: mail certificate on port $p expires in $days days"
    else chk+=", valid $days more days"; fi
    echo "  port $p: $chk"
  done
}

check_domaindns() {   # still pointing here?, CAA vs. Let's Encrypt, DNSSEC, domain blocklists
  local d st a aaaa here caa par n=0 out="" r bl
  cert_scan   # Let's Encrypt sites for the CAA check
  BL_REFUSED=""
  for d in $(site_domains); do
    [[ $d == "$HOST" || $d =~ ^[0-9.]+$ ]] && continue
    n=$((n + 1))
    st=$(dig_status "$d" A)
    if [[ $st == SERVFAIL ]]; then
      if [[ $(dig +cd +time=3 +tries=2 ${MAILAUTH_RESOLVER:+"@$MAILAUTH_RESOLVER"} A "$d" 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1) == NOERROR ]]; then
        out+="  $d: DNSSEC broken – validating resolvers cannot resolve the domain"$'\n'
        dalert "DNS: $d does not resolve for validating resolvers – DNSSEC is broken (DS record at the registrar vs. zone signing)"
      else
        out+="  $d: SERVFAIL – name servers not answering"$'\n'
        dalert "DNS: $d does not resolve (SERVFAIL) – website and mail unreachable"
      fi
      continue
    fi
    [[ $st == NXDOMAIN ]] && { out+="  $d: does not exist in public DNS (NXDOMAIN)"$'\n'; continue; }
    # does the domain still point here?
    a=$(DIGQ A "$d" | grep -E '^[0-9.]+$' | xargs); here=0
    [[ " $a " == *" $PUBIP "* ]] && here=1
    if (( ! here )) && [[ -n $a ]]; then
      geo "${a%% *}"; out+="  $d: website points elsewhere ($a${GEO_LABEL:+, $GEO_LABEL}) – moved? CDN?"$'\n'
    elif [[ -z $a ]]; then out+="  $d: no A record"$'\n'; fi
    if [[ -n ${PUBIP6:-} ]]; then
      aaaa=$(DIGQ AAAA "$d" | grep ':' | xargs)
      [[ -n $aaaa && " $aaaa " != *" $PUBIP6 "* ]] && (( here )) &&
        out+="  $d: AAAA ($aaaa) differs from A – IPv6 visitors reach another server"$'\n'
    fi
    # CAA: issuance by Let's Encrypt allowed? (CAA is inherited from parent domains)
    if [[ " $LE_DOMAINS " == *" $d "* ]]; then
      par=$d; caa=""
      while [[ $par == *.* && -z $caa ]]; do caa=$(DIGQ CAA "$par" | grep -i 'issue'); [[ -z $caa ]] && par=${par#*.}; done
      if [[ -n $caa ]] && ! grep -qi 'issue.*letsencrypt\.org' <<<"$caa"; then
        out+="  $d: CAA ($par) does not allow Let's Encrypt – renewal will fail"$'\n'
        dalert "TLS: CAA record of $par does not allow Let's Encrypt – the certificate of $d cannot be renewed"
      fi
    fi
    # domain blocklists (listed domains: phishing/malware on a hacked site, or spam links)
    for bl in $DOMAIN_BLOCKLISTS; do
      r=$(getent ahostsv4 "$d.$bl" 2>/dev/null | awk 'NR==1{print $1}')
      [[ -z $r ]] && continue
      case "$bl:$r" in
        *:127.255.255.*|dbl.spamhaus.org:127.0.1.255|multi.surbl.org:127.0.0.1) BL_REFUSED+=" $bl" ;;
        *) out+="  $d: LISTED on $bl ($r)"$'\n'
           dalert "DNS: domain $d is listed on $bl ($r) – mails mentioning it get rejected; check the website for malware/phishing" ;;
      esac
    done
  done
  echo ""; echo "Domain DNS (points here? CAA, DNSSEC, domain blocklists):"
  [[ -n $out ]] && printf '%s' "$out"
  echo "  $n domain(s) checked, findings listed above"
  [[ -n ${BL_REFUSED:-} ]] && echo "  note: some blocklists refused queries from this resolver:$(tr ' ' '\n' <<<"$BL_REFUSED" | sort -u | xargs -r echo ' ')"
  return 0
}

check_exposed() {   # .env, .git, dumps, backups, config copies in document roots (with reachability test)
  local dom root f rel code out="" n=0 found=0 pub=0 nblk ex nerr exerr
  echo ""; echo "Exposed files in document roots (.env, .git, dumps, backups, config copies, info/admin tools):"
  while IFS=$'\t' read -r dom root; do
    [[ -d $root ]] || continue
    n=$((n + 1)); nblk=0; ex=""; nerr=0; exerr=""
    while IFS= read -r f; do
      [[ -n $EXPOSED_FILES_IGNORE && $f =~ $EXPOSED_FILES_IGNORE ]] && continue
      rel=${f#"$root"}; [[ -d $f ]] && rel+="/"
      # is it really reachable from the internet?
      code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 --resolve "$dom:443:${PUBIP:-127.0.0.1}" "https://$dom$rel$([[ -d $f ]] && echo HEAD)" 2>/dev/null)
      found=$((found + 1))
      if [[ $code == 200 ]]; then
        out+="  $dom$rel – PUBLICLY REACHABLE (HTTP 200)"$'\n'; pub=$((pub + 1))
        dalert "Web: $dom exposes $rel publicly (HTTP 200) – remove it from the document root or block access, then check again: $(basename "$0") --only exposed"
      elif [[ $code == 403 || $code == 401 ]]; then
        nblk=$((nblk + 1)); [[ -z $ex ]] && ex="$rel"
      else
        nerr=$((nerr + 1)); [[ -z $exerr ]] && exerr="$rel (HTTP ${code:-no answer})"
      fi
    done < <(T "$FIND_TIMEOUT" find "$root" -maxdepth 6 \( -path '*/node_modules' -o -path '*/wp-content/cache' -o -path '*/vendor/*/tests' \) -prune -o \
               \( \( -type d -name .git \) -o \( -type d -name .svn \) \
                  -o \( -type f \( -name '.env' -o -name '.env.*' -o -iname '*.sql' -o -iname '*.sql.gz' -o -iname '*.sql.zip' \
                       -o -name 'wp-config.php.*' -o -name 'wp-config.php~' -o -name '.htpasswd' -o -name 'id_rsa' -o -name 'phpinfo.php' \
                       -o -iname 'adminer*.php' \
                       -o -iregex '.*/\(backup\|backups\|dump\|db\|database\|site\|www\|httpdocs\|wordpress\)[^/]*\.\(zip\|tar\|tgz\|tar\.gz\|gz\|7z\|rar\)' \) \) \) \
               -print -prune 2>/dev/null | head -200)
    (( nblk )) && out+="  $dom: $nblk file(s) found but blocked by the web server (HTTP 403), e.g. $ex"$'\n'
    (( nerr )) && out+="  $dom: $nerr file(s) found, not served (server error/no answer), e.g. $exerr"$'\n'
  done < <(docroots)
  [[ -n $out ]] && printf '%s' "$out"
  echo "  $n document root(s) scanned, $found finding(s); only publicly reachable ones raise an alert"
  (( pub )) && echo "  This list is from the daily check (see \"As of\") and repeats until the next one. After fixing a file, check again right away: $(basename "$0") --only exposed – or rm $STATE_DIR/daily_date to refresh the daily checks in the next run"
  return 0
}
# "Recently changed" = by file date (mtime) or by inode change time (ctime): a backdated file
# (PHP touch()) still has a fresh ctime.
# .htaccess / .user.ini / php.ini: settings that make the web server run attacker code – a file
# loaded before every PHP request (auto_prepend_file/auto_append_file, except known security
# plugins), PHP executed for image or text files, and the signature of a widespread WordPress
# malware campaign that blocks every PHP file except its own. Prints "FILE<TAB>LINE" per hit.
php_config_backdoors() {   # php_config_backdoors < list of files
  # shellcheck disable=SC2016  # awk program: its $0 is awk's, not the shell's
  T "$FIND_TIMEOUT" xargs -r -d '\n' awk '
    FNR == 1 { img = 0; done_ = 0 }
    done_ { next }
    { l = tolower($0); sub(/^[ \t]+/, "", l) }
    l ~ /^[#;]/ { next }
    l ~ /auto_(prepend|append)_file/ && l !~ /(wordfence-waf|ninjafirewall|sucuri)/ && l !~ /auto_(prepend|append)_file[ \t=]+"?(none)?"?[ \t]*$/ { hit(); next }
    l ~ /(addhandler|addtype)[^#]*php/ && l ~ /\.(jpe?g|png|gif|ico|bmp|svg|webp|txt)([ \t$]|$)/ { hit(); next }
    l ~ /<filesmatch[^>]*(jpe?g|png|gif|ico|bmp|svg|webp|txt)/ { img = 1 }
    img && l ~ /sethandler[^#]*php/ { hit(); next }
    l ~ /<\/filesmatch/ { img = 0 }
    l ~ /<filesmatch[^>]*\.\(py\|exe\|php\)/ { hit(); next }
    function hit() { printf "%s\t%s\n", FILENAME, substr($0, 1, 160); done_ = 1 }
  ' 2>/dev/null
}
check_webshell() {   # recently changed PHP files with typical backdoor code, PHP settings in .htaccess/.user.ini
  local stamp="$STATE_DIR/webshell_scan" new="$STATE_DIR/webshell_scan.new" dom root out="" n=0 hits=0 f nto ln
  # shellcheck disable=SC2016  # a grep pattern: $_POST etc. are PHP, not shell variables
  local re='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|gzdecode)[[:space:]]*\(|assert[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)|\$_(POST|GET|REQUEST|COOKIE)[[:space:]]*\[[^]]*\][[:space:]]*\(|preg_replace[[:space:]]*\([[:space:]]*["'"'"'][^"'"'"']*/e["'"'"']|create_function[[:space:]]*\([^)]*\$_(POST|GET|REQUEST)|(system|shell_exec|passthru|exec|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)'
  can_write_state && touch "$new"
  nto=$(timeouts_seen)
  echo ""; echo "Suspicious code in recently changed PHP files, .htaccess and .user.ini (typical webshell/backdoor patterns):"
  while IFS=$'\t' read -r dom root; do
    [[ -d $root ]] || continue
    n=$((n + 1))
    while IFS= read -r f; do
      [[ -n $WEBSHELL_IGNORE && $f =~ $WEBSHELL_IGNORE ]] && continue
      hits=$((hits + 1))
      out+="  $f (file date $(date -r "$f" '+%Y-%m-%d %H:%M'), last change $(date -d "@$(stat -c %Z "$f" 2>/dev/null || echo 0)" '+%Y-%m-%d %H:%M'))"$'\n'
      dalert "Web: suspicious code in recently changed file $f – check it (webshell/backdoor?)"
    done < <(if [[ -f $stamp ]]; then T "$FIND_TIMEOUT" find "$root" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[0-9]' \) \( -newer "$stamp" -o -cnewer "$stamp" \) 2>/dev/null
             else T "$FIND_TIMEOUT" find "$root" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[0-9]' \) \( -mtime -"$WEBSHELL_FIRST_DAYS" -o -ctime -"$WEBSHELL_FIRST_DAYS" \) 2>/dev/null; fi |
             T "$FIND_TIMEOUT" xargs -r -d '\n' grep -lE "$re" 2>/dev/null | head -30)
    while IFS=$'\t' read -r f ln; do
      [[ -n $WEBSHELL_IGNORE && $f =~ $WEBSHELL_IGNORE ]] && continue
      hits=$((hits + 1))
      out+="  $f: $ln (file date $(date -r "$f" '+%Y-%m-%d %H:%M'))"$'\n'
      dalert "Web: suspicious PHP setting in recently changed $f: $ln – check it (backdoor?)"
    # these files are few and small: the first scan (and the first after the update that added
    # them) checks all of them, whatever their date – a backdoor may be older than the script
    done < <(if [[ -f $stamp && -f $STATE_DIR/webshell_conf_full ]]; then T "$FIND_TIMEOUT" find "$root" -type f \( -name .htaccess -o -name .user.ini -o -name php.ini \) \( -newer "$stamp" -o -cnewer "$stamp" \) 2>/dev/null
             else T "$FIND_TIMEOUT" find "$root" -type f \( -name .htaccess -o -name .user.ini -o -name php.ini \) 2>/dev/null; fi |
             php_config_backdoors | head -30)
  done < <(docroots)
  # after a timeout the scan was incomplete: keep the old stamp, so the next scan looks again
  if [[ $(timeouts_seen) == "$nto" ]]; then can_write_state && { mv "$new" "$stamp"; : >"$STATE_DIR/webshell_conf_full"; }; fi
  [[ -n $out ]] && printf '%s' "$out"
  echo "  $n document root(s) scanned, $hits suspicious file(s)"
}

# Plesk domain aliases: ALIAS_OF[alias]=primary domain, ALIAS_MAIL[alias]=true|false (mail service of the alias)
declare -A ALIAS_OF=() ALIAS_MAIL=()
load_aliases() {
  local a m p
  command -v plesk >/dev/null || return 0
  while IFS=$'\t' read -r a m p; do
    [[ -n $a ]] || continue
    ALIAS_OF[$a]=$p; ALIAS_MAIL[$a]=$m
  done < <(T "$CMD_TIMEOUT" plesk db -Ne "SELECT a.name, a.mail, d.name FROM domain_aliases a JOIN domains d ON d.id = a.dom_id" 2>/dev/null)
  return 0
}
mailauth_scan() {
  local d doms ok=0 bad=0 nomail=0 spf spf_ok dkim dmarc mxinfo mxhere ns line key dnskey m nmb probs mailoff note
  load_aliases
  [[ -n $MAILNAMES_DIR && -d $MAILNAMES_DIR ]] ||
    note "mailauth: mailbox directory MAILNAMES_DIR=\"$MAILNAMES_DIR\" not found – mailbox counts are 0"
  doms=$( { ls "$MAILNAMES_DIR" 2>/dev/null; ls "$DKIM_KEY_DIR" 2>/dev/null; } | sort -u)
  for d in $doms; do
    [[ $d == *.* && " $MAILAUTH_IGNORE_DOMAINS " != *" $d "* ]] || continue
    nmb=$(T "$CMD_TIMEOUT" find "$MAILNAMES_DIR/$d" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | grep -vc '/@')
    # MX: is mail for this domain hosted here?
    mxhere=0; mxinfo=""
    for m in $(DIGQ MX "$d" | awk '{print $2}'); do
      if host_has_ip "${m%.}" "$PUBIP"; then mxhere=1; else mxinfo+="${mxinfo:+,}${m%.}"; fi
    done
    (( nmb == 0 && mxhere == 0 )) && [[ -z $mxinfo ]] && continue     # no MX, no mailboxes → no mail
    # SPF
    spf_eval "$d" "$PUBIP"; spf=$SPF_RES; spf_ok=0
    [[ $spf == pass ]] && spf_ok=1
    (( SPF_PLUSALL )) && spf="+all"
    if [[ -n ${PUBIP6:-} ]]; then   # server sends via IPv6 too: SPF must cover both addresses
      spf_eval "$d" "$PUBIP6"
      if [[ $SPF_RES != pass ]]; then spf+="/v6:${SPF_RES%%:*}"; spf_ok=0; fi
    fi
    # DKIM: compare the public key in DNS with the private key on this server
    dkim="off"
    if [[ -r $DKIM_KEY_DIR/$d/$DKIM_SELECTOR ]]; then
      key=$(openssl rsa -in "$DKIM_KEY_DIR/$d/$DKIM_SELECTOR" -pubout -outform DER 2>/dev/null | base64 -w0)
      dnskey=$(txt_records "$DKIM_SELECTOR._domainkey.$d" | grep -i 'p=' | head -1 | tr -d ' ' | sed -n 's/.*p=\([^;]*\).*/\1/p')
      if [[ -z $dnskey ]]; then dkim="MISSING"
      elif [[ $dnskey == "$key" ]]; then dkim="ok"
      else dkim="MISMATCH"; fi
    fi
    dmarc=$(txt_records "_dmarc.$d" | grep -i '^v=DMARC1' | head -1 | grep -oiE 'p=[a-z]+' | head -1)
    ns=$(DIGQ NS "$d" | head -1); ns=${ns%.}
    # Plesk alias with mail service switched off: nobody can send or receive mail with this domain
    # here, so missing SPF/DKIM is irrelevant (SPF -all + DMARC p=reject is even the right setup)
    mailoff=0; note=""
    if [[ -n ${ALIAS_OF[$d]:-} && ${ALIAS_MAIL[$d]} == false ]]; then
      mailoff=1; note=" | alias of ${ALIAS_OF[$d]}, mail off – info only"
    fi
    probs=""
    (( spf_ok )) || [[ $spf == "+all" ]] || probs+=" SPF:${spf}"
    if [[ $spf == "+all" ]] && (( mxhere || mailoff )); then   # +all lets anyone forge mail, sending or not
      dalert "Mail auth: $d – SPF ends in +all: anyone may send mail as this domain (DNS at ${ns:-?})"
    fi
    if [[ $spf == permerror* ]] && (( mxhere && ! mailoff )); then
      dalert "Mail auth: $d – SPF record is invalid (${spf#permerror:}) – receivers treat it as a hard error (DNS at ${ns:-?})"
    fi
    [[ $dkim == MISSING || $dkim == MISMATCH ]] && probs+=" DKIM:${dkim,,}"
    # no DMARC record: Gmail and Yahoo require one from bulk senders, and without it nobody learns
    # about forged mails with this domain – a recommendation, mail is still delivered
    [[ -z $dmarc ]] && (( mxhere )) && probs+=" DMARC:missing"
    # DMARC passes if SPF *or* DKIM passes – only both failing breaks delivery
    local broken=0
    (( ! spf_ok )) && [[ $spf != "+all" && $dkim != ok ]] && broken=1
    line=$(printf '  %-28s SPF %-9s | DKIM %-8s | DMARC %-12s | MX %s | DNS %s%s' "$d" \
      "$spf" "$dkim" "${dmarc:-missing}" "$( ((mxhere)) && echo here || echo "${mxinfo:-none}")" "${ns:-?}" "$note")
    if (( mailoff )); then
      nomail=$((nomail + 1)); [[ -n $probs ]] || (( MAILAUTH_SHOW_ALL )) && echo "$line"
    elif [[ -n $probs ]]; then
      bad=$((bad + 1)); echo "$line"
      # alert only if mail for the domain is hosted here (users send through this server)
      # and neither SPF nor DKIM passes; a single failing one is listed as a recommendation
      if (( mxhere && broken )) && [[ $spf != permerror* ]]; then   # permerror already alerted above
        dalert "Mail auth: $d – neither SPF nor DKIM passes (${probs# }, DNS at ${ns:-?}) – mails from this domain are likely rejected or marked as spam"
      fi
    else
      ok=$((ok + 1)); (( MAILAUTH_SHOW_ALL )) && echo "$line"
    fi
  done
  echo "  $ok domain(s) OK, $bad with findings$( ((nomail)) && echo ", $nomail alias(es) without mail service (info only)"). Alert only if SPF and DKIM both fail and the MX points here;"
  echo "  a single missing/outdated record (SPF, DKIM or DMARC) is a recommendation (DMARC passes if SPF or DKIM passes)."
  echo "  DNS queried via ${MAILAUTH_RESOLVER:-system resolver}"
}
check_mailauth() {   # SPF / DKIM / DMARC of every domain with mail service
  echo ""; echo "Mail authentication (SPF / DKIM / DMARC):"
  if ! command -v dig >/dev/null; then
    echo "  skipped – dig not installed (Debian/Ubuntu: apt install bind9-dnsutils)"
  elif [[ -z ${PUBIP:-} ]]; then
    echo "  skipped – public IPv4 of this server unknown"
  else
    mailauth_scan
  fi
}

# =============================================================================
# Running the checks, report, upload
# =============================================================================

# check_enabled NAME – the on/off switches from the settings (with --only every named check runs)
# Mailbox fill level: usage from the Maildir++ file maildirsize (Courier and Dovecot keep it up
# to date), the size limit from Plesk – the mailbox's own, or with -1 the subscription's default
# (domains inside a subscription use the main domain's). Without Plesk the limit in maildirsize
# counts. Mailboxes without limit or without maildirsize are left out.
fmt_bytes() {   # fmt_bytes N – 1.07 GB / 512 MB, in units of 1024 like Plesk shows them
  awk -v b="$1" 'BEGIN { if (b >= 1073741824) printf "%.2f GB", b/1073741824; else printf "%.0f MB", b/1048576 }'
}
maildir_used() {   # maildir_used FILE – bytes used according to a maildirsize file
  awk 'NR > 1 { s += $1 } END { printf "%.0f\n", s + 0 }' "$1" 2>/dev/null
}
check_mailboxes() {
  local who lim sub f used pct n=0 nolim=0 nofile=0 d mb h
  echo ""; echo "Mailboxes (fill level of the size limit; warning from WARN_MAILBOX_PCT=$WARN_MAILBOX_PCT %):"
  if [[ -z $MAILNAMES_DIR || ! -d $MAILNAMES_DIR ]]; then echo "  mailbox directory MAILNAMES_DIR=\"$MAILNAMES_DIR\" not found – skipped"; return 0; fi
  {
    if command -v plesk >/dev/null; then
      T "$CMD_TIMEOUT" plesk db -Ne "SELECT CONCAT(m.mail_name, '@', d.name), m.mbox_quota, IFNULL(l.value, -1) FROM mail m JOIN domains d ON d.id = m.dom_id LEFT JOIN Subscriptions s ON s.object_id = IF(d.webspace_id > 0, d.webspace_id, d.id) AND s.object_type = 'domain' LEFT JOIN SubscriptionProperties sp ON sp.subscription_id = s.id AND sp.name = 'limitsId' LEFT JOIN Limits l ON l.id = sp.value AND l.limit_name = 'mbox_quota' WHERE m.postbox = 'true'" 2>/dev/null
    else
      # without Plesk: every <domain>/<mailbox> with a maildirsize file, limit from its first line
      for f in "$MAILNAMES_DIR"/*/*/Maildir/maildirsize; do
        [[ -f $f ]] || continue
        h=${f%/Maildir/maildirsize}; mb=${h##*/}; d=${h%/*}; d=${d##*/}
        printf '%s@%s\t%s\t-1\n' "$mb" "$d" "$(head -1 "$f" | grep -oE '^[0-9]+' || echo -1)"
      done
    fi
  } >"$TMP.mbx"
  while IFS=$'\t' read -r who lim sub; do
    [[ -n $who ]] || continue
    [[ $lim =~ ^[0-9]+$ ]] && (( lim > 0 )) || lim=$sub
    if ! [[ $lim =~ ^[0-9]+$ ]] || (( lim <= 0 )); then nolim=$((nolim + 1)); continue; fi
    f="$MAILNAMES_DIR/${who#*@}/${who%@*}/Maildir/maildirsize"
    if [[ ! -r $f ]]; then nofile=$((nofile + 1)); continue; fi
    used=$(maildir_used "$f"); n=$((n + 1))
    pct=$(( used * 100 / lim ))
    printf '%d\t%s\t%s\t%s\n' "$pct" "$who" "$(fmt_bytes "$used")" "$(fmt_bytes "$lim")" >>"$TMP.mbp"
    if (( pct >= WARN_MAILBOX_PCT )); then
      dalert "Mail: mailbox $who is $pct % full ($(fmt_bytes "$used") of $(fmt_bytes "$lim")) – when it is full, mail to it is rejected. Raise its size limit, or have the customer delete or archive mail"
    fi
  done <"$TMP.mbx"
  if [[ -s $TMP.mbp ]]; then
    sort -t$'\t' -k1,1nr "$TMP.mbp" | head -5 | awk -F'\t' '{ printf "  %3d %%  %s  (%s of %s)\n", $1, $2, $3, $4 }'
  fi
  echo "  $n mailbox(es) checked; $nolim without size limit, $nofile without maildirsize (not counted)"
  rm -f "$TMP.mbp"
  return 0
}
check_enabled() {
  (( ONLY_MODE )) && return 0
  case $1 in
    serverdns) (( SERVER_DNS_CHECK )) ;;
    domaindns) (( DOMAIN_DNS_CHECK )) ;;
    exposed)   (( EXPOSED_FILES_CHECK )) ;;
    webshell)  (( WEBSHELL_CHECK )) ;;
    mailauth)  (( MAILAUTH_CHECK )) ;;
    mailboxes) (( WARN_MAILBOX_PCT > 0 )) ;;
    https)     (( HTTPS_CHECK )) ;;
    persistence) (( PERSISTENCE_CHECK )) ;;
    *) return 0 ;;
  esac
}
# checks that need dig are skipped silently without it (mailauth prints a note)
check_needs_dig() { [[ $1 == serverdns || $1 == domaindns || $1 == https ]]; }

run_hourly() {   # run_hourly NAME… – checks write directly into the report body
  local c
  for c in "$@"; do check_enabled "$c" && { step "$c"; "check_$c"; }; done
  return 0
}
run_daily() {   # run_daily NAME… – section text to stdout, alerts to $DALERTS
  local c
  : >"$DALERTS"
  echo "As of: $(date '+%Y-%m-%d %H:%M %Z')"
  detect_pubip6
  for c in "$@"; do
    check_enabled "$c" || continue
    check_needs_dig "$c" && ! command -v dig >/dev/null && continue
    step "daily: $c"
    "check_$c"
  done
  return 0
}
# daily checks run once per day (first run after midnight); later runs reuse the cached text.
# After an update or a change of the configuration file they run again right away, so the
# daily checks show the new results (and the new version line) at once instead of from the
# next night on. "Update" means the script file changed – also between two releases.
self_sum() {   # self_sum – short checksum of this script and its configuration file
  cat "$(readlink -f "$0" 2>/dev/null || echo "$0")" "$CONF" 2>/dev/null |
    { sha256sum 2>/dev/null || cksum; } | awk '{print substr($1, 1, 12)}'
}
daily_checks() {
  local daily="$STATE_DIR/daily.txt" a stamp
  DALERTS="$STATE_DIR/daily_alerts.txt"
  stamp="$(date +%F) $VERSION $(self_sum)"
  if [[ $(cat "$STATE_DIR/daily_date" 2>/dev/null) != "$stamp" ]]; then
    # mark the day first: if a daily check makes the run abort, the next runs still report hourly
    echo "$stamp" >"$STATE_DIR/daily_date"
    # shellcheck disable=SC2086  # a list of check names, one argument each – split on purpose
    run_daily $DAILY_CHECKS >"$daily.new" 2>/dev/null; mv "$daily.new" "$daily"
  fi
  section "DAILY CHECKS"
  cat "$daily" >>"$BODY" 2>/dev/null
  [[ -f $DALERTS ]] && while IFS= read -r a; do [[ -n $a ]] && alert "$a"; done <"$DALERTS"
  return 0
}

write_report() {
  {
    echo "Server report $HOST – $NOW${ONLY:+ (only: $ONLY)} – plesk-server-report v$VERSION"
    if (( ${#ALERTS[@]} )); then
      echo "STATUS: WARNING (${#ALERTS[@]})"
      printf ' ! %s\n' "${ALERTS[@]}"
    else
      echo "STATUS: OK"
    fi
    [[ -s $TMPD/notes ]] && sed 's/^/ i /' "$TMPD/notes"
    cat "$BODY"
    echo ""
    if (( GEO_OK )); then echo "IP geolocation: DB-IP.com Lite databases (CC BY 4.0)"
    elif [[ -n $GEO_NOTE ]]; then echo "$GEO_NOTE"; fi
  } >"$REPORT"
  chmod 600 "$REPORT"
}

# ---------------------------------------------------------------- 24-hour summary
# Condenses the local reports of the last SUMMARY_HOURS into one file (summary.txt):
# every alert with count and first/last time, totals and peaks per section, and every
# line of the rarely filled sections (logins, new PHP files, login ≠ from, webmail, …).
# A reviewer (human or AI) reads this file plus latest.txt (daily checks, fail2ban)
# instead of every single report. Built from the report files, so nothing is lost
# that a report contains; the per-run reports stay as they are.
summary_records() {   # summary_records FILE… – one tab-separated record per finding
  awk '
    function t(s) { gsub(/\t/, " ", s); return s }
    FNR == 1 {
      tm = "?"; if (match($0, /[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]( [A-Z]+)?/)) tm = substr($0, RSTART, RLENGTH)
      sec = ""; sub_ = ""; cur = ""; nrun++; next
    }
    FNR == 2 { print "RUN\t" tm "\t" $0; next }
    /^ ! / { a = substr($0, 4); if (!(a in ac)) { ac[a] = 0; af[a] = tm; ao[++nao] = a }; ac[a]++; al[a] = tm; next }
    /^ i / { a = substr($0, 4); if (!(a in nc)) { nc[a] = 0; nf[a] = tm; no[++nno] = a }; nc[a]++; nl[a] = tm; next }
    /^== / { sec = $0; sub_ = ""; next }
    sec ~ /DAILY CHECKS/ { next }
    # ---------------- MAIL
    sec ~ /== MAIL ==/ {
      if ($0 ~ /^Delivered: /) { n = split($0, x, /[^0-9]+/); dl += x[2]; df += x[3]; bo += x[4]; if (x[5] + 0 > mq) { mq = x[5] + 0; mqt = tm }; next }
      if ($0 ~ /^Rejections mentioning/) { r = $0; sub(/.*: /, "", r); rj += r; next }
      if ($0 ~ /^  example: /) { if (nbx < 5) { l = $0; sub(/^  example: /, "", l); print "BLX\t" tm "\t" t(substr(l, 1, 260)); nbx++ }; next }
      if ($0 ~ /^Outgoing deliveries per (provider|receiving mail server)/) { sub_ = "prov"; next }
      if (sub_ == "prov" && $0 ~ /^  [^ ].* [0-9]+ \/ [0-9]+ \/ [0-9]+$/) {
        n = split($0, x, " "); pn = $0; sub(/^  /, "", pn); sub(/ +[0-9]+ \/ [0-9]+ \/ [0-9]+$/, "", pn)
        ps[pn] += x[n-4]; pd[pn] += x[n-2]; pb[pn] += x[n]; next }
      if ($0 ~ /^Watched recipient domain /) { sub_ = ""; w = $0; sub(/^Watched recipient domain /, "", w); sub(/:.*/, "", w)
        if (match($0, /[0-9]+ sent, [0-9]+ deferred, [0-9]+ bounced/)) { split(substr($0, RSTART, RLENGTH), x, /[^0-9]+/); ws[w] += x[1]; wd[w] += x[2]; wb[w] += x[3] }; next }
      if ($0 ~ /^  example \(watched\): /) { if (nwx < 5) { l = $0; sub(/^  example \(watched\): /, "", l); print "WATCHX\t" tm "\t" t(substr(l, 1, 260)); nwx++ }; next }
      if ($0 ~ /^Spam filter: /) { r = $0; sub(/^Spam filter: /, "", r); skt += r + 0
                                   if (match($0, /= [0-9]+ bytes/) || match($0, /limit of [0-9]+/)) { l = substr($0, RSTART, RLENGTH); gsub(/[^0-9]/, "", l); skl = l }; next }
      if ($0 ~ /^DNS blocklists for/ && $0 ~ /LISTED/) { print "BL\t" tm "\t" t($0); next }
      if ($0 ~ /^Top senders/) { sub_ = "top"; next }
      if ($0 ~ /^Authenticated mailboxes/) { sub_ = "auth"; next }
      if ($0 ~ /^Mailboxes sending with a foreign/) { sub_ = "mism"; next }
      if ($0 ~ /^IMAP\/POP3 logins \(/) { sub_ = "imapf"; next }
      if ($0 ~ /^Mails sent by scripts/) { sub_ = "script"; next }
      if ($0 ~ /^Failed mail logins:/) { s = $0; sub(/.*SMTP /, "", s); a1 = s + 0; sub(/.*POP3 /, "", s); a2 = s + 0
                                         fs_ += a1; fd += a2; if (a1 + a2 > fm) { fm = a1 + a2; fmt = tm }; sub_ = "fip"; next }
      if ($0 ~ /^Most attacked mailboxes \(failed SMTP/) { sub_ = "fusr"; next }
      if ($0 ~ /^Failed logins from IPs with earlier/) { sub_ = "oldpw"; next }
      if ($0 ~ /^Mail logins from datacenters/) { sub_ = "dc"; next }
      if ($0 ~ /^Webmail \(Roundcube\)/) { sub_ = "wsend"; next }
      if ($0 ~ /^Failed webmail logins:/) { n = split($0, x, /[^0-9]+/); wf += x[2]; sub_ = "wfip"; next }
      if ($0 ~ /^Most attacked mailboxes \(failed webmail/) { sub_ = "wfusr"; next }
      if (sub_ == "auth" && $0 ~ /^ +[0-9]+ +[0-9]+ IPs /) { cur = $4; au[cur] += $1; next }
      if (sub_ == "auth" && $0 ~ /^          [^ ]/) {   # "ip (CC, operator) ×n, ip (…) ×n, …" → sum per mailbox and IP
        l = $0
        while (match(l, /[0-9a-fA-F:.]+( \([^)]*\))? ×[0-9]+/)) {
          e = substr(l, RSTART, RLENGTH); l = substr(l, RSTART + RLENGTH)
          n = e; sub(/.*×/, "", n); e = substr(e, 1, length(e) - length(n) - 3)   # strip " ×n" (× is 2 bytes)
          k = cur SUBSEP e; if (!(k in aip)) { aip[k] = 0; aio[++naio] = k }; aip[k] += n
        }
        if (l ~ /…/) amore[cur] = 1
        next
      }
      if (sub_ == "imapf" && $0 ~ /^ +[0-9]+  .* from /) { l = $0; sub(/^ +/, "", l); print "IMAPF\t" tm "\t" t(l); next }
      if (sub_ == "mism" && $0 ~ /^ +[0-9]+ /) { l = $0; sub(/^ +/, "", l); print "MISM\t" tm "\t" t(l); next }
      if (sub_ == "script" && $0 ~ /^ +[0-9]+ +uid /) { l = $0; sub(/^ +[0-9]+ +/, "", l); sc[l] += $1; next }
      if (sub_ == "top" && $0 ~ /^ +[0-9]+  /) { l = $0; sub(/^ +[0-9]+  /, "", l); ts[l] += $1; next }
      if (sub_ == "fip" && $0 ~ /^ +[0-9]+  /) { l = $0; sub(/^ +[0-9]+  /, "", l); fi[l] += $1; next }
      if (sub_ == "fusr" && $0 ~ /^ +[0-9]+ /) { fu[tolower($2)] += $1; next }
      if (sub_ == "wsend" && $0 ~ / rcpt /) { l = $0; sub(/^ +/, "", l); print "WSEND\t" tm "\t" t(l); next }
      if (sub_ == "wsend" && $0 ~ /^          [^ ]/) { l = $0; sub(/^ +/, "", l); print "WSEND\t" tm "\t    " t(l); next }
      if (sub_ == "wfusr" && $0 ~ /^ +[0-9]+ /) { wu[tolower($2)] += $1; next }
      next
    }
    # ---------------- SYSTEM
    sec ~ /== SYSTEM ==/ {
      if ($0 ~ /^Load: /) { if ($4 + 0 > ml || mlt == "") { ml = $4 + 0; mlt = tm }; c = $0; sub(/.* on /, "", c); sub(/ cores.*/, "", c); cores = c; next }
      if ($0 ~ /^CPU per system user/) { sub_ = "cpu"; next }
      if ($0 ~ /^Top processes/) { sub_ = ""; next }
      if ($0 ~ /^RAM: / && match($0, /\([0-9]+ %\)/)) { p = substr($0, RSTART + 1, RLENGTH - 4) + 0; if (rmt == "" || p < rm) { rm = p; rmt = tm }; next }
      if ($0 ~ /^Filesystems/) { sub_ = "fs"; next }
      if (sub_ == "cpu" && $0 ~ /^ +[0-9.]+ %/) { if ($1 + 0 > cu[$3] + 0) { cu[$3] = $1 + 0; cut[$3] = tm }; next }
      if (sub_ == "fs" && $0 ~ /^ +[0-9]+% /) { p = $1; sub(/%/, "", p); if (!($2 in dk) || p + 0 > dk[$2] + 0) dk[$2] = p + 0; next }
      next
    }
    # ---------------- WEB
    sec ~ /== WEB / {
      if ($0 ~ /^requests \|/) { sub_ = "table"; next }
      if ($0 ~ /^WordPress login attacks/) { sub_ = "wp"; next }
      if ($0 ~ /^PHP fatal errors/) { sub_ = "fatal"; next }
      if ($0 ~ /^Attack patterns/) { sub_ = "att"; next }
      if ($0 ~ /^Traffic peaks/) { sub_ = "peak"; next }
      if ($0 ~ /^ModSecurity/) { sub_ = "modsec"; next }
      if (sub_ == "table" && $0 ~ /^ +[0-9]+ +[0-9]+ +[0-9]+  /) { wr[$4] += $1; w5[$4] += $2; wl[$4] += $3; next }
      if (sub_ == "wp" && $0 ~ /^  /) { l = $0; sub(/^  /, "", l); print "WP\t" tm "\t" t(l); next }
      if (sub_ == "fatal" && $0 ~ /^ +[0-9]+ /) { fa[$2] += $1; if (!($2 in fx)) { m = $0; sub(/^[^–]*– /, "", m); fx[$2] = m }; next }
      if (sub_ == "att" && $0 ~ / SQLi /) {
        cur = $1; l = $0; i = 0
        while (match(l, /[0-9]+\/[0-9]+/)) { i++; v = substr(l, RSTART, RLENGTH); split(v, y, "/"); at[cur, i] += y[1]; at2[cur, i] += y[2]; l = substr(l, RSTART + RLENGTH) }
        atd[cur] = 1; next
      }
      if (sub_ == "att" && $0 ~ /served with 200 AND present on disk:/) { f = $0; sub(/.*disk: /, "", f); k = cur SUBSEP f; if (!(k in sv)) { sv[k] = 1; print "SERVED\t" tm "\t" cur "\t" t(f) }; next }
      if (sub_ == "peak" && $0 ~ /^  [^ ]/) { l = $0; sub(/^  /, "", l); print "PEAK\t" tm "\t" t(l); next }
      if (sub_ == "modsec" && $0 ~ /^ +[0-9]+ +[0-9]+  /) { mh[$3] += $1; mb[$3] += $2; next }
      next
    }
    # ---------------- WEBROOTS, LOGINS, SERVICES
    sec ~ /WEBROOTS/ {
      if ($0 ~ /^(New since last run|First run)/) { n = $0; sub(/.*: /, "", n); up += n; next }
      if ($0 ~ /^  \//) { l = $0; sub(/^  /, "", l); print "UPLOAD\t" tm "\t" t(l) }
      next
    }
    sec ~ /SUCCESSFUL LOGINS/ {
      if ($0 ~ /^ +[0-9]+× /) {
        c = $1; sub(/×.*/, "", c); l = $0; sub(/^ +[0-9]+× +/, "", l)
        if (!(l in lc)) { lc[l] = 0; lf[l] = tm; lo[++nlo] = l }; lc[l] += c; ll[l] = tm
      }
      next
    }
    sec ~ /ACCESS & PERSISTENCE/ {   # changes (+ - ~) and findings (!), counted like the logins
      if ($0 ~ /^  [-+~!] /) { l = substr($0, 3); if (!(l in pc)) { pc[l] = 0; pf[l] = tm; po[++npo] = l }; pc[l]++; pl[l] = tm }
      next
    }
    sec ~ /SERVICES/ {
      if (($0 ~ /^Failed units: / && $0 !~ /: none$/) || ($0 ~ /^OOM killer: / && $0 !~ /: none$/)) print "SVC\t" tm "\t" t($0)
      next
    }
    sec ~ /== BACKUPS ==/ {   # backup status: the lines of the newest report
      if ($0 == "") next
      if (bkrun != nrun) { nbk = 0; bkrun = nrun }
      bk[++nbk] = $0; next
    }
    END {
      for (i = 1; i <= nao; i++) { a = ao[i]; print "ALERT\t" ac[a] "\t" af[a] "\t" al[a] "\t" t(a) }
      for (i = 1; i <= nno; i++) { a = no[i]; print "NOTE\t" nc[a] "\t" nf[a] "\t" nl[a] "\t" t(a) }
      for (i = 1; i <= nbk; i++) print "BKP\t" t(bk[i])
      printf "MAILTOT\t%d\t%d\t%d\t%d\t%s\t%d\n", dl, df, bo, mq, mqt, rj
      printf "SKIPTOT\t%d\t%s\n", skt, skl
      for (p in ps) printf "PROVTOT\t%d\t%d\t%d\t%d\t%s\n", ps[p] + pd[p] + pb[p], ps[p], pd[p], pb[p], p
      for (w in ws) printf "WATCHTOT\t%d\t%d\t%d\t%s\n", ws[w], wd[w], wb[w], w
      printf "FAILTOT\t%d\t%d\t%d\t%s\t%d\n", fs_, fd, fm, fmt, wf
      for (u in au) print "AUTH\t" au[u] "\t" u
      for (i = 1; i <= naio; i++) { split(aio[i], kk, SUBSEP); print "AUTHIP\t" kk[1] "\t" aip[aio[i]] "\t" t(kk[2]) }
      for (u in amore) print "AUTHMORE\t" u
      for (s in sc) print "SCRIPT\t" sc[s] "\t" s
      for (u in fu) print "FUSR\t" fu[u] "\t" u
      for (u in ts) print "TOPS\t" ts[u] "\t" u
      for (u in fi) print "FIP\t" fi[u] "\t" t(u)
      for (u in wu) print "WFUSR\t" wu[u] "\t" u
      printf "SYS\t%s\t%s\t%s\t%s\t%s\n", ml, mlt, cores, rm, rmt
      for (u in cu) print "CPU\t" cu[u] "\t" u "\t" cut[u]
      for (d in dk) print "DISK\t" dk[d] "\t" d
      for (d in wr) print "WEB\t" wr[d] "\t" w5[d] "\t" wl[d] "\t" d
      for (d in fa) print "FATAL\t" fa[d] "\t" d "\t" t(fx[d])
      for (d in atd) printf "ATT\t%d\t%s\t%d/%d\t%d/%d\t%d/%d\t%d/%d\t%d/%d\n", at[d,1]+at[d,2]+at[d,3]+at[d,4]+at[d,5], d, at[d,1], at2[d,1], at[d,2], at2[d,2], at[d,3], at2[d,3], at[d,4], at2[d,4], at[d,5], at2[d,5]
      for (d in mh) print "MODSEC\t" mh[d] "\t" mb[d] "\t" d
      print "UPTOT\t" up
      for (i = 1; i <= nlo; i++) { l = lo[i]; print "LOGIN\t" lc[l] "\t" lf[l] "\t" ll[l] "\t" t(l) }
      for (i = 1; i <= npo; i++) { l = po[i]; print "PERS\t" pc[l] "\t" pf[l] "\t" pl[l] "\t" t(l) }
      print "NRUN\t" nrun
    }' "$@"
}

write_summary() {   # write_summary OUTFILE – from the local reports of the last SUMMARY_HOURS
  local outf=$1 recs files newest n
  files=$(find "$OUT_DIR" -maxdepth 1 -name 'report-*.txt' -mmin -$(( SUMMARY_HOURS * 60 )) 2>/dev/null | sort)
  [[ -n $files ]] || return 0
  newest=$(tail -n 1 <<<"$files")
  # shellcheck disable=SC2086  # a list of report files (names without spaces, made by the script) – split on purpose
  recs=$(summary_records $files)
  rec() { grep "^$1"$'\t' <<<"$recs" | cut -f2-; }
  n=$(rec NRUN)
  SUM_NALERTS=$(rec ALERT | grep -c .)   # for the subject of the summary mail
  {
    echo "Server summary $HOST – last $SUMMARY_HOURS h: $n report(s), $(rec RUN | head -1 | cut -f1) to $(rec RUN | tail -1 | cut -f1) – plesk-server-report v$VERSION"
    echo "Built from the reports of this period. Daily checks and fail2ban: see latest.txt. Details of a run: report-<date>-<time>.txt"
    echo ""
    echo "== RUNS (time, status) =="
    rec RUN | awk -F'\t' '{printf "  %s  %s\n", $1, $2}'
    echo ""
    echo "== ALERTS (times seen, first – last, text) =="
    if [[ -n $(rec ALERT) ]]; then
      rec ALERT | awk -F'\t' '{printf "  %3d×  %s – %s  %s\n", $1, $2, $3, $4}'
    else echo "  none"; fi
    if [[ -n $(rec NOTE) ]]; then
      echo ""; echo "== SCRIPT NOTES (missing data sources, shortened logs; times seen, first – last) =="
      rec NOTE | awk -F'\t' '{printf "  %3d×  %s – %s  %s\n", $1, $2, $3, $4}'
    fi

    echo ""; echo "== MAIL =="
    rec MAILTOT | awk -F'\t' '{printf "Delivered: %d | deferred: %d | bounced: %d | highest queue: %d%s\nRejections mentioning blocklist/reputation/spam/rate limit: %d\n", $1, $2, $3, $4, ($5 != "" ? " (" $5 ")" : ""), $6}'
    rec BLX | awk -F'\t' '{printf "  example (%s): %s\n", $1, $2}'
    if [[ -n $(rec PROVTOT) ]]; then
      echo "Outgoing deliveries per receiving mail server (provider or MX host; total sent / deferred / bounced):"
      rec PROVTOT | sort -t$'\t' -k1,1nr | head -10 | awk -F'\t' '{printf "  %-22s %5d / %d / %d\n", $5, $2, $3, $4}'
    fi
    rec WATCHTOT | awk -F'\t' '{printf "Watched recipient domain %s: %d sent, %d deferred, %d bounced\n", $4, $1, $2, $3}'
    rec WATCHX | awk -F'\t' '{printf "  example (%s): %s\n", $1, $2}'
    rec SKIPTOT | awk -F'\t' '{ lim = ($2 != "" ? sprintf("limit %.1f MB = %s bytes", $2/1048576, $2) : "") }
      $1 > 0 {printf "Spam filter: %d mail(s) not scanned, larger than the size limit%s\n", $1, (lim != "" ? " (" lim ")" : "")}
      $1 == 0 {printf "Spam filter: all mails scanned%s\n", (lim != "" ? " (" lim ")" : "")}'
    if [[ -n $(rec BL) ]]; then echo "Server IP LISTED on a DNS blocklist:"; rec BL | awk -F'\t' '{printf "  %s  %s\n", $1, $2}'
    else echo "DNS blocklists for the server IP: not listed in any run"; fi
    echo ""; echo "Top senders (total recipients; incoming mail included):"
    rec TOPS | sort -t$'\t' -k1,1nr | head -10 | awk -F'\t' '{printf "  %6d  %s\n", $1, $2}'
    echo ""; echo "Authenticated mailboxes (mails in total; every client IP seen):"
    rec AUTH | sort -t$'\t' -k1,1nr | head -15 | while IFS=$'\t' read -r m u; do
      printf '  %6d  %s\n' "$m" "$u"
      rec AUTHIP | awk -F'\t' -v u="$u" '$1 == u {print $2 "\t" $3}' | sort -t$'\t' -k1,1nr |
        awk -F'\t' '{ s = s (s == "" ? "" : ", ") $2 " ×" $1; n++ } n == 6 { exit } END { if (s != "") print "          " s }'
      rec AUTHMORE | grep -qxF "$u" && echo "          (more IPs in single runs – see the reports)"
    done
    echo ""; echo "IMAP/POP3 logins from outside the allowed countries (time; logins, mailbox, IP):"
    rec IMAPF | awk -F'\t' '{printf "  %s  %s\n", $1, $2}'
    echo ""; echo "Mailboxes sending with a foreign sender domain (login ≠ from):"
    rec MISM | awk -F'\t' '{printf "  %s  %s\n", $1, $2}'
    echo ""; echo "Mails sent by scripts (total per system user):"
    rec SCRIPT | sort -t$'\t' -k1,1nr | head -10 | awk -F'\t' '{printf "  %6d  %s\n", $1, $2}'
    echo ""
    rec FAILTOT | awk -F'\t' '{printf "Failed mail logins: SMTP %d | IMAP/POP3 %d in total, most in one run: %d%s\n", $1, $2, $3, ($4 != "" ? " (" $4 ")" : "")}'
    echo "Top IPs (failed mail logins, total; only IPs that were among the top 5 of a run):"
    rec FIP | sort -t$'\t' -k1,1nr | head -10 | awk -F'\t' '{printf "  %6d  %s\n", $1, $2}'
    echo "Most attacked mailboxes (failed SMTP/IMAP/POP3 logins, total):"
    rec FUSR | sort -t$'\t' -k1,1nr | head -8 | awk -F'\t' '{printf "  %6d  %s\n", $1, $2}'
    echo ""; echo "Webmail (Roundcube) – mails sent (time; mails, recipients, IPs):"
    rec WSEND | awk -F'\t' '{printf "  %s  %s\n", $1, $2}'
    rec FAILTOT | awk -F'\t' '{printf "Failed webmail logins: %d in total\n", $5}'
    if [[ -n $(rec WFUSR) ]]; then
      echo "Most attacked mailboxes (failed webmail logins, total):"
      rec WFUSR | sort -t$'\t' -k1,1nr | head -5 | awk -F'\t' '{printf "  %6d  %s\n", $1, $2}'
    fi

    echo ""; echo "== SYSTEM =="
    rec SYS | awk -F'\t' '{printf "Highest 5-min load: %s (%s) on %s cores | lowest available RAM: %s %% (%s)\n", $1, $2, $3, $4, $5}'
    echo "Highest CPU per system user (snapshots):"
    rec CPU | sort -t$'\t' -k1,1nr | head -5 | awk -F'\t' '{printf "  %6s %%  %s (%s)\n", $1, $2, $3}'
    echo "Filesystems (highest usage):"
    rec DISK | sort -t$'\t' -k1,1nr | awk -F'\t' '{printf "  %4s%%  %s\n", $1, $2}'
    if [[ -n $(rec SVC) ]]; then echo "Failed services / OOM killer:"; rec SVC | awk -F'\t' '{printf "  %s  %s\n", $1, $2}'
    else echo "Failed services / OOM killer: none in any run"; fi
    if [[ -n $(rec BKP) ]]; then echo "Backups (newest report):"; rec BKP | sed 's/^/  /'; fi

    echo ""; echo "== WEB (totals) =="
    echo "requests | 5xx | login POSTs | domain"
    rec WEB | sort -t$'\t' -k1,1nr | head -10 | awk -F'\t' '{printf "  %7d %5d %6d  %s\n", $1, $2, $3, $4}'
    rec WEB | sort -t$'\t' -k1,1nr | tail -n +11 | awk -F'\t' '$2 > 0 || $3 > 0 {printf "  %7d %5d %6d  %s\n", $1, $2, $3, $4}'
    echo ""; echo "WordPress login attacks (time, details):"
    rec WP | awk -F'\t' '{printf "  %s  %s\n", $1, $2}'
    echo ""; echo "PHP fatal errors (total, domain, first message):"
    rec FATAL | sort -t$'\t' -k1,1nr | head -8 | awk -F'\t' '{printf "  %5d  %s – %s\n", $1, $2, $3}'
    echo ""; echo "Attack patterns & sensitive-file probes (totals, of which answered 200):"
    rec ATT | sort -t$'\t' -k1,1nr | head -12 | awk -F'\t' '{printf "  %-26s SQLi %s | traversal %s | code exec %s | XSS %s | sensitive files %s\n", $2, $3, $4, $5, $6, $7}'
    if [[ -n $(rec SERVED) ]]; then
      echo "  served with 200 AND present on disk (time, domain, file):"
      rec SERVED | awk -F'\t' '{printf "    %s  %s  %s\n", $1, $2, $3}'
    fi
    echo ""; echo "Traffic peaks & distributed requests (time, details):"
    rec PEAK | awk -F'\t' '{printf "  %s  %s\n", $1, $2}'
    echo ""; echo "ModSecurity (total hits, of which blocked):"
    rec MODSEC | sort -t$'\t' -k1,1nr | head -8 | awk -F'\t' '{printf "  %6d %6d  %s\n", $1, $2, $3}'

    echo ""; echo "== WEBROOTS: PHP files in upload folders =="
    echo "New in this period: $(rec UPTOT)"
    rec UPLOAD | awk -F'\t' '{printf "  %s  %s\n", $1, $2}'

    echo ""; echo "== SUCCESSFUL LOGINS (SSH, Plesk panel; count, first – last) =="
    rec LOGIN | awk -F'\t' '{printf "  %4d×  %s – %s  %s\n", $1, $2, $3, $4}'

    echo ""; echo "== ACCESS & PERSISTENCE (changes + − ~ and findings !; count, first – last) =="
    if [[ -n $(rec PERS) ]]; then rec PERS | awk -F'\t' '{printf "  %4d×  %s – %s  %s\n", $1, $2, $3, $4}'
    else echo "  no change, nothing suspicious"; fi

    echo ""; echo "Newest report: $(basename "$newest")"
  } >"$outf"
  chmod 600 "$outf"
}

# replace_remote LOCALFILE NAME – upload as a new file instead of overwriting: Google Drive (and
# some other backends) keep the old content of an overwritten file as a version for up to 30 days,
# which would keep report data longer than RETENTION_DAYS. Deleted permanently, not into the trash.
replace_remote() {
  rcl deletefile "$REMOTE/$2" --drive-use-trash=false --quiet 2>/dev/null
  rcl copyto "$1" "$REMOTE/$2" --quiet
}
# rclone with short network timeouts, as a whole limited to CMD_TIMEOUT. rclone's own retries
# stay at their defaults: Google Drive answers bursts with "rate limit exceeded", which rclone
# handles by waiting and retrying
rcl() { T "$CMD_TIMEOUT" rclone --contimeout 30s --timeout 60s "$@"; }

# Pseudonymised mailboxes (MASK_MAILBOXES=1): the uploaded copies show every mail address as
# mbx-<6 hex>@<domain>. The token is a hash of the address with a secret key that never leaves
# this server ($STATE_DIR/mask_key), so the same mailbox gets the same token in every report and
# on every day. $STATE_DIR/mailbox_pseudonyms keeps "pseudonym address last-seen" for --decode.
MAIL_RE='[A-Za-z0-9._%+=-]+@([A-Za-z0-9-]+[.])+[A-Za-z][A-Za-z]+'
mask_key() {
  local k="$STATE_DIR/mask_key"
  if [[ ! -s $k ]]; then
    ( umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$k" ) || return 1
  fi
  cat "$k"
}
# upload_copy FILE – the file to upload: FILE itself, or with MASK_MAILBOXES=1 a pseudonymised copy
upload_copy() {
  (( MASK_MAILBOXES )) || { printf '%s\n' "$1"; return 0; }
  local c map="$TMPD/pseudonyms" key a t now f="$STATE_DIR/mailbox_pseudonyms"
  c="$TMPD/upload-${1##*/}"
  key=$(mask_key) || { printf '%s\n' "$1"; return 0; }
  now=$(date +%s)
  # one token per distinct address (lower case: Office@ and office@ are the same mailbox)
  : >"$map"
  while read -r a; do
    t=$(printf '%s:%s' "$key" "$a" | sha256sum | cut -c1-6)
    printf '%s mbx-%s@%s\n' "$a" "$t" "${a#*@}" >>"$map"
  done < <(grep -oE "$MAIL_RE" "$1" | tr '[:upper:]' '[:lower:]' | sort -u)
  awk -v re="$MAIL_RE" -v note="Mailbox addresses are pseudonymised (MASK_MAILBOXES=1) – decode on the server: plesk-server-report.sh --decode" '
    NR == FNR { m[$1] = $2; next }
    { out = ""; rest = $0
      while (match(rest, re)) { a = substr(rest, RSTART, RLENGTH)
        out = out substr(rest, 1, RSTART - 1) ((tolower(a) in m) ? m[tolower(a)] : a); rest = substr(rest, RSTART + RLENGTH) }
      print out rest
      if (!done && (FNR == 1 && $0 !~ /^Server report/ || $0 ~ /^STATUS:/)) { print note; done = 1 } }' "$map" "$1" >"$c" ||
    { printf '%s\n' "$1"; return 0; }
  # remember the pseudonyms for --decode, as long as the uploaded reports may exist (at least 30 days)
  if can_write_state; then
    { [[ -f $f ]] && cat "$f"; awk -v now="$now" '{ print $2, $1, now }' "$map"; } |
      awk -v now="$now" -v keep=$(( (RETENTION_DAYS > 30 ? RETENTION_DAYS : 30) * 86400 )) '
        { if ($3 > t[$1]) { t[$1] = $3; a[$1] = $2 } }
        END { for (p in t) if (now - t[p] <= keep) print p, a[p], t[p] }' | sort >"$f.new" && mv "$f.new" "$f"
  fi
  printf '%s\n' "$c"
}
# --decode [PSEUDONYM ...]: the real address of each pseudonym, or – without arguments – stdin
# with every pseudonym replaced (paste an AI review to get it back with real addresses)
decode_pseudonyms() {
  local f="$STATE_DIR/mailbox_pseudonyms"
  [[ -r $f ]] || { echo "no pseudonyms stored ($f) – MASK_MAILBOXES was never active, or the file was deleted" >&2; return 1; }
  if (( $# )); then
    local p
    for p in "$@"; do awk -v p="${p,,}" '$1 == p || $1 ~ "^" p "@" { print $1, "=", $2; f = 1 } END { if (!f) print p, "= (unknown)" }' "$f"; done
  else
    awk 'NR == FNR { m[$1] = $2; next }
      { out = ""; rest = $0
        while (match(rest, /mbx-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]@([A-Za-z0-9-]+\.)+[A-Za-z][A-Za-z]+/)) {
          p = substr(rest, RSTART, RLENGTH)
          out = out substr(rest, 1, RSTART - 1) ((p in m) ? m[p] : p); rest = substr(rest, RSTART + RLENGTH) }
        print out rest }' "$f" -
  fi
}
upload_report() {
  if (( ! UPLOAD )); then
    cat "$REPORT"
  elif [[ -n $REMOTE ]] && command -v rclone >/dev/null; then
    local up sm
    local ok=1 err="$TMPD/rclone.err" uf="$STATE_DIR/upload_failed"
    up=$(upload_copy "$REPORT")
    { rcl copyto "$up" "$REMOTE/$(basename "$REPORT")" --quiet &&
      replace_remote "$up" latest.txt; } 2>"$err" ||
      { ok=0; logger -t plesk-server-report "upload to $REMOTE failed"; }
    if (( SUMMARY )) && [[ -s $OUT_DIR/summary.txt ]]; then
      sm=$(upload_copy "$OUT_DIR/summary.txt")
      replace_remote "$sm" summary.txt 2>>"$err" ||
        { ok=0; logger -t plesk-server-report "upload of summary.txt to $REMOTE failed"; }
    fi
    # a failed upload is only in the system log, and the report that could say so was not
    # uploaded: remember it (time of the first failure, rclone's message), the next run raises
    # an alert – in the local report, by mail (REPORT_MAIL_TO) and in the upload once it works again
    if can_write_state; then
      if (( ok )); then rm -f "$uf"
      else
        [[ -s $uf ]] || date '+%Y-%m-%d %H:%M %Z' >"$uf"
        { head -1 "$uf"; grep -v '^$' "$err" 2>/dev/null | tail -1 | cut -c1-200; } >"$uf.new" && mv "$uf.new" "$uf"
      fi
    fi
    if (( RETENTION_DAYS > 0 )); then
      # delete old reports permanently (Google Drive: not into the trash)
      rcl delete "$REMOTE" --include 'report-*.txt' --min-age "${RETENTION_DAYS}d" \
        --drive-use-trash=false --quiet 2>>"$err" ||
        logger -t plesk-server-report "deleting old reports in $REMOTE failed"
    fi
  fi
}

# ---------------------------------------------------------------- reports by mail
# send_mail SUBJECT FILE – hands the mail to the local mail server (sendmail of Postfix or qmail).
# For a mailbox on this server it is delivered locally and never leaves the server. The text
# follows MASK_MAILBOXES like an upload. The script leaves these mails out of its mail figures.
send_mail() {
  local body rcpt to
  if ! command -v sendmail >/dev/null; then
    logger -t plesk-server-report "REPORT_MAIL_TO is set, but there is no sendmail command – no mail sent"
    return 1                            # the report says so in its notes (init)
  fi
  body=$(upload_copy "$2")
  read -ra rcpt <<<"${REPORT_MAIL_TO//,/ }"
  to=$(printf '%s, ' "${rcpt[@]}"); to=${to%, }
  {
    printf 'From: plesk-server-report <%s>\n' "$REPORT_MAIL_FROM"
    printf 'To: %s\n' "$to"
    # the subject may contain non-ASCII characters (–, ≠): MIME encoded word
    printf 'Subject: =?UTF-8?B?%s?=\n' "$(printf '%s' "$1" | base64 -w0)"
    printf 'Date: %s\n' "$(LC_ALL=C date -R)"
    printf 'MIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n'
    printf 'Auto-Submitted: auto-generated\n\n'
    cat "$body"
  } | T "$CMD_TIMEOUT" sendmail -oi -f "$REPORT_MAIL_FROM" "${rcpt[@]}" ||
    { logger -t plesk-server-report "mailing the report to $REPORT_MAIL_TO failed"
      can_write_state && date '+%Y-%m-%d %H:%M %Z' >"$STATE_DIR/mail_failed"; return 1; }
}
# --test-mail: mail the newest local report to REPORT_MAIL_TO right away and follow it in the mail
# log for up to 20 seconds, so a new setup can be checked without waiting for an alert or the next
# day's summary. Changes no state; a later normal run also reports a failed delivery.
test_mail() {
  local f log="" size=0 q="" lines="" i r st pl a p
  [[ -n $REPORT_MAIL_TO ]] || { echo "REPORT_MAIL_TO is empty – set it in $CONF first" >&2; return 1; }
  # shellcheck disable=SC2012  # the newest report; the script names these files itself
  f=$(ls -1t "$STATE_DIR"/out/report-*.txt 2>/dev/null | head -1)
  [[ -n $f ]] || { echo "no report in $STATE_DIR/out yet – let the script run once first" >&2; return 1; }
  for log in /var/log/maillog /var/log/mail.log ""; do [[ -z $log || -r $log ]] && break; done
  [[ -n $log ]] && size=$(stat -c %s "$log")
  echo "Sending $(basename "$f") to $REPORT_MAIL_TO (from $REPORT_MAIL_FROM) …"
  if ! send_mail "$HOST: test mail of plesk-server-report ($(basename "$f"))" "$f"; then
    if command -v sendmail >/dev/null; then echo "FAILED: sendmail did not accept the mail – see journalctl -t plesk-server-report"
    else echo "FAILED: there is no sendmail command – is a mail server (Postfix or qmail) installed?"; fi
    return 1
  fi
  echo "Accepted by the local mail server. Delivery (from the mail log):"
  if [[ -z $log ]] && ! command -v journalctl >/dev/null; then
    echo "  no mail log found – check the mailbox"; return 0
  fi
  for (( i = 0; i < 20; i++ )); do
    sleep 1
    if [[ -n $log ]]; then lines=$(tail -c +$(( size + 1 )) "$log" 2>/dev/null)
    else lines=$(journalctl --since "-$(( i + 30 )) s" -o short -u 'postfix*' 2>/dev/null); fi
    [[ -n $q ]] || q=$(grep 'postfix/pickup' <<<"$lines" | grep -F "from=<$REPORT_MAIL_FROM>" | tail -1 | sed -n 's/.*\]: \([0-9A-Za-z]*\): .*/\1/p')
    [[ -n $q ]] || continue
    # one status line per recipient; stop when every recipient has one
    st=$(grep -F " $q: to=<" <<<"$lines" | grep ' status=')
    (( $(grep -c . <<<"$st") >= $(wc -w <<<"${REPORT_MAIL_TO//,/ }") )) && break
  done
  if [[ -z $q ]]; then
    echo "  not found in the mail log within 20 s (qmail, or a log elsewhere) – check the mailbox"; return 0
  fi
  [[ -n $st ]] || { echo "  queued as $q, no delivery yet after 20 s – check the mailbox; the next normal run reports a failure"; return 0; }
  # Plesk hands the mail to its own delivery (relay=plesk_virtual, logged as "sent"); a missing
  # mailbox or a full one is only logged by postfix-local – and the mail is discarded, no bounce
  pl=$(grep -F " $q: " <<<"$lines" | grep 'postfix-local' | grep -E ': (Unknown user|.*[Qq]uota)')
  r=0
  while IFS= read -r i; do
    a=$(sed -n 's/.* to=<\([^>]*\)>.*/\1/p' <<<"$i")
    p=$(grep -F "$a" <<<"$pl" | head -1 | sed 's/.*postfix-local\[[0-9]*\]: [0-9A-Za-z]*: //')
    if [[ -n $p ]]; then printf '  %s: NOT delivered – Plesk: %s (the mail was discarded, no bounce)\n' "$a" "$p"; r=1
    elif [[ $i == *" status=deferred"* ]]; then
      printf '  %s: deferred – %s\n' "$a" "$(sed -n 's/.* status=deferred \(.*\)/\1/p' <<<"$i")"
      echo "    not failed yet: Postfix tries again (the next normal run still lists the deferral as an alert)"; (( r )) || r=2
    else printf '  %s: %s\n' "$a" "$(sed -n 's/.* status=\(.*\)/\1/p' <<<"$i")"; [[ $i == *" status=sent"* ]] || r=1; fi
  done <<<"$st"
  case $r in
    1) echo "Not delivered to every recipient – check REPORT_MAIL_TO (does the mailbox exist?)" ;;
    2) echo "Not delivered yet (deferred) – check the mailbox later" ;;
    *) echo "Delivered. If the mail is not in the inbox, look in the spam folder (see README: whitelist the sender)."
       [[ $st == *"relay=plesk_virtual"* ]] ||
         echo "(Delivered to another mail server: if it rejects the mail later, its bounce comes back to $REPORT_MAIL_FROM – the next normal run reports that.)" ;;
  esac
  return $(( r == 1 ))
}
# alert_key – an alert without its changing figures ("sent 163 mails" = "sent 170 mails"), so
# that the same problem in the next run is not mailed again; IPs and names stay
alert_key() {
  awk '{ n = split($0, w, " "); s = ""
         for (i = 1; i <= n; i++) { t = w[i]; gsub(/^[(\[]+|[),;:\]]+$/, "", t)
           s = s " " (t ~ /^[0-9]+([.,][0-9]+)?(%|×)?$/ ? "#" : w[i]) }
         print s }' <<<"$1" | md5sum | cut -c1-16
}
# mail_reports – what REPORT_MAIL asks for: the report when it has an alert that was not mailed in
# the last 24 hours (alerts), every report (all), summary.txt once a day from REPORT_MAIL_HOUR on
mail_reports() {
  [[ -n $REPORT_MAIL_TO ]] && (( UPLOAD )) || return 0
  local m=" ${REPORT_MAIL//[,|]/ } " f="$STATE_DIR/mailed_alerts" now a k first="" n=0 today hour subj
  now=$(date +%s)
  if [[ $m == *" all "* ]]; then
    if (( ${#ALERTS[@]} )); then subj="$HOST: WARNING (${#ALERTS[@]}) – ${ALERTS[0]}"
    else subj="$HOST: report OK"; fi
    send_mail "${subj:0:200}" "$REPORT"
  elif [[ $m == *" alerts "* ]] && (( ${#ALERTS[@]} )) && ! can_write_state; then
    # the previous run is stuck and holds the state: mail the alert every time
    subj="$HOST: WARNING (${#ALERTS[@]}) – ${ALERTS[0]}"
    send_mail "${subj:0:200}" "$REPORT"
  elif [[ $m == *" alerts "* ]] && (( ${#ALERTS[@]} )); then
    # mailed_alerts: "key epoch" of every alert mailed in the last 24 hours
    touch "$f"
    for a in "${ALERTS[@]}"; do
      k=$(alert_key "$a")
      if ! awk -v k="$k" -v now="$now" '$1 == k && now - $2 < 86400 { f = 1 } END { exit !f }' "$f"; then
        (( n++ )); [[ -z $first ]] && first=$a
        echo "$k $now" >>"$f"
      fi
    done
    awk -v now="$now" 'now - $2 < 86400' "$f" >"$f.new" && mv "$f.new" "$f"
    if (( n )); then
      subj="$HOST: WARNING (${#ALERTS[@]}, new: $n) – $first"
      send_mail "${subj:0:200}" "$REPORT"
    fi
  fi
  if [[ $m == *" summary "* ]] && (( SUMMARY )) && can_write_state && [[ -s $OUT_DIR/summary.txt ]]; then
    today=$(date +%F); hour=$(date +%-H)
    if (( hour >= REPORT_MAIL_HOUR )) && [[ $(cat "$STATE_DIR/mail_summary_date" 2>/dev/null) != "$today" ]]; then
      echo "$today" >"$STATE_DIR/mail_summary_date"
      if (( ${SUM_NALERTS:-0} )); then subj="$HOST: daily summary – ${SUM_NALERTS} alert(s) in the last $SUMMARY_HOURS h"
      else subj="$HOST: daily summary – no alerts in the last $SUMMARY_HOURS h"; fi
      send_mail "$subj" "$OUT_DIR/summary.txt"
    fi
  fi
  return 0
}

# Description of the state directory. Written to $STATE_DIR/README.txt in every normal run
# (only when it changed) and published in the repository as STATE-FILES.md
# (generated with --state-readme), so it always matches the installed version.
state_readme() {
  cat <<'EOF'
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
EOF
}
write_state_readme() {   # keep $STATE_DIR/README.txt in step with this version
  local f="$STATE_DIR/README.txt"
  can_write_state || return 0
  state_readme | cmp -s - "$f" 2>/dev/null || state_readme >"$f"
}

# --show-state: the remembered data in readable form (dates instead of Unix time)
show_state() {
  local f d ip who cc t ino off path
  d() { date -d "@$1" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "$1"; }
  echo "State directory: $STATE_DIR (description: README.txt there, or --state-readme)"
  echo ""
  f=$STATE_DIR/last_run; [[ -f $f ]] && echo "Last normal run: $(d "$(cat "$f")")"
  f=$STATE_DIR/daily_date; [[ -f $f ]] && echo "Daily checks last run on: $(cat "$f") (day, script version, checksum of script and configuration)"
  for f in last_scan webshell_scan; do
    [[ -f $STATE_DIR/$f ]] && echo "$f: $(date -r "$STATE_DIR/$f" '+%Y-%m-%d %H:%M')"
  done
  f=$STATE_DIR/running; [[ -f $f ]] && echo "Run in progress or not finished: $(tr '\t' ' ' <"$f")"
  echo ""
  echo "Known SSH/Plesk login IPs – IP, last seen ($STATE_DIR/known_login_ips):"
  f=$STATE_DIR/known_login_ips
  if [[ -s $f ]]; then
    while read -r ip t; do printf '  %-40s %s\n' "$ip" "${t:+$(d "$t")}"; done <"$f"
  else echo "  (none)"; fi
  echo ""
  echo "Known client IPs of successful mail logins – IP, mailbox, last seen ($STATE_DIR/known_mail_ips):"
  f=$STATE_DIR/known_mail_ips
  if [[ -s $f ]]; then
    while read -r ip who t; do printf '  %-40s %-40s %s\n' "$ip" "$who" "$(d "$t")"; done <"$f"
  else echo "  (none)"; fi
  echo ""
  echo "Known foreign countries per mailbox – mailbox, country, last seen ($STATE_DIR/known_imap_countries):"
  f=$STATE_DIR/known_imap_countries
  if [[ -s $f ]]; then
    while read -r who cc t; do printf '  %-40s %-3s %s\n' "$who" "$cc" "$(d "$t")"; done <"$f"
  else echo "  (none)"; fi
  echo ""
  if [[ -d $STATE_DIR/baseline ]]; then
    echo "Baseline of the access & persistence check ($STATE_DIR/baseline):"
    for f in keys access cron ports; do
      [[ -f $STATE_DIR/baseline/$f ]] && printf '  %-7s %4d entries, as of %s\n' "$f" "$(wc -l <"$STATE_DIR/baseline/$f")" "$(date -r "$STATE_DIR/baseline/$f" '+%Y-%m-%d %H:%M')"
    done
    [[ -s $STATE_DIR/baseline/keys ]] && { echo "  SSH keys:"; awk -F'\t' '{ printf "    %-16s %s%s\n", $1, $2, ($3 == "" ? "" : "  " $3) }' "$STATE_DIR/baseline/keys"; }
    [[ -s $STATE_DIR/baseline/addrs ]] && echo "  IP addresses: $(awk -F'\t' '{ printf "%s%s (%s)", (NR > 1 ? ", " : ""), $1, $2 }' "$STATE_DIR/baseline/addrs")"
    [[ -s $STATE_DIR/baseline/ports ]] && echo "  Listening TCP ports: $(sort -n "$STATE_DIR/baseline/ports" | awk -F'\t' '{ printf "%s%s %s", (NR > 1 ? ", " : ""), $1, $2 }')"
    echo ""
  fi
  f=$STATE_DIR/mailbox_pseudonyms
  [[ -s $f ]] && { echo "Mailbox pseudonyms for MASK_MAILBOXES: $(wc -l <"$f") ($f, decode with --decode)"; echo ""; }
  echo "Log positions – bytes read, inode, log ($STATE_DIR/offsets):"
  for f in "$STATE_DIR"/offsets/*; do
    [[ -f $f ]] || continue
    read -r ino off path <"$f"
    printf '  %12s  %-10s %s\n' "$off" "$ino" "${path:-(path not stored yet – written by the next run)}"
  done
}

usage() {
  sed -n '/^# Options:/,/^# Settings:/p' "$0" | sed '$d; s/^# \{0,1\}//'
}
list_checks() {
  echo "hourly: $HOURLY_CHECKS"
  echo "daily:  $DAILY_CHECKS"
  echo "groups: hourly, daily, all"
}
parse_args() {
  UPLOAD=1; ONLY=""; ONLY_MODE=0; SUMMARY_ONLY=0
  while (( $# )); do
    case $1 in
      --no-upload) UPLOAD=0 ;;
      --only) [[ -n ${2:-} ]] || { echo "--only needs a check name (see --list)" >&2; exit 2; }
              ONLY=$2; shift ;;
      --only=*) ONLY=${1#--only=} ;;
      --list) list_checks; exit 0 ;;
      --summary) SUMMARY_ONLY=1 ;;
      --version) echo "plesk-server-report $VERSION"; exit 0 ;;
      --state-readme) state_readme; exit 0 ;;
      --test-mail) TEST_MAIL=1 ;;
      --show-state) SHOW_STATE=1 ;;
      --decode) shift; DECODE=1; DECODE_ARGS=("$@"); break ;;
      --pseudonymise|--pseudonymize)
              [[ -r ${2:-} ]] || { echo "--pseudonymise needs a readable file, e.g. $STATE_DIR/out/summary.txt" >&2; exit 2; }
              PSEUDO_FILE=$2; shift ;;
      -h|--help) usage; exit 0 ;;
      *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
  done
  if [[ -n $ONLY ]]; then
    local c
    ONLY_MODE=1; UPLOAD=0
    ONLY=${ONLY//,/ }
    ONLY=${ONLY//hourly/$HOURLY_CHECKS}; ONLY=${ONLY//daily/$DAILY_CHECKS}; ONLY=${ONLY//all/$HOURLY_CHECKS $DAILY_CHECKS}
    for c in $ONLY; do
      [[ " $HOURLY_CHECKS $DAILY_CHECKS " == *" $c "* ]] || { echo "unknown check: $c (see --list)" >&2; exit 2; }
    done
    ONLY=$(xargs <<<"$ONLY")
  fi
}
# only_list GROUP – the checks of a group that were selected with --only, in report order
# timeout_alerts – every command that hit its time limit in this run becomes an alert
timeout_alerts() {
  local a
  [[ -s $TMPD/timeouts ]] || return 0
  while IFS= read -r a; do alert "Script: $a – that part of the report is incomplete"; done < <(sort -u "$TMPD/timeouts")
}
only_list() {
  local c r=""
  for c in $1; do [[ " $ONLY " == *" $c "* ]] && r+=" $c"; done
  echo "$r"
}

# on_exit – runs at every end of the script: a run that did not finish (error, timeout, kill)
# leaves $RUNFILE with its last step and exit code, so the next run can report it
# load_conf – the configuration is bash code run as root: whoever can write it gets root. If it
# belongs to another user or group/others may write it, the script refuses to run at all –
# a warning in the report would come too late, after the code already ran. The message goes
# to stderr (cron mails it to root) and to the system log.
load_conf() {
  [[ -e $CONF ]] || return 0
  if [[ -n $(find -L "$CONF" -maxdepth 0 \( ! -user root -o -perm /022 \) 2>/dev/null) ]]; then
    local m
    m="refusing to run – $CONF is $(stat -L -c '%U:%G %A' "$CONF" 2>/dev/null). It is loaded as root code; whoever can write it gets root. Fix: chown root:root $CONF; chmod 600 $CONF"
    echo "plesk-server-report: $m" >&2
    logger -t plesk-server-report "$m" 2>/dev/null
    DONE=1; exit 1
  fi
  # shellcheck source=/dev/null  # the configuration file is not in the repository, so ShellCheck cannot follow it
  [[ -r $CONF ]] && . "$CONF"
  return 0
}

on_exit() {
  local rc=$?
  if [[ -n ${RUNFILE:-} ]] && can_write_state; then
    if (( DONE )); then rm -f "$RUNFILE"
    else
      printf '%s\t%s\t%s\t%s\t%s\n' "$$" "${RUN_START:-}" "${NOW:-}" "${STEP:-}" "$rc" >"$RUNFILE"
      logger -t plesk-server-report "run aborted (exit code $rc) during: ${STEP:-?}" 2>/dev/null
    fi
  fi
  [[ -n ${TMPD:-} ]] && rm -rf "$TMPD"
}

init() {
  local opid="" ostart="" onow="" ostep="" orc="" why
  load_conf
  if [[ -z $STATE_DIR || $STATE_DIR == / ]]; then
    echo "plesk-server-report: STATE_DIR must not be empty or / – check $CONF" >&2
    logger -t plesk-server-report "STATE_DIR must not be empty or /" 2>/dev/null
    exit 1
  fi
  [[ -n $REPORT_MAIL_FROM ]] || REPORT_MAIL_FROM="plesk-server-report@$HOST"
  # Unattended runs (cron) are stopped after MAX_RUNTIME, together with everything they started.
  # Interactive runs are not wrapped, so that Ctrl-C keeps working.
  if [[ -z ${PSR_LIMITED:-} && ! -t 0 && -f $0 ]] && (( MAX_RUNTIME > 0 )); then
    export PSR_LIMITED=1
    exec timeout -k 60 "$(( MAX_RUNTIME * 60 ))" "$BASH" "$0" "${ARGS[@]}"
  fi
  renice -n 10 -p $$ >/dev/null 2>&1; ionice -c 2 -n 7 -p $$ >/dev/null 2>&1   # low priority
  OUT_DIR=$STATE_DIR/out
  mkdir -p "$STATE_DIR/offsets" "$OUT_DIR"
  chmod 700 "$STATE_DIR"
  NOW=$(date '+%Y-%m-%d %H:%M %Z')
  RUN_START=$(date +%s)
  ALERTS=()
  trap on_exit EXIT
  trap 'exit 143' TERM HUP
  trap 'exit 130' INT
  exec 9>"$STATE_DIR/lock"
  if flock -n 9; then
    rm -rf "$STATE_DIR"/tmp.*            # left behind by a killed run (safe: we hold the lock)
    if can_write_state; then
      RUNFILE=$STATE_DIR/running
      if [[ -f $RUNFILE ]]; then         # the previous run did not finish
        IFS=$'\t' read -r opid ostart onow ostep orc <"$RUNFILE"
        case $orc in
          "") why="killed" ;;
          124|137|143) why="stopped – time limit MAX_RUNTIME reached, or killed" ;;
          130) why="interrupted with Ctrl-C" ;;
          *) why="exit code $orc" ;;
        esac
        alert "Script: the run of ${onow:-?} did not finish ($why) during: ${ostep:-?} – that report is missing; see the system log (journalctl -t plesk-server-report)"
      fi
      step "start"
    fi
  else
    if (( ONLY_MODE || SUMMARY_ONLY )); then
      echo "another run of plesk-server-report is in progress – try again in a few minutes" >&2
      DONE=1; exit 1
    fi
    IFS=$'\t' read -r opid ostart onow ostep orc <"$STATE_DIR/running" 2>/dev/null
    logger -t plesk-server-report "previous run (PID ${opid:-?}) is still running – this run is skipped" 2>/dev/null
    # alert only if that run is really stuck: alive and older than MAX_RUNTIME (or 1 h) + 5 min
    if [[ -z $opid || -z $ostart ]] || ! kill -0 "$opid" 2>/dev/null ||
       (( RUN_START - ostart < ( MAX_RUNTIME > 0 ? MAX_RUNTIME : 60 ) * 60 + 300 )); then
      DONE=1; exit 0
    fi
    LOCKED_OUT=1
    LOCK_ALERT="Script: the previous run (started $onow, PID $opid) is still running after $(( (RUN_START - ostart) / 60 )) min, at: $ostep – this report has no new data; check the process (ps -fp $opid) and what it is waiting for"
  fi
  if (( LOCKED_OUT )); then GEO_OK=0; GEO_NOTE=""; else geo_init; fi
  SINCE=$(cat "$STATE_DIR/last_run" 2>/dev/null || date -d '-1 hour' +%s)
  # temporary files on disk under STATE_DIR (on Debian 13 /tmp is in RAM)
  TMPD=$(mktemp -d "$STATE_DIR/tmp.XXXXXX")
  BODY=$TMPD/body; TMP=$TMPD/tmp; : >"$BODY"
  if (( ONLY_MODE )); then REPORT=$TMPD/report.txt
  else REPORT="$OUT_DIR/report-$(date '+%Y%m%d-%H%M').txt"; fi
  PUBIP6=""
  detect_pubip
  local v
  for v in VHOST_LOGS PLESK_PANEL_LOG MAILNAMES_DIR DKIM_KEY_DIR; do
    [[ -n ${!v} ]] || note "config: $v is empty in $CONF – the checks that need it are skipped"
  done
  [[ -n $REMOTE ]] && (( UPLOAD )) && ! command -v rclone >/dev/null &&
    note "upload: REMOTE is set, but rclone is not installed – reports stay in $OUT_DIR (REMOTE=\"\" in $CONF switches the upload off)"
  [[ -n $REPORT_MAIL_TO ]] && ! command -v sendmail >/dev/null &&
    note "REPORT_MAIL_TO is set, but there is no sendmail command – reports are not mailed"
  if [[ -s $STATE_DIR/upload_failed ]] && ! (( ONLY_MODE || SUMMARY_ONLY )); then
    alert "Script: the upload to $REMOTE fails since $(head -1 "$STATE_DIR/upload_failed") – the reports are missing there (local copies: $OUT_DIR). rclone says: $(sed -n 2p "$STATE_DIR/upload_failed" | grep . || echo "nothing – see journalctl -t plesk-server-report"). Test: rclone lsf $REMOTE"
  fi
  if [[ -f $STATE_DIR/mail_failed ]] && can_write_state; then
    note "mail: sendmail refused the report mail of $(cat "$STATE_DIR/mail_failed") – see journalctl -t plesk-server-report"
    rm -f "$STATE_DIR/mail_failed"
  fi
  command -v plesk >/dev/null || note "plesk command not found – domain list from VHOST_LOGS only, domain aliases unknown"
}

main() {
  ARGS=("$@")
  parse_args "$@"
  if (( SHOW_STATE || DECODE )); then  # read-only: no lock, no state written
    load_conf
    if (( SHOW_STATE )); then show_state; else decode_pseudonyms "${DECODE_ARGS[@]}"; fi
    return
  fi
  if (( TEST_MAIL )); then              # changes no state (ONLY_MODE)
    load_conf
    [[ -n $REPORT_MAIL_FROM ]] || REPORT_MAIL_FROM="plesk-server-report@$HOST"
    ONLY_MODE=1; TMPD=$(mktemp -d) || return 1
    test_mail; local rc=$?
    rm -rf "$TMPD"; return $rc
  fi
  if [[ -n $PSEUDO_FILE ]]; then        # preview: creates mask_key and stores the pseudonyms, so --decode works
    load_conf
    TMPD=$(mktemp -d) || return 1
    MASK_MAILBOXES=1 upload_copy "$PSEUDO_FILE" | xargs cat
    rm -rf "$TMPD"; return 0
  fi
  init
  if (( LOCKED_OUT )); then          # previous run stuck: report that instead of staying silent
    alert "$LOCK_ALERT"
    write_report
    (( SUMMARY )) && write_summary "$OUT_DIR/summary.txt"
    upload_report
    mail_reports
    return 0
  fi
  if (( SUMMARY_ONLY )); then
    write_summary "$TMPD/summary.txt"
    if [[ -s $TMPD/summary.txt ]]; then cat "$TMPD/summary.txt"; else echo "no reports of the last $SUMMARY_HOURS h in $OUT_DIR"; fi
    return 0
  fi
  if (( ONLY_MODE )); then
    local hourly daily
    hourly=$(only_list "$HOURLY_CHECKS"); daily=$(only_list "$DAILY_CHECKS")
    # shellcheck disable=SC2086  # a list of check names, one argument each – split on purpose
    [[ -n $hourly ]] && run_hourly $hourly
    if [[ -n $daily ]]; then
      DALERTS=$TMPD/daily_alerts
      section "DAILY CHECKS"
      # shellcheck disable=SC2086  # a list of check names, one argument each – split on purpose
      run_daily $daily >>"$BODY" 2>/dev/null
      while IFS= read -r a; do [[ -n $a ]] && alert "$a"; done <"$DALERTS"
    fi
    timeout_alerts
    write_report
    cat "$REPORT"
    return 0
  fi
  write_state_readme
  # shellcheck disable=SC2086  # a list of check names, one argument each – split on purpose
  run_hourly $HOURLY_CHECKS
  daily_checks
  timeout_alerts
  step "report"
  write_report
  (( SUMMARY )) && write_summary "$OUT_DIR/summary.txt"
  step "upload"
  upload_report
  step "mail"
  mail_reports
  # -mmin instead of -mtime: "-mtime +7" only matches files at least 8 full days old
  (( LOCAL_KEEP_DAYS > 0 )) && find "$OUT_DIR" -name 'report-*.txt' -mmin +$(( LOCAL_KEEP_DAYS * 1440 )) -delete
  echo "$RUN_START" >"$STATE_DIR/last_run"
}

LOCKED_OUT=0; DONE=0; STEP=""; RUNFILE=""; SUMMARY_ONLY=0; ONLY_MODE=0; SHOW_STATE=0; TEST_MAIL=0; DECODE=0; DECODE_ARGS=(); PSEUDO_FILE=""
main "$@"
DONE=1
