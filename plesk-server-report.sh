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
# files (.env, .git, dumps, backups) and recently changed PHP files for webshell code.
# Successful logins are annotated with country and network operator (local
# GeoIP database, optional alerts for logins from unexpected countries).
#
# Only log lines written since the previous run are analysed. The resulting
# plain-text report is stored locally and (optionally) uploaded with rclone to
# any storage backend rclone supports (Google Drive, OneDrive, S3, SFTP, ...).
#
# Run as root from cron, e.g. hourly:
#   5 * * * * root /usr/local/sbin/plesk-server-report.sh
#
# Options:
#   --no-upload       print the report to stdout and skip the rclone upload
#   --only CHECK,...  run only these checks right now and print the result; nothing
#                     is uploaded and no state is changed (log offsets, known IPs, …)
#   --list            list the check names for --only
#   --summary         print the summary of the last SUMMARY_HOURS from the stored reports (runs no checks)
#   --show-state      show what the script remembers (known IPs, countries, log positions)
#                     in readable form; changes nothing
#   --state-readme    print the description of the state files (also kept as README.txt
#                     in the state directory)
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

VERSION=1.6.0

set -uo pipefail
export LC_ALL=C
# cron runs with PATH=/usr/bin:/bin – plesk, postqueue, ip etc. live in /usr/sbin
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ---------------------------------------------------------------- defaults
HOST=$(hostname -f 2>/dev/null || hostname)
STATE_DIR=/var/lib/plesk-server-report   # a new or changed state file must be described in state_readme()
REMOTE="reports:server-reports/${HOST}"  # rclone remote:path – empty = local only
RETENTION_DAYS=7                         # delete remote reports older than x days (0 = never)
LOCAL_KEEP_DAYS=7                        # keep local reports x days (0 = never delete; summary.txt needs at least SUMMARY_HOURS)
SUMMARY=1                                # write summary.txt (all reports of the last SUMMARY_HOURS condensed) and upload it
SUMMARY_HOURS=24
# Limits, so that a hanging command or a huge log can't block the script or fill disk/RAM
MAX_RUNTIME=50                # minutes: an unattended (cron) run is stopped after this – keep it below the cron interval (0 = no limit)
CMD_TIMEOUT=120               # seconds per external command (plesk db, fail2ban-client, postqueue, journalctl, apt-get/dnf, rclone)
FIND_TIMEOUT=600              # seconds per file-system scan of the web folders (find, grep)
IMAP_COUNTRY_KEEP_DAYS=30     # forget a mailbox's foreign country after x days without a login from there (0 = never)
KNOWN_MAIL_IP_DAYS=30         # remember IPs with successful mail logins this long – alert when fail2ban bans one of them
MAX_LOG_MB=200                # read at most x MB of new lines per log file and run, the newest part (0 = no limit)
VHOST_LOGS=/var/www/vhosts/system        # Plesk per-domain log directories
PLESK_PANEL_LOG=/var/log/plesk/httpsd_access_log   # access log of the Plesk panel (port 8443) – panel logins
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
HOURLY_CHECKS="mail webmail system fail2ban web uploads logins services backups"
DAILY_CHECKS="updates certificates https serverdns mailtls domaindns exposed webshell mailauth"

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
      if curl -fsS --max-time 180 -o "$f.gz.tmp" "https://download.db-ip.com/free/dbip-$kind-lite-$m.mmdb.gz" 2>/dev/null &&
         gunzip -c "$f.gz.tmp" >"$f.tmp" 2>/dev/null &&
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
      a)   [[ $q == + ]] && host_has_ip "${arg:-$d}" "$ip" $bits && { SPF_RES=pass; return; } ;;
      mx)  if [[ $q == + ]]; then
             for mxh in $(DIGQ MX "${arg:-$d}" | awk '{print $2}'); do
               host_has_ip "${mxh%.}" "$ip" $bits && { SPF_RES=pass; return; }
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

  MAILSTATS=$(awk -v watch="$WATCH_RECIPIENT_DOMAINS" '
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
    /SASL (LOGIN|PLAIN|CRAM-MD5) authentication failed/ {
      sf++; sip[ipof($0)]++
      if (match($0, /sasl_username=[^ ,]+/)) fu[substr($0, RSTART+14, RLENGTH-14)]++
    }
    # plausibility check: lines of the IMAP/POP3 server vs. login lines recognized (ok or failed)
    /(dovecot|imap-login|pop3-login|imap[ds]|pop3[ds])/ { imapl++ }
    /(imap|pop3)-login: Login: / || /(imap|pop3)[ds](-ssl)?(\[[0-9]+\])?: LOGIN, user=/ { imapok++ }
    # successful IMAP/POP3 logins per mailbox and client IP (country check)
    /(imap|pop3)-login: Login: user=<[^>]+>.*rip=/ {
      u=$0; sub(/.*user=</, "", u); sub(/>.*/, "", u); r=$0; sub(/.*rip=/, "", r); sub(/[, ].*/, "", r); iok[u SUBSEP r]++
    }
    /(imap|pop3)[ds](-ssl)?(\[[0-9]+\])?: LOGIN, user=[^,]+, ip=\[/ {
      u=$0; sub(/.*LOGIN, user=/, "", u); sub(/,.*/, "", u); r=$0; sub(/.*ip=\[/, "", r); sub(/\].*/, "", r); sub(/^::ffff:/, "", r)
      iok[u SUBSEP r]++
    }
    # IMAP/POP3 – Dovecot: "imap-login: Disconnected (auth failed, …): user=<x>, …, rip=1.2.3.4"
    /(imap|pop3)-login: .*(auth failed|Authentication failed)/ {
      df++; r=$0; if (match(r, /rip=[0-9a-fA-F:.]+/)) dip[substr(r, RSTART+4, RLENGTH-4)]++
      if (match($0, /user=<[^>]+>/)) fu[substr($0, RSTART+6, RLENGTH-7)]++
    }
    # IMAP/POP3 – Courier (Plesk alternative): one line per failed attempt,
    # "imapd: LOGIN FAILED, user=x, ip=[::ffff:1.2.3.4], port=[…]" (user= is not always logged)
    /(imap|pop3)[ds](-ssl)?(\[[0-9]+\])?: LOGIN FAILED/ {
      df++
      if (match($0, /ip=\[[^]]+\]/)) { r=substr($0, RSTART+4, RLENGTH-5); sub(/^::ffff:/, "", r); dip[r]++ }
      if (match($0, /user=[^,]+/)) fu[substr($0, RSTART+5, RLENGTH-5)]++
    }
    END {
      printf "TOT\t%d\t%d\t%d\t%d\t%d\t%d\n", sent, def, bou, bl, sf, df
      printf "IMAPCHK\t%d\t%d\n", imapl, imapok + df
      printf "SKIP\t%d\t%s\n", sk, skl
      for (p in pt) printf "PROV\t%d\t%d\t%d\t%d\t%s\n", pt[p], pv[p, 1], pv[p, 2], pv[p, 3], p
      nw = split(watch, ww, " "); for (i = 1; i <= nw; i++) { w = tolower(ww[i]); printf "WATCH\t%d\t%d\t%d\t%s\t%s\n", wv[w, 1], wv[w, 2], wv[w, 3], w, wx[w] }
      for (k in iok) { split(k, kk, SUBSEP); printf "IMOK\t%d\t%s\t%s\n", iok[k], kk[1], kk[2] }
      for (u in sasl) printf "SASL\t%d\t%d\t%s\t%s\n", sasl[u], nip[u], u, ipl[u]
      for (k in sic) { split(k, kk, SUBSEP); printf "SAIP\t%d\t%s\t%s\n", sic[k], kk[1], kk[2] }
      for (m in pick) printf "PICK\t%d\t%s\n", pick[m], m
      for (f in rc)   printf "RCPT\t%d\t%s\n", rc[f], f
      for (f in orc)  printf "ORCP\t%d\t%s\n", orc[f], f
      for (i in sip)  printf "SFIP\t%d\t%s\n", sip[i], i
      for (i in dip)  printf "DFIP\t%d\t%s\n", dip[i], i
      for (u in fu)   printf "FUSR\t%d\t%s\n", fu[u], u
      for (u in mm)   printf "MISM\t%d\t%s\t%s\n", mm[u], u, mml[u]
      for (i=1; i<=blx; i++) printf "BLEX\t%s\n", bex[i]
    }' "$TMP")

  read -r _ SENT DEF BOU BL SF DF <<<"$(grep '^TOT' <<<"$MAILSTATS")"
  QUEUE=$(T "$CMD_TIMEOUT" postqueue -j 2>/dev/null | wc -l)
  out "Delivered: $SENT | deferred: $DEF | bounced: $BOU | queue: $QUEUE"
  out "Rejections mentioning blocklist/reputation/spam/rate limit: $BL"
  (( DEF > WARN_DEFERRED )) && alert "Mail: $DEF deferred deliveries"
  (( BL >= WARN_BLOCKLIST )) && alert "Mail: $BL rejections by remote servers mentioning a blocklist, reputation, spam or rate limit – check the server IP and the examples"
  (( QUEUE > WARN_QUEUE )) && alert "Mail: $QUEUE messages in the queue"
  grep '^BLEX' <<<"$MAILSTATS" | cut -f2- | sed 's/^/  example: /' >>"$BODY"
  # outgoing deliveries per provider: shows trouble with a big provider whatever its reply says
  if grep -q '^PROV' <<<"$MAILSTATS"; then
    out "Outgoing deliveries per provider (sent / deferred / bounced):"
    grep '^PROV' <<<"$MAILSTATS" | sort -t$'\t' -k2,2nr | head -10 |
      awk -F'\t' '{printf "  %-22s %5d / %d / %d\n", $6, $3, $4, $5}' >>"$BODY"
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
  local -A IMF=() IMU=() IMI=() KC=()
  local imn=0 KNOWNC="$STATE_DIR/known_imap_countries" firstc=0 isnew km kc kt now
  now=$(date +%s)
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
      printf '  %6d  %s  from %s (%s)%s\n' "$c" "$who" "$ip" "$GEO_LABEL" "${isnew:+  – first login from $GEO_CC}" >>"$BODY"
      [[ -n $isnew && ${IMF[$who]:-} != *"$ip "* ]] && IMF[$who]+="$ip ($GEO_LABEL) "
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
  grep '^FUSR' <<<"$MAILSTATS" | sort -t$'\t' -k2,2nr | head -5 |
    awk -F'\t' '{printf "  %6d  %s\n", $2, $3}' >>"$BODY"

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
        u=$0; sub(/.*Login failed for /, "", u); sub(/ against .*/, "", u)
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
  local CORES L1 L5 L15 LIMIT pct user MEM MT MA MP SWAP mnt p
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

  out ""; out "Filesystems:"
  while read -r pct mnt; do
    p=${pct%\%}; printf '  %4s  %s\n' "$pct" "$mnt" >>"$BODY"
    (( p > WARN_DISK_PCT )) && alert "Disk: $mnt is $pct full"
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
      for ip in $(sed -n 's/.*Banned IP list:[[:space:]]*//p' <<<"$s"); do
        k=""
        [[ -n ${MW[$ip]:-} ]] && k="mail logins of ${MW[$ip]%, } (last $(date -d "@${ML[$ip]}" '+%Y-%m-%d'))"
        [[ -r $KL ]] && grep -qxF "$ip" "$KL" && k="${k:+$k; }SSH/Plesk logins"
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
  : >"$TMP"; : >"$TMP.php"; : >"$TMP.att"; : >"$TMP.modsec"
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
    new_lines "$dir/error_log" | awk -v d="$dom" -v msf="$TMP.modsec" '
      /PHP Fatal error/ { n++; if (ex == "") { ex=$0; sub(/.*PHP Fatal error: */, "", ex); ex=substr(ex, 1, 160) } }
      /ModSecurity: / {
        if (/Access denied/) mb++; else mw++
        id="?"; if (match($0, /\[id "[0-9]+"\]/)) id=substr($0, RSTART+5, RLENGTH-7)
        msg="";  if (match($0, /\[msg "[^"]*"\]/)) msg=substr($0, RSTART+6, RLENGTH-8)
        r[id]++; rm[id]=substr(msg, 1, 70)
      }
      END { if (n) printf "%d\t%s\t%s\n", n, d, ex
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
            ignored_domain "$dom" || alert "Web: $dom served the sensitive file $f (HTTP 200, file exists) – remove it or block access; assume it was downloaded"
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
  rm -f "$TMP.att" "$TMP.modsec"
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
      T "$FIND_TIMEOUT" find "$up" -type f \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.phar' \) -newer "$SCAN_STAMP" 2>/dev/null
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
  head -15 "$TMP" | sed 's/^/  /' >>"$BODY"
  # after a timeout the scan was incomplete: keep the old stamp, so the next run looks again
  if [[ $(timeouts_seen) == "$nto" ]]; then can_write_state && mv "$SCAN_STAMP.new" "$SCAN_STAMP"; fi
  return 0
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
    if ! grep -qxF "$ip" "$KNOWN" 2>/dev/null; then
      can_write_state && echo "$ip" >>"$KNOWN"
      fnote=""; geo_foreign && fnote=" – OUTSIDE $ALLOWED_COUNTRIES"
      (( FIRST_LOGIN_RUN )) || echo "$( [[ $kind == Plesk ]] && echo "Plesk panel login" || echo "$kind login as $user") from previously unknown IP $ip${GEO_LABEL:+ ($GEO_LABEL)}$fnote" >>"$NEWLOGINS"
    fi
  done
  if [[ -s $NEWLOGINS ]]; then
    while IFS= read -r a; do alert "Login: $a"; done <"$NEWLOGINS"
  fi
  [[ -s $TMPD/panel_fail ]] && (( $(cat "$TMPD/panel_fail") > 0 )) &&
    out "  Plesk panel: $(cat "$TMPD/panel_fail") failed login attempt(s) (fail2ban jail plesk-panel)"
  (( FIRST_LOGIN_RUN )) && out "  (first run: all IPs stored as known; from now on new IPs raise an alert. List: $KNOWN)"
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

check_updates() {   # pending (security) updates, reboot required
  local upg sec
  if command -v apt-get >/dev/null; then
    upg=$(T "$CMD_TIMEOUT" apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep '^Inst' || true)
    sec=$(grep -ci 'security' <<<"$upg" || true)
    echo "Updates available: $(grep -c . <<<"$upg" || true), security updates: $sec"
    grep -i security <<<"$upg" | awk '{print "  " $2}' | head -10
    (( sec > 0 )) && dalert "Updates: $sec security update(s) pending"
    if [[ -f /var/run/reboot-required ]]; then
      echo "Reboot required (since $(date -r /var/run/reboot-required '+%Y-%m-%d'))"
      dalert "System: reboot required after updates"
    fi
  elif command -v dnf >/dev/null; then
    sec=$(T "$CMD_TIMEOUT" dnf -q updateinfo list --security 2>/dev/null | grep -c . || true)
    echo "Security updates available: $sec"
    (( sec > 0 )) && dalert "Updates: $sec security update(s) pending"
    if command -v needs-restarting >/dev/null && ! needs-restarting -r >/dev/null 2>&1; then
      echo "Reboot required"; dalert "System: reboot required after updates"
    fi
  fi
  return 0
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
  helo=$(postconf -h smtp_helo_name 2>/dev/null); [[ -z $helo || $helo == '$myhostname' ]] && helo=$(postconf -h myhostname 2>/dev/null)
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
      dalert "Mail: server IPv6 $PUBIP6 has no reverse DNS – Gmail rejects IPv6 mail without PTR; set it or disable IPv6 in Postfix (inet_protocols = ipv4)"
    elif host_has_ip "$ptr" "$PUBIP6"; then echo "  $PUBIP6 → $ptr: ok (forward-confirmed)"
    else echo "  $PUBIP6 → $ptr: does NOT resolve back (no matching AAAA)"
      dalert "Mail: IPv6 reverse DNS $PUBIP6 → $ptr has no matching AAAA record"
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
    # shellcheck disable=SC2086
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
  local dom root f rel code out="" n=0 found=0 nblk ex nerr exerr
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
        out+="  $dom$rel – PUBLICLY REACHABLE (HTTP 200)"$'\n'
        dalert "Web: $dom exposes $rel publicly (HTTP 200) – remove it from the document root or block access"
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
}
check_webshell() {   # recently changed PHP files with typical backdoor code
  local stamp="$STATE_DIR/webshell_scan" new="$STATE_DIR/webshell_scan.new" dom root out="" n=0 hits=0 f nto
  local re='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|gzdecode)[[:space:]]*\(|assert[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)|\$_(POST|GET|REQUEST|COOKIE)[[:space:]]*\[[^]]*\][[:space:]]*\(|preg_replace[[:space:]]*\([[:space:]]*["'"'"'][^"'"'"']*/e["'"'"']|create_function[[:space:]]*\([^)]*\$_(POST|GET|REQUEST)|(system|shell_exec|passthru|exec|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)'
  can_write_state && touch "$new"
  nto=$(timeouts_seen)
  echo ""; echo "Suspicious code in recently changed PHP files (typical webshell/backdoor patterns):"
  while IFS=$'\t' read -r dom root; do
    [[ -d $root ]] || continue
    n=$((n + 1))
    while IFS= read -r f; do
      [[ -n $WEBSHELL_IGNORE && $f =~ $WEBSHELL_IGNORE ]] && continue
      hits=$((hits + 1))
      out+="  $f ($(date -r "$f" '+%Y-%m-%d %H:%M'))"$'\n'
      dalert "Web: suspicious code in recently changed file $f – check it (webshell/backdoor?)"
    done < <(if [[ -f $stamp ]]; then T "$FIND_TIMEOUT" find "$root" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[0-9]' \) -newer "$stamp" 2>/dev/null
             else T "$FIND_TIMEOUT" find "$root" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[0-9]' \) -mtime -"$WEBSHELL_FIRST_DAYS" 2>/dev/null; fi |
             T "$FIND_TIMEOUT" xargs -r -d '\n' grep -lE "$re" 2>/dev/null | head -30)
  done < <(docroots)
  # after a timeout the scan was incomplete: keep the old stamp, so the next scan looks again
  if [[ $(timeouts_seen) == "$nto" ]]; then can_write_state && mv "$new" "$stamp"; fi
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
  echo "  a single missing/outdated record is a recommendation (DMARC passes if SPF or DKIM passes)."
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
check_enabled() {
  (( ONLY_MODE )) && return 0
  case $1 in
    serverdns) (( SERVER_DNS_CHECK )) ;;
    domaindns) (( DOMAIN_DNS_CHECK )) ;;
    exposed)   (( EXPOSED_FILES_CHECK )) ;;
    webshell)  (( WEBSHELL_CHECK )) ;;
    mailauth)  (( MAILAUTH_CHECK )) ;;
    https)     (( HTTPS_CHECK )) ;;
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
# daily checks run once per day (first run after midnight); later runs reuse the cached text
daily_checks() {
  local daily="$STATE_DIR/daily.txt" a
  DALERTS="$STATE_DIR/daily_alerts.txt"
  if [[ $(cat "$STATE_DIR/daily_date" 2>/dev/null) != "$(date +%F)" ]]; then
    # mark the day first: if a daily check makes the run abort, the next runs still report hourly
    date +%F >"$STATE_DIR/daily_date"
    # shellcheck disable=SC2086
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
      if ($0 ~ /^Outgoing deliveries per provider/) { sub_ = "prov"; next }
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
      if (sub_ == "fusr" && $0 ~ /^ +[0-9]+ /) { fu[$2] += $1; next }
      if (sub_ == "wsend" && $0 ~ / rcpt /) { l = $0; sub(/^ +/, "", l); print "WSEND\t" tm "\t" t(l); next }
      if (sub_ == "wsend" && $0 ~ /^          [^ ]/) { l = $0; sub(/^ +/, "", l); print "WSEND\t" tm "\t    " t(l); next }
      if (sub_ == "wfusr" && $0 ~ /^ +[0-9]+ /) { wu[$2] += $1; next }
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
      print "NRUN\t" nrun
    }' "$@"
}

write_summary() {   # write_summary OUTFILE – from the local reports of the last SUMMARY_HOURS
  local outf=$1 recs files newest n
  files=$(find "$OUT_DIR" -maxdepth 1 -name 'report-*.txt' -mmin -$(( SUMMARY_HOURS * 60 )) 2>/dev/null | sort)
  [[ -n $files ]] || return 0
  newest=$(tail -n 1 <<<"$files")
  # shellcheck disable=SC2086
  recs=$(summary_records $files)
  rec() { grep "^$1"$'\t' <<<"$recs" | cut -f2-; }
  n=$(rec NRUN)
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
      echo "Outgoing deliveries per provider (total sent / deferred / bounced):"
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

upload_report() {
  if (( ! UPLOAD )); then
    cat "$REPORT"
  elif [[ -n $REMOTE ]] && command -v rclone >/dev/null; then
    rcl copyto "$REPORT" "$REMOTE/$(basename "$REPORT")" --quiet &&
    replace_remote "$REPORT" latest.txt ||
      logger -t plesk-server-report "upload to $REMOTE failed"
    if (( SUMMARY )) && [[ -s $OUT_DIR/summary.txt ]]; then
      replace_remote "$OUT_DIR/summary.txt" summary.txt ||
        logger -t plesk-server-report "upload of summary.txt to $REMOTE failed"
    fi
    if (( RETENTION_DAYS > 0 )); then
      # delete old reports permanently (Google Drive: not into the trash)
      rcl delete "$REMOTE" --include 'report-*.txt' --min-age "${RETENTION_DAYS}d" \
        --drive-use-trash=false --quiet ||
        logger -t plesk-server-report "deleting old reports in $REMOTE failed"
    fi
  fi
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
| `known_login_ips` | `IP` | SSH and Plesk panel logins: an IP not in this list raises "login … from previously unknown IP". The first run fills it without alerts. |
| `known_mail_ips` | `IP mailbox last-seen` | client IPs of successful IMAP/POP3 and SMTP logins, kept for `KNOWN_MAIL_IP_DAYS`. When fail2ban bans one of them, the report raises "fail2ban: jail … bans … which had successful logins before". |
| `known_imap_countries` | `mailbox country last-seen` | countries outside `ALLOWED_COUNTRIES` a mailbox has fetched mail from. The alert "logged in via IMAP/POP3 from a new country" comes once per mailbox and country; an entry not seen for `IMAP_COUNTRY_KEEP_DAYS` is dropped, so the next trip alerts again. |

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
  f=$STATE_DIR/daily_date; [[ -f $f ]] && echo "Daily checks last run on: $(cat "$f")"
  for f in last_scan webshell_scan; do
    [[ -f $STATE_DIR/$f ]] && echo "$f: $(date -r "$STATE_DIR/$f" '+%Y-%m-%d %H:%M')"
  done
  f=$STATE_DIR/running; [[ -f $f ]] && echo "Run in progress or not finished: $(tr '\t' ' ' <"$f")"
  echo ""
  echo "Known SSH/Plesk login IPs ($STATE_DIR/known_login_ips):"
  f=$STATE_DIR/known_login_ips
  if [[ -s $f ]]; then sed 's/^/  /' "$f"; else echo "  (none)"; fi
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
      --show-state) SHOW_STATE=1 ;;
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
  # shellcheck source=/dev/null
  [[ -r $CONF ]] && . "$CONF"
  if [[ -z $STATE_DIR || $STATE_DIR == / ]]; then
    echo "plesk-server-report: STATE_DIR must not be empty or / – check $CONF" >&2
    logger -t plesk-server-report "STATE_DIR must not be empty or /" 2>/dev/null
    exit 1
  fi
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
  command -v plesk >/dev/null || note "plesk command not found – domain list from VHOST_LOGS only, domain aliases unknown"
}

main() {
  ARGS=("$@")
  parse_args "$@"
  if (( SHOW_STATE )); then           # read-only: no lock, no state written
    [[ -r $CONF ]] && . "$CONF"
    show_state; return 0
  fi
  init
  if (( LOCKED_OUT )); then          # previous run stuck: report that instead of staying silent
    alert "$LOCK_ALERT"
    write_report
    (( SUMMARY )) && write_summary "$OUT_DIR/summary.txt"
    upload_report
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
    # shellcheck disable=SC2086
    [[ -n $hourly ]] && run_hourly $hourly
    if [[ -n $daily ]]; then
      DALERTS=$TMPD/daily_alerts
      section "DAILY CHECKS"
      # shellcheck disable=SC2086
      run_daily $daily >>"$BODY" 2>/dev/null
      while IFS= read -r a; do [[ -n $a ]] && alert "$a"; done <"$DALERTS"
    fi
    timeout_alerts
    write_report
    cat "$REPORT"
    return 0
  fi
  write_state_readme
  # shellcheck disable=SC2086
  run_hourly $HOURLY_CHECKS
  daily_checks
  timeout_alerts
  step "report"
  write_report
  (( SUMMARY )) && write_summary "$OUT_DIR/summary.txt"
  step "upload"
  upload_report
  # -mmin instead of -mtime: "-mtime +7" only matches files at least 8 full days old
  (( LOCAL_KEEP_DAYS > 0 )) && find "$OUT_DIR" -name 'report-*.txt' -mmin +$(( LOCAL_KEEP_DAYS * 1440 )) -delete
  echo "$RUN_START" >"$STATE_DIR/last_run"
}

LOCKED_OUT=0; DONE=0; STEP=""; RUNFILE=""; SUMMARY_ONLY=0; ONLY_MODE=0; SHOW_STATE=0
main "$@"
DONE=1
