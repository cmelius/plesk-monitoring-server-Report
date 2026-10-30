#!/bin/bash
# =============================================================================
# plesk-server-report.sh
#
# Hourly health & security report for Plesk servers (Linux, Postfix/Dovecot).
#
# Focus: outgoing spam from compromised mailboxes or hacked websites, CPU/RAM,
# plus brute-force noise, fail2ban, web errors, successful logins, new PHP files
# in upload folders, failed services, OOM kills, DNS blocklists – and once a day:
# pending updates, expiring certificates and Plesk backup status.
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
#   --no-upload   print the report to stdout and skip the rclone upload
#
# Settings: edit the defaults below or – recommended, survives updates –
# override them in /etc/plesk-server-report.conf (plain bash variable syntax).
#
# License: MIT. No warranty – read the code before running it as root.
# =============================================================================

set -uo pipefail
export LC_ALL=C
# cron runs with PATH=/usr/bin:/bin – plesk, postqueue, ip etc. live in /usr/sbin
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ---------------------------------------------------------------- defaults
HOST=$(hostname -f 2>/dev/null || hostname)
STATE_DIR=/var/lib/plesk-server-report
REMOTE="reports:server-reports/${HOST}"  # rclone remote:path – empty = local only
RETENTION_DAYS=7                         # delete remote reports older than x days (0 = never)
LOCAL_KEEP_DAYS=7                        # keep local reports x days
VHOST_LOGS=/var/www/vhosts/system        # Plesk per-domain log directories
PLESK_PANEL_LOG=/var/log/plesk/panel.log
ROUNDCUBE_LOG_DIR=""          # default: /var/log/plesk-roundcube (or /usr/share/psa-roundcube/logs)

# Alert thresholds – per run (with an hourly cron job: per hour)
WARN_MAILS_PER_SENDER=150     # recipients per envelope sender
WARN_MAILS_PER_SASL=150       # mails submitted per authenticated mailbox
WARN_MAILS_PER_SCRIPT=100     # mails per system user (PHP mail() / sendmail)
WARN_IPS_PER_MAILBOX=4        # distinct client IPs per authenticated mailbox
WARN_FROM_MISMATCH=10         # mails of a mailbox with a foreign sender domain
WARN_DEFERRED=100             # deferred deliveries
WARN_BLOCKLIST=1              # remote rejections mentioning a blocklist/reputation
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
# shellcheck source=/dev/null
[[ -r $CONF ]] && . "$CONF"

UPLOAD=1
[[ ${1:-} == --no-upload ]] && UPLOAD=0

OUT_DIR=$STATE_DIR/out
mkdir -p "$STATE_DIR/offsets" "$OUT_DIR"
chmod 700 "$STATE_DIR"

# ---------------------------------------------------------------- GeoIP
GEOIP_DIR=${GEOIP_DIR:-$STATE_DIR/geoip}
GEO_CC_DB="$GEOIP_DIR/dbip-country-lite.mmdb"; GEO_ASN_DB="$GEOIP_DIR/dbip-asn-lite.mmdb"
GEO_OK=0; GEO_NOTE=""
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
if (( GEOIP )); then
  if command -v mmdblookup >/dev/null; then
    geo_update
    if [[ -s $GEO_CC_DB ]]; then GEO_OK=1
    else GEO_NOTE="GeoIP: no database – download from download.db-ip.com failed"; fi
  else
    GEO_NOTE="GeoIP: off – install mmdblookup (Debian/Ubuntu: apt install mmdb-bin)"
  fi
fi
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
exec 9>"$STATE_DIR/lock"
flock -n 9 || exit 0

NOW=$(date '+%Y-%m-%d %H:%M %Z')
RUN_START=$(date +%s)
SINCE=$(cat "$STATE_DIR/last_run" 2>/dev/null || date -d '-1 hour' +%s)
STAMP=$(date '+%Y%m%d-%H%M')
REPORT="$OUT_DIR/report-$STAMP.txt"
BODY=$(mktemp); TMP=$(mktemp)
trap 'rm -f "$BODY" "$TMP" "$TMP.php" "$TMP.u"' EXIT
ALERTS=()
alert() { ALERTS+=("$*"); }
section() { printf '\n== %s ==\n' "$1" >>"$BODY"; }
out() { printf '%s\n' "$*" >>"$BODY"; }
ignored_domain() { [[ " $WEB_IGNORE_DOMAINS " == *" $1 "* ]]; }

# Document roots of all domains: "domain<TAB>path" (Plesk DB, fallback /var/www/vhosts/<domain>/httpdocs)
docroots() {
  if [[ -z ${DOCROOTS_CACHE:-} ]]; then
    DOCROOTS_CACHE=$(plesk db -Ne "SELECT d.name, h.www_root FROM domains d JOIN hosting h ON h.dom_id = d.id" 2>/dev/null)
    if [[ -z $DOCROOTS_CACHE ]]; then
      local d
      for d in "$(dirname "$VHOST_LOGS")"/*/httpdocs; do
        [[ -d $d ]] && DOCROOTS_CACHE+="$(basename "$(dirname "$d")")"$'\t'"$d"$'\n'
      done
    fi
  fi
  printf '%s\n' "$DOCROOTS_CACHE" | grep -v '^$'
}
docroot_of() { docroots | awk -F'\t' -v d="$1" '$1 == d {print $2; exit}'; }

# Print only the lines appended to a log file since the previous run.
# Handles logrotate (the remainder of the rotated file .1 is read as well).
new_lines() {
  local f=$1 key st ino size off=0 oino="" ooff=0
  [[ -r $f ]] || return 0
  key=$(printf '%s' "$f" | md5sum | cut -c1-16)
  st="$STATE_DIR/offsets/$key"
  ino=$(stat -c %i "$f"); size=$(stat -c %s "$f")
  if [[ -f $st ]]; then
    read -r oino ooff <"$st"
    if [[ $oino == "$ino" && $ooff -le $size ]]; then
      off=$ooff
    elif [[ -r $f.1 && $(stat -c %i "$f.1") == "$oino" ]]; then
      tail -c +"$((ooff + 1))" "$f.1"          # rest of the file before rotation
    fi
  else
    # first run: only the last 20,000 lines to keep it fast
    tail -n 20000 "$f" | head -c "$size"
    echo "$ino $size" >"$st"; return 0
  fi
  tail -c +"$((off + 1))" "$f" | head -c "$((size - off))"
  echo "$ino $size" >"$st"
}

num_gt() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a>b)}'; }

# =============================================================== MAIL
section "MAIL"
MAILLOG=""
for f in /var/log/maillog /var/log/mail.log; do [[ -r $f ]] && { MAILLOG=$f; break; }; done

if [[ -n $MAILLOG ]]; then
  new_lines "$MAILLOG" >"$TMP"
else
  # no log file (no rsyslog): fall back to the journal
  last=$(cat "$STATE_DIR/journal_since" 2>/dev/null || date -d '-1 hour' +%s)
  journalctl --since "@$last" -o short -u postfix\* -u dovecot >"$TMP" 2>/dev/null
  date +%s >"$STATE_DIR/journal_since"
  MAILLOG="journal"
fi
out "Source: $MAILLOG, $(wc -l <"$TMP") new lines"

MAILSTATS=$(awk '
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
  /postfix\/pickup.*uid=/ { m=$0; sub(/.*uid=/, "", m); sub(/[ ,].*/, "", m); pick[m]++ }
  # Recipients per envelope sender
  /postfix\/qmgr.*from=<.*nrcpt=/ {
    f=$0; sub(/.*from=</, "", f); sub(/>.*/, "", f); if (f=="") f="<> (bounce)"
    n=$0; sub(/.*nrcpt=/, "", n); sub(/[^0-9].*/, "", n); rc[f]+=n
    # sender domain differs from the domain of the authenticated mailbox?
    q=qid($0)
    if (q != "" && (q in sq) && !(q in mdone) && sq[q] ~ /@/ && f ~ /@/ && dom(f) != dom(sq[q])) {
      mdone[q]=1; su=sq[q]; mm[su]++
      if (!((su SUBSEP f) in mms) && mmc[su] < 3) { mms[su SUBSEP f]=1; mmc[su]++; mml[su]=mml[su] " " f }
    }
  }
  / status=sent/     { sent++ }
  / status=deferred/ { def++ }
  / status=bounced/  { bou++ }
  / status=(deferred|bounced)/ {
    l=tolower($0)
    if (l ~ /blacklist|blocklist|blocked|spamhaus|barracuda|spamcop|listed|reputation|poor ip|banned/) {
      bl++; if (blx < 3) bex[++blx]=substr($0, 1, 300)
    }
  }
  /SASL (LOGIN|PLAIN|CRAM-MD5) authentication failed/ {
    sf++; sip[ipof($0)]++
    if (match($0, /sasl_username=[^ ,]+/)) fu[substr($0, RSTART+14, RLENGTH-14)]++
  }
  /(imap|pop3)-login: .*(auth failed|Authentication failed)/ {
    df++; r=$0; if (match(r, /rip=[0-9a-fA-F:.]+/)) dip[substr(r, RSTART+4, RLENGTH-4)]++
  }
  END {
    printf "TOT\t%d\t%d\t%d\t%d\t%d\t%d\n", sent, def, bou, bl, sf, df
    for (u in sasl) printf "SASL\t%d\t%d\t%s\t%s\n", sasl[u], nip[u], u, ipl[u]
    for (k in sic) { split(k, kk, SUBSEP); printf "SAIP\t%d\t%s\t%s\n", sic[k], kk[1], kk[2] }
    for (m in pick) printf "PICK\t%d\t%s\n", pick[m], m
    for (f in rc)   printf "RCPT\t%d\t%s\n", rc[f], f
    for (i in sip)  printf "SFIP\t%d\t%s\n", sip[i], i
    for (i in dip)  printf "DFIP\t%d\t%s\n", dip[i], i
    for (u in fu)   printf "FUSR\t%d\t%s\n", fu[u], u
    for (u in mm)   printf "MISM\t%d\t%s\t%s\n", mm[u], u, mml[u]
    for (i=1; i<=blx; i++) printf "BLEX\t%s\n", bex[i]
  }' "$TMP")

read -r _ SENT DEF BOU BL SF DF <<<"$(grep '^TOT' <<<"$MAILSTATS")"
QUEUE=$(postqueue -j 2>/dev/null | wc -l)
out "Delivered: $SENT | deferred: $DEF | bounced: $BOU | queue: $QUEUE"
out "Rejections mentioning blocklist/reputation: $BL"
(( DEF > WARN_DEFERRED )) && alert "Mail: $DEF deferred deliveries"
(( BL >= WARN_BLOCKLIST )) && alert "Mail: $BL rejections mentioning a blocklist/reputation – check the server IP"
(( QUEUE > WARN_QUEUE )) && alert "Mail: $QUEUE messages in the queue"
grep '^BLEX' <<<"$MAILSTATS" | cut -f2- | sed 's/^/  example: /' >>"$BODY"

PUBIP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="src") print $(i+1)}')
if [[ $PUBIP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && ! $PUBIP =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.) ]]; then
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
while IFS=$'\t' read -r _ n who; do
  [[ $who == "<> (bounce)" ]] && continue
  (( n > WARN_MAILS_PER_SENDER )) && alert "Mail: $who sent to $n recipients"
done < <(grep '^RCPT' <<<"$MAILSTATS")

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
declare -A FOREIGN_N=() FOREIGN_W=()
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

out ""; out "Failed mail logins: SMTP $SF | IMAP/POP3 $DF – top IPs:"
(( SF + DF > WARN_AUTH_FAIL )) && alert "Mail: $((SF + DF)) failed mail logins (brute force?)"
while IFS=$'\t' read -r c ip; do
  geo "$ip"; printf '  %6d  %s%s\n' "$c" "$ip" "${GEO_LABEL:+ ($GEO_LABEL)}" >>"$BODY"
done < <(grep -E '^(SFIP|DFIP)' <<<"$MAILSTATS" | awk -F'\t' '{a[$3]+=$2} END{for(i in a) print a[i]"\t"i}' | sort -nr | head -5)
out "Most attacked mailboxes (failed SMTP logins):"
grep '^FUSR' <<<"$MAILSTATS" | sort -t$'\t' -k2,2nr | head -5 |
  awk -F'\t' '{printf "  %6d  %s\n", $2, $3}' >>"$BODY"

# --------------------------------------------------------------- webmail (Roundcube)
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
  declare -A WFOREIGN=()
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
fi

# =============================================================== CPU / RAM / DISK
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

# =============================================================== FAIL2BAN
section "FAIL2BAN"
if command -v fail2ban-client >/dev/null; then
  JAILS=$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ' ' | tr ',' ' ')
  for j in $JAILS; do
    s=$(fail2ban-client status "$j" 2>/dev/null)
    cb=$(sed -n 's/.*Currently banned:[[:space:]]*//p' <<<"$s")
    tb=$(sed -n 's/.*Total banned:[[:space:]]*//p' <<<"$s")
    cf=$(sed -n 's/.*Currently failed:[[:space:]]*//p' <<<"$s")
    [[ ${cb:-0} -gt 0 || ${cf:-0} -gt 0 ]] && printf '  %-28s banned: %3s (total %s), currently failed: %s\n' "$j" "$cb" "$tb" "$cf" >>"$BODY"
  done
  out "  (jails without bans/failures hidden)"
else
  out "fail2ban not installed"; alert "fail2ban is not running"
fi

# =============================================================== WEB
section "WEB (since last run)"
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

# =============================================================== NEW PHP FILES IN UPLOAD FOLDERS
section "WEBROOTS: PHP files in upload folders"
SCAN_STAMP="$STATE_DIR/last_scan"
touch "$SCAN_STAMP.new"   # remember the time before scanning
while IFS= read -r up; do
  if [[ -f $SCAN_STAMP ]]; then
    find "$up" -type f \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.phar' \) -newer "$SCAN_STAMP" 2>/dev/null
  else
    find "$up" -type f \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.phar' \) ! -name 'index.php' 2>/dev/null
  fi
done < <(find "$(dirname "$VHOST_LOGS")" -mindepth 2 -maxdepth 7 -type d -path '*/wp-content/uploads' ! -path '*/system/*' 2>/dev/null) |
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
mv "$SCAN_STAMP.new" "$SCAN_STAMP"

# =============================================================== SUCCESSFUL LOGINS
section "SUCCESSFUL LOGINS (SSH, Plesk panel)"
KNOWN="$STATE_DIR/known_login_ips"
FIRST_LOGIN_RUN=0; [[ -f $KNOWN ]] || { FIRST_LOGIN_RUN=1; : >"$KNOWN"; }
rm -f "$STATE_DIR/new_login_alerts"
{
  if [[ -r /var/log/auth.log ]]; then new_lines /var/log/auth.log
  elif [[ -r /var/log/secure ]]; then new_lines /var/log/secure
  else journalctl --since "@$SINCE" -u ssh -u sshd -o short 2>/dev/null; fi |
    awk '/sshd.*Accepted / { for (i=1;i<=NF;i++) { if ($i=="Accepted") m=$(i+1); if ($i=="for") u=$(i+1); if ($i=="from") ip=$(i+1) }
                             print "SSH\t" u "\t" ip "\t" m }'
  # Plesk panel: best-effort match of successful login lines (format varies by version)
  new_lines "$PLESK_PANEL_LOG" | grep -iE 'log(ged)? ?in' | grep -viE 'fail|invalid|wrong|denied|error' |
    awk '{ ip=""; if (match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) ip=substr($0, RSTART, RLENGTH);
           u="?"; if (match($0, /login[=: ]+"?[A-Za-z0-9_.@-]+/)) { u=substr($0, RSTART, RLENGTH); sub(/login[=: ]+"?/, "", u) }
           if (ip != "") print "Plesk\t" u "\t" ip "\tpanel" }'
} | sort | uniq -c | while read -r cnt rest; do
  IFS=$'\t' read -r kind user ip meth <<<"$rest"
  geo "$ip"
  printf '  %4d× %-5s %-14s from %-16s (%s)%s\n' "$cnt" "$kind" "$user" "$ip" "$meth" "${GEO_LABEL:+  $GEO_LABEL}" >>"$BODY"
  if ! grep -qxF "$ip" "$KNOWN"; then
    echo "$ip" >>"$KNOWN"
    fnote=""; geo_foreign && fnote=" – OUTSIDE $ALLOWED_COUNTRIES"
    (( FIRST_LOGIN_RUN )) || echo "$kind login as $user from previously unknown IP $ip${GEO_LABEL:+ ($GEO_LABEL)}$fnote" >>"$STATE_DIR/new_login_alerts"
  fi
done
if [[ -s $STATE_DIR/new_login_alerts ]]; then
  while IFS= read -r a; do alert "Login: $a"; done <"$STATE_DIR/new_login_alerts"
  rm -f "$STATE_DIR/new_login_alerts"
fi
(( FIRST_LOGIN_RUN )) && out "  (first run: all IPs stored as known; from now on new IPs raise an alert. List: $KNOWN)"

# =============================================================== SERVICES / OOM
section "SERVICES"
if command -v systemctl >/dev/null; then
  FAILED=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | xargs)
  out "Failed units: ${FAILED:-none}"
  [[ -n $FAILED ]] && alert "Service(s) failed: $FAILED"
fi
if command -v journalctl >/dev/null; then
  OOM=$(journalctl -k --since "@$SINCE" 2>/dev/null | grep -iE 'out of memory|oom-kill|killed process' | grep -oE 'Killed process [0-9]+ \([^)]+\)' | sort | uniq -c | xargs)
  out "OOM killer: ${OOM:-none}"
  [[ -n $OOM ]] && alert "RAM: the kernel killed processes due to low memory: $OOM"
fi

# =============================================================== DAILY CHECKS
DAILY="$STATE_DIR/daily.txt"; DALERTS="$STATE_DIR/daily_alerts.txt"

# ---------------------------------------------------------------- SPF / DKIM / DMARC helpers
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
# ---------------------------------------------------------------- document-root scans
exposed_files_check() {
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
    done < <(find "$root" -maxdepth 6 \( -path '*/node_modules' -o -path '*/wp-content/cache' -o -path '*/vendor/*/tests' \) -prune -o \
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
webshell_check() {
  local stamp="$STATE_DIR/webshell_scan" new="$STATE_DIR/webshell_scan.new" dom root out="" n=0 hits=0 f
  local re='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|gzdecode)[[:space:]]*\(|assert[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)|\$_(POST|GET|REQUEST|COOKIE)[[:space:]]*\[[^]]*\][[:space:]]*\(|preg_replace[[:space:]]*\([[:space:]]*["'"'"'][^"'"'"']*/e["'"'"']|create_function[[:space:]]*\([^)]*\$_(POST|GET|REQUEST)|(system|shell_exec|passthru|exec|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)'
  touch "$new"
  echo ""; echo "Suspicious code in recently changed PHP files (typical webshell/backdoor patterns):"
  while IFS=$'\t' read -r dom root; do
    [[ -d $root ]] || continue
    n=$((n + 1))
    while IFS= read -r f; do
      [[ -n $WEBSHELL_IGNORE && $f =~ $WEBSHELL_IGNORE ]] && continue
      hits=$((hits + 1))
      out+="  $f ($(date -r "$f" '+%Y-%m-%d %H:%M'))"$'\n'
      dalert "Web: suspicious code in recently changed file $f – check it (webshell/backdoor?)"
    done < <(if [[ -f $stamp ]]; then find "$root" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[0-9]' \) -newer "$stamp" 2>/dev/null
             else find "$root" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[0-9]' \) -mtime -"$WEBSHELL_FIRST_DAYS" 2>/dev/null; fi |
             xargs -r -d '\n' grep -lE "$re" 2>/dev/null | head -30)
  done < <(docroots)
  mv "$new" "$stamp"
  [[ -n $out ]] && printf '%s' "$out"
  echo "  $n document root(s) scanned, $hits suspicious file(s)"
}

# ---------------------------------------------------------------- server DNS, mail TLS, domain DNS
server_dns_check() {
  local ptr fwd helo hname v6proto
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
  # IPv6 – only relevant if the server has a global IPv6 and Postfix uses it
  PUBIP6=""
  if [[ $CHECK_IPV6 != 0 ]]; then
    PUBIP6=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="src") print $(i+1)}')
    # only a real public address counts: not link-local (fe80::/10), ULA (fc00::/7) or loopback,
    # and it must be configured with global scope on an interface
    if [[ -n $PUBIP6 ]]; then
      if [[ ${PUBIP6,,} =~ ^(fe[89ab]|f[cd]|::1$|::$) ]] ||
         ! ip -6 -o addr show scope global 2>/dev/null | grep -qiF -- " ${PUBIP6}/"; then PUBIP6=""; fi
    fi
    v6proto=$(postconf -h inet_protocols 2>/dev/null)
    if [[ $CHECK_IPV6 == auto && ( -z $PUBIP6 || ! $v6proto =~ all|ipv6 ) ]]; then PUBIP6=""; fi
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
mail_tls_check() {
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
domain_dns_check() {
  local d st a aaaa here caa par n=0 out="" r bl
  for d in "$@"; do
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
mailauth_check() {
  local d doms ok=0 bad=0 spf spf_ok dkim dmarc mxinfo mxhere ns line key dnskey m nmb probs
  doms=$( { ls "$MAILNAMES_DIR" 2>/dev/null; ls "$DKIM_KEY_DIR" 2>/dev/null; } | sort -u)
  for d in $doms; do
    [[ $d == *.* && " $MAILAUTH_IGNORE_DOMAINS " != *" $d "* ]] || continue
    nmb=$(find "$MAILNAMES_DIR/$d" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | grep -vc '/@')
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
    probs=""
    (( spf_ok )) || [[ $spf == "+all" ]] || probs+=" SPF:${spf}"
    if [[ $spf == "+all" ]] && (( mxhere )); then
      dalert "Mail auth: $d – SPF ends in +all: anyone may send mail as this domain (DNS at ${ns:-?})"
    fi
    if [[ $spf == permerror* ]] && (( mxhere )); then
      dalert "Mail auth: $d – SPF record is invalid (${spf#permerror:}) – receivers treat it as a hard error (DNS at ${ns:-?})"
    fi
    [[ $dkim == MISSING || $dkim == MISMATCH ]] && probs+=" DKIM:${dkim,,}"
    # DMARC passes if SPF *or* DKIM passes – only both failing breaks delivery
    local broken=0
    (( ! spf_ok )) && [[ $spf != "+all" && $dkim != ok ]] && broken=1
    line=$(printf '  %-28s SPF %-9s | DKIM %-8s | DMARC %-12s | MX %s | DNS %s' "$d" \
      "$spf" "$dkim" "${dmarc:-missing}" "$( ((mxhere)) && echo here || echo "${mxinfo:-none}")" "${ns:-?}")
    if [[ -n $probs ]]; then
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
  echo "  $ok domain(s) OK, $bad with findings. Alert only if SPF and DKIM both fail and the MX points here;"
  echo "  a single missing/outdated record is a recommendation (DMARC passes if SPF or DKIM passes)."
  echo "  DNS queried via ${MAILAUTH_RESOLVER:-system resolver}"
}
run_daily() {
  : >"$DALERTS"
  dalert() { echo "$*" >>"$DALERTS"; }
  echo "As of: $(date '+%Y-%m-%d %H:%M %Z')"

  # --- updates
  if command -v apt-get >/dev/null; then
    local upg sec
    upg=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep '^Inst' || true)
    sec=$(grep -ci 'security' <<<"$upg" || true)
    echo "Updates available: $(grep -c . <<<"$upg" || true), security updates: $sec"
    grep -i security <<<"$upg" | awk '{print "  " $2}' | head -10
    (( sec > 0 )) && dalert "Updates: $sec security update(s) pending"
    if [[ -f /var/run/reboot-required ]]; then
      echo "Reboot required (since $(date -r /var/run/reboot-required '+%Y-%m-%d'))"
      dalert "System: reboot required after updates"
    fi
  elif command -v dnf >/dev/null; then
    local sec
    sec=$(dnf -q updateinfo list --security 2>/dev/null | grep -c . || true)
    echo "Security updates available: $sec"
    (( sec > 0 )) && dalert "Updates: $sec security update(s) pending"
    if command -v needs-restarting >/dev/null && ! needs-restarting -r >/dev/null 2>&1; then
      echo "Reboot required"; dalert "System: reboot required after updates"
    fi
  fi

  # --- TLS certificates (checked live on the server's public IP)
  echo ""; echo "TLS certificates:"
  local doms now d c end days san soon=0 nossl="" port
  LE_DOMAINS=""
  now=$(date +%s)
  doms=$( { command -v plesk >/dev/null && plesk bin site --list 2>/dev/null; echo "$HOST"; } | sort -u)
  for d in $doms; do
    port=443; [[ $d == "$HOST" ]] && port=8443
    c=$(echo | timeout 6 openssl s_client -connect "${PUBIP:-127.0.0.1}:$port" -servername "$d" 2>/dev/null | openssl x509 -noout -enddate -issuer -ext subjectAltName 2>/dev/null)
    grep -qi "Let's Encrypt" <<<"$c" && LE_DOMAINS+=" $d"
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

  # --- server DNS: PTR / HELO / IPv6 and mail server certificates
  (( SERVER_DNS_CHECK )) && command -v dig >/dev/null && server_dns_check
  mail_tls_check

  # --- per-domain DNS: A/AAAA here?, CAA, DNSSEC, domain blocklists
  (( DOMAIN_DNS_CHECK )) && command -v dig >/dev/null && domain_dns_check $doms

  # --- document roots: exposed files and webshell code
  (( EXPOSED_FILES_CHECK )) && exposed_files_check
  (( WEBSHELL_CHECK )) && webshell_check

  # --- mail authentication: SPF / DKIM / DMARC
  if (( MAILAUTH_CHECK )); then
    echo ""; echo "Mail authentication (SPF / DKIM / DMARC):"
    if ! command -v dig >/dev/null; then
      echo "  skipped – dig not installed (Debian/Ubuntu: apt install bind9-dnsutils)"
    elif [[ -z ${PUBIP:-} ]]; then
      echo "  skipped – public IPv4 of this server unknown"
    else
      mailauth_check
    fi
  fi

  # --- backups
  echo ""; echo "Backups:"
  local pmm last age st
  for pmm in /var/log/plesk/PMM /usr/local/psa/PMM/logs /opt/psa/PMM/logs; do [[ -d $pmm ]] && break; pmm=""; done
  if [[ -n $pmm ]]; then
    last=$(find -L "$pmm" -maxdepth 2 -type d -name 'backup-*' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)
    if [[ -n $last ]]; then
      age=$(( (now - $(stat -c %Y "$last")) / 3600 ))
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
      echo "  Plesk backup: last run $age h ago ($(basename "$last")), status: $st"
      [[ -n $ex ]] && echo "    first error: $ex"
      (( age > WARN_BACKUP_HOURS )) && dalert "Backup: latest Plesk backup is $age hours old"
      [[ $st == ERROR* ]] && dalert "Backup: latest Plesk backup finished with errors"
    else
      echo "  Plesk backup: no backup logs found in $pmm"
    fi
  else
    echo "  Plesk backup: log directory not found"
  fi
  # Acronis agent (used by several hosting providers for image backups) – only if installed
  if pgrep -x aakore >/dev/null || pgrep -f '[a]cronis' >/dev/null; then
    echo "  Acronis agent: running"
  elif [[ -d /usr/lib/Acronis || -d /opt/acronis || -d /var/lib/Acronis ]]; then
    echo "  Acronis agent: installed but NOT running"; dalert "Backup: Acronis agent is not running"
  fi
}
if [[ $(cat "$STATE_DIR/daily_date" 2>/dev/null) != "$(date +%F)" ]]; then
  run_daily >"$DAILY.new" 2>/dev/null; mv "$DAILY.new" "$DAILY"
  date +%F >"$STATE_DIR/daily_date"
fi
section "DAILY CHECKS"
cat "$DAILY" >>"$BODY" 2>/dev/null
[[ -f $DALERTS ]] && while IFS= read -r a; do [[ -n $a ]] && alert "$a"; done <"$DALERTS"

# =============================================================== WRITE REPORT
{
  echo "Server report $HOST – $NOW"
  if (( ${#ALERTS[@]} )); then
    echo "STATUS: WARNING (${#ALERTS[@]})"
    printf ' ! %s\n' "${ALERTS[@]}"
  else
    echo "STATUS: OK"
  fi
  cat "$BODY"
  echo ""
  if (( GEO_OK )); then echo "IP geolocation: DB-IP.com Lite databases (CC BY 4.0)"
  elif [[ -n $GEO_NOTE ]]; then echo "$GEO_NOTE"; fi
} >"$REPORT"
chmod 600 "$REPORT"

# =============================================================== UPLOAD
if (( ! UPLOAD )); then
  cat "$REPORT"
elif [[ -n $REMOTE ]] && command -v rclone >/dev/null; then
  rclone copyto "$REPORT" "$REMOTE/$(basename "$REPORT")" --quiet &&
  rclone copyto "$REPORT" "$REMOTE/latest.txt" --quiet ||
    logger -t plesk-server-report "upload to $REMOTE failed"
  if (( RETENTION_DAYS > 0 )); then
    # delete old reports permanently (Google Drive: not into the trash)
    rclone delete "$REMOTE" --include 'report-*.txt' --min-age "${RETENTION_DAYS}d" \
      --drive-use-trash=false --quiet ||
      logger -t plesk-server-report "deleting old reports in $REMOTE failed"
  fi
fi
find "$OUT_DIR" -name 'report-*.txt' -mtime +"$LOCAL_KEEP_DAYS" -delete
echo "$RUN_START" >"$STATE_DIR/last_run"
