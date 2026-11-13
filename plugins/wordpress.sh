# shellcheck shell=bash
# shellcheck disable=SC2034  # the PLUGIN_ header is read by the main script
PLUGIN_NAME="wordpress"
PLUGIN_API="0"
PLUGIN_SCHEDULE="hourly"
PLUGIN_SECTION="WORDPRESS (since last run)"
PLUGIN_SETTINGS="VHOST_LOGS WARN_LOGIN_POSTS WARN_LOGIN_DETAIL WARN_LOGIN_BRUTE_FAILS ALLOWED_COUNTRIES WEB_IGNORE_DOMAINS UPLOADS_PHP_IGNORE FIND_TIMEOUT"
PLUGIN_LOGS="$VHOST_LOGS/*/logs/access_ssl_log $VHOST_LOGS/*/logs/access_log"
PLUGIN_READS="the folders wp-content/uploads below the parent folder of VHOST_LOGS"
PLUGIN_OS="debian rhel"
PLUGIN_MAINTAINER="core"

# WordPress: login attempts (POSTs to wp-login.php and xmlrpc.php) per domain from the access
# logs, successful logins – from abroad, or after repeated failures from the same IP –, and new
# PHP files in wp-content/uploads, where WordPress keeps media and never PHP.
#
# The main script reads the same access logs for its WEB section; this plugin has log positions
# of its own, so both see every line.
#
# Upload folders: the first scan lists all PHP files there (except index.php); later scans only
# files changed since the last complete scan – by file date or by inode change time (malware sets
# the file date back; the change time can't be set by a user). State: "last_scan <Unix time with
# nanoseconds>", printed only after a complete scan, so a scan cut off by its time limit is
# repeated next time.

# wp_logins < access logs on stdin – per domain with login POSTs:
# POSTs, domain, IPs, busiest IP (count), wp-login.php, successful, xmlrpc.php, blocked,
# "IP=failures-before …" of successful logins (or -), IPs with a success after WARN_LOGIN_BRUTE_FAILS failures (or -)
wp_logins() {
  # shellcheck disable=SC2016  # awk program: its $0 is awk's, not the shell's
  awk -v sep="$PSR_SEP" -v bf="$WARN_LOGIN_BRUTE_FAILS" '
    substr($0, 1, 1) == sep { d = $0; sub(/^[^ ]* [^ ]* /, "", d); sub(/\/logs\/[^\/]*$/, "", d); sub(/.*\//, "", d); next }
    d == "" { next }
    # a successful wp-login.php POST answers 302 (redirect to wp-admin), a failed one 200.
    # Requests with ?action= (lost password, ...) are ignored.
    $6 == "\"POST" && $7 ~ /wp-login\.php/ {
      lp[d]++; wl[d]++; lip[d, $1]++
      if ($7 !~ /action=/) { if ($9 == 302) ws[d, $1]++; else if ($9 == 200) wf[d, $1]++ }
    }
    $6 == "\"POST" && $7 ~ /xmlrpc\.php/ { lp[d]++; xr[d]++; lip[d, $1]++; if ($9 ~ /^40[0-9]$/) xb[d]++ }
    END {
      for (k in lip) { split(k, x, SUBSEP); nl[x[1]]++; if (lip[k] > lm[x[1]]) { lm[x[1]] = lip[k]; lt[x[1]] = x[2] } }
      for (k in ws) { split(k, x, SUBSEP); ns[x[1]] += ws[k]; succ[x[1]] = succ[x[1]] " " x[2] "=" (wf[k] + 0)
                      if (wf[k] >= bf) brute[x[1]] = brute[x[1]] " " x[2] }
      for (dm in lp) {
        s = succ[dm]; b = brute[dm]; if (s == "") s = "-"; if (b == "") b = "-"
        printf "%d\t%s\t%d\t%s (%d)\t%d\t%d\t%d\t%d\t%s\t%s\n", lp[dm], dm, nl[dm], lt[dm], lm[dm], wl[dm] + 0, ns[dm] + 0, xr[dm] + 0, xb[dm] + 0, s, b
      }
    }'
}

wp_uploads() {   # wp_uploads LAST – the PHP files in upload folders (changed since LAST, if given), one per line
  local up
  while IFS= read -r up; do
    if [[ -n $1 ]]; then
      find "$up" -type f \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.phar' \) \( -newermt "@$1" -o -newerct "@$1" \) -print0 2>/dev/null
    else
      find "$up" -type f \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.phar' \) ! -name 'index.php' -print0 2>/dev/null
    fi
  done < <(find "$(dirname "$VHOST_LOGS")" -mindepth 2 -maxdepth 7 -type d -path '*/wp-content/uploads' ! -path '*/system/*' 2>/dev/null) |
    tr '\n\0' '?\n'   # one name per line: a line break in a name is shown as ?
}

plugin_check() {
  local LOGINS lp dom nl lt wl ws xr xb succ brute tok sip sline xnote last now files cnt rc st fm f
  if [[ -z $VHOST_LOGS || ! -d $VHOST_LOGS ]]; then
    out "  skipped – log directory not found"
    note "web: log directory VHOST_LOGS=\"$VHOST_LOGS\" not found – web figures are 0"
    return 0
  fi
  LOGINS=$(wp_logins | sort -t$'\t' -k1,1nr)

  out "login POSTs (wp-login.php + xmlrpc.php) | domain:"
  while IFS=$'\t' read -r lp dom _; do
    [[ -n $dom ]] && out "$(printf '  %6d  %s' "$lp" "$dom")"
  done < <(head -10 <<<"$LOGINS")
  out ""; out "WordPress login attacks (domains with at least $WARN_LOGIN_DETAIL login POSTs):"
  while IFS=$'\t' read -r lp dom nl lt wl ws xr xb succ brute; do
    [[ -n $dom ]] || continue
    if ! ignored_domain "$dom"; then
      (( lp > WARN_LOGIN_POSTS )) && alert "Web: $dom received $lp login attempts (wp-login/xmlrpc)"
      [[ $brute != - ]] && alert "Web: $dom – successful WordPress login from$brute after repeated failures – brute force succeeded? Check the users of this site"
    fi
    sline=""
    if [[ $succ != - ]]; then
      for tok in $(tr ' ' '\n' <<<"$succ" | sort -V); do   # by IP, the same order every run
        sip=${tok%=*}
        sline+="${sline:+, }$(geo_ref "$sip"), ${tok##*=} failures before"
        ignored_domain "$dom" || alert_foreign "$sip" "Web: $dom – successful WordPress login from {ips}, outside $ALLOWED_COUNTRIES"
      done
    fi
    (( lp >= WARN_LOGIN_DETAIL )) || continue
    xnote=""; (( xr > 0 && xb == 0 )) && xnote=" – xmlrpc.php is NOT blocked"
    out "$(printf '  %s: %d POSTs from %d IPs (busiest %s)' "$dom" "$lp" "$nl" "$lt")"
    out "$(printf '    wp-login.php: %d, successful (302): %d | xmlrpc.php: %d, blocked (4xx): %d%s' "$wl" "$ws" "$xr" "$xb" "$xnote")"
    [[ -n $sline ]] && out "    successful wp-login from: $sline"
  done <<<"$LOGINS"

  # ---- PHP files in upload folders
  now=$(date +%s.%N)   # before scanning, with nanoseconds like the file times find compares it with
  last=$(awk '$1 == "last_scan" && $2 ~ /^[0-9]+(\.[0-9]+)?$/ { t = $2 } END { print t }' "$PSR_STATE")
  out ""; out "PHP files in upload folders (wp-content/uploads):"
  # the scan gets two thirds of the time limit, so the login figures above are never lost
  files=$(timeout -k 5 $(( ${FIND_TIMEOUT:-300} * 2 / 3 )) bash -c "$(declare -f wp_uploads); VHOST_LOGS=\"\$1\" wp_uploads \"\$2\"" _ "$VHOST_LOGS" "$last" |
          grep -vE "${UPLOADS_PHP_IGNORE:-^\$}"; exit "${PIPESTATUS[0]}")
  rc=$?
  cnt=$(grep -c . <<<"$files")
  if [[ -n $last ]]; then
    out "New since last run: $cnt"
    (( cnt > 0 )) && alert "Web: $cnt new PHP file(s) in wp-content/uploads – possible malware"
  else
    out "First run – existing PHP files (excluding index.php): $cnt"
    (( cnt > 0 )) && alert "Web: $cnt PHP file(s) found in wp-content/uploads – check whether legitimate"
  fi
  st=${last%%.*}
  while IFS= read -r f; do
    [[ -n $f ]] || continue
    fm=$(stat -c %Y "$f" 2>/dev/null || echo 0)
    if [[ -n $st ]] && (( fm > 0 && fm < st )); then     # found by its change time only
      out "  $f  (file date $(date -d "@$fm" +%F) is older than its last change – set back, or the file was moved/its permissions changed)"
    else out "  $f"; fi
  done < <(head -15 <<<"$files")
  # after a timeout the scan was incomplete: no new state, so the next run looks again
  if (( rc == 124 || rc == 137 )); then
    note "wordpress: the scan of the upload folders took longer than $(( ${FIND_TIMEOUT:-300} * 2 / 3 ))s and was cut off – it is repeated in the next run"
  else
    state "last_scan $now"
  fi
  return 0
}
