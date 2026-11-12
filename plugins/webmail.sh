# shellcheck shell=bash
# shellcheck disable=SC2034  # the PLUGIN_ header is read by the main script
PLUGIN_NAME="webmail"
PLUGIN_API="0"
PLUGIN_SCHEDULE="hourly"
PLUGIN_SECTION=""    # continues the section MAIL, where the summary looks for its lines
PLUGIN_SETTINGS="ROUNDCUBE_LOG_DIR WARN_MAILS_PER_SASL WARN_MAILS_PER_SENDER WARN_IPS_PER_MAILBOX WARN_LOGIN_BRUTE_FAILS WARN_AUTH_FAIL ALLOWED_COUNTRIES"
PLUGIN_LOGS="$ROUNDCUBE_LOG_DIR/sendmail $ROUNDCUBE_LOG_DIR/errors /var/log/plesk-roundcube/sendmail /var/log/plesk-roundcube/errors /usr/share/psa-roundcube/logs/sendmail /usr/share/psa-roundcube/logs/errors"
PLUGIN_OS="debian rhel"
PLUGIN_MAINTAINER="core"

# Roundcube: mails sent per mailbox with the real client IP, failed webmail logins.
# Roundcube connects to Postfix/Dovecot from localhost, so the mail log shows neither
# the real client IP nor (on Plesk) the mailbox. Roundcube's own logs have both:
#   sendmail: "User <mailbox> [<ip>]; Message <id> for <rcpt>, <rcpt>; 250: ..."
#   errors:   "Login failed for <mailbox> against localhost from <ip>."
# The main script sends the logs of every place in PLUGIN_LOGS; the ones of the directory
# in use are taken, by the path in the line before each log.
plugin_check() {
  local RC_DIR d WEBMAIL WSIP n nr who nip line k c ip fails WFL
  RC_DIR=$ROUNDCUBE_LOG_DIR
  if [[ -z $RC_DIR ]]; then
    for d in /var/log/plesk-roundcube /usr/share/psa-roundcube/logs; do [[ -d $d ]] && { RC_DIR=$d; break; }; done
  fi
  out ""; out "Webmail (Roundcube) – mails sent (mails, recipients, IPs):"
  if [[ -n $RC_DIR && -d $RC_DIR ]]; then
    WEBMAIL=$(awk -v sep="$PSR_SEP" -v s="${RC_DIR%/}/sendmail" -v e="${RC_DIR%/}/errors" '
      substr($0, 1, 1) == sep { p = $0; sub(/^[^ ]* [^ ]* /, "", p); log_ = (p == s ? "S" : (p == e ? "E" : "")); next }
      log_ == "S" && / User [^ ]+ \[[0-9a-fA-F:.]+\]; Message / {
        u=$0; sub(/.* User /, "", u); ip=u; sub(/ .*/, "", u); sub(/^[^[]*\[/, "", ip); sub(/\].*/, "", ip)
        r=$0; sub(/.*; Message [^ ]+ for /, "", r); sub(/; [0-9][0-9][0-9]:.*/, "", r); nr=split(r, x, ",")
        ms[u]++; rcp[u]+=nr; mip[u SUBSEP ip]++
      }
      log_ == "E" && /Login failed for .* from / {
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
      out "$(printf '  %6d  %5d rcpt  %2d IPs  %s' "$n" "$nr" "$nip" "$who")"
      line=""; k=0
      while IFS=$'\t' read -r _ c _ ip _; do
        k=$((k + 1)); (( k > 5 )) && { line+=", …"; break; }
        line+="${line:+, }$(geo_ref "$ip") ×$c"
      done < <(awk -F'\t' -v u="$who" '$3 == u' <<<"$WSIP")
      [[ -n $line ]] && out "          $line"
      (( n > WARN_MAILS_PER_SASL )) && alert "Mail: webmail user $who sent $n mails"
      (( nr > WARN_MAILS_PER_SENDER )) && alert "Mail: webmail user $who sent to $nr recipients"
      (( nip > WARN_IPS_PER_MAILBOX )) && alert "Mail: webmail user $who used from $nip different IPs – password compromised?"
    done < <(grep '^WSND' <<<"$WEBMAIL" | sort -t$'\t' -k2,2nr | head -10)
    local -A WIPS=()
    local -a WHO=()
    while IFS=$'\t' read -r _ c who ip fails; do
      [[ -n $ip ]] || continue
      [[ -n ${WIPS[$who]+x} ]] || WHO+=("$who")
      WIPS[$who]+="$ip "
      (( fails >= WARN_LOGIN_BRUTE_FAILS )) &&
        alert "Mail: webmail user $who sent $c mails from $(geo_ref "$ip") after $fails failed logins from that IP – password guessed?"
    done <<<"$WSIP"
    for who in ${WHO[@]+"${WHO[@]}"}; do
      alert_foreign "${WIPS[$who]% }" "Mail: webmail user $who sent mails from outside $ALLOWED_COUNTRIES: {ips} – password compromised?"
    done
    WFL=$(grep '^WTOT' <<<"$WEBMAIL" | cut -f2)
    out "Failed webmail logins: ${WFL:-0} – top IPs:"
    (( ${WFL:-0} > WARN_AUTH_FAIL )) && alert "Mail: ${WFL} failed webmail logins (brute force?)"
    while IFS=$'\t' read -r _ c ip; do
      out "$(printf '  %6d  ' "$c")$(geo_ref "$ip")"
    done < <(grep '^WFIP' <<<"$WEBMAIL" | sort -t$'\t' -k2,2nr | head -5)
    out "Most attacked mailboxes (failed webmail logins):"
    while IFS= read -r line; do out "$line"; done < <(grep '^WFUS' <<<"$WEBMAIL" | sort -t$'\t' -k2,2nr | head -5 | awk -F'\t' '{printf "  %6d  %s\n", $2, $3}')
  else
    out "  (no Roundcube log directory found)"
    note "webmail: no Roundcube log directory found (ROUNDCUBE_LOG_DIR) – webmail not checked"
  fi
  return 0
}
