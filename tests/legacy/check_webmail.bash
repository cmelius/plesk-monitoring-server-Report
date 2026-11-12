# check_webmail as it was inside the main script before it became plugins/webmail.sh – kept,
# unchanged, for the parity test in webmail.bats.
# shellcheck shell=bash
legacy_check_webmail() {   # Roundcube: mails sent per mailbox with real client IP, failed webmail logins
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
