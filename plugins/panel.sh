# shellcheck shell=bash
# shellcheck disable=SC2034  # the PLUGIN_ header is read by the main script
PLUGIN_NAME="panel"
PLUGIN_API="0"
PLUGIN_SCHEDULE="hourly"
PLUGIN_SECTION="PLESK PANEL LOG"
PLUGIN_SETTINGS="PLESK_ERROR_LOG WEB_IGNORE_DOMAINS"
PLUGIN_LOGS="$PLESK_ERROR_LOG"
PLUGIN_OS="debian rhel"
PLUGIN_MAINTAINER="core"

# Plesk's own log (panel.log): failed panel logins with the login name, and failed automatic
# certificate renewals (Let's Encrypt via SSL It!) with Let's Encrypt's reason. Plesk renews
# 30 days before expiry and retries daily, so a failure shows up weeks before the certificate
# check warns – usually a domain whose DNS points elsewhere, or a blocked challenge URL.
plugin_check() {
  local P n ip d r line="" k
  if [[ -n $PSR_LOGS_MISSING ]]; then out "Plesk log PLESK_ERROR_LOG=\"$PLESK_ERROR_LOG\" not found (no Plesk?) – skipped"; return 0; fi
  P=$(awk -v apo="'" -v sep="$PSR_SEP" '
    substr($0, 1, 1) == sep { next }
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
      for (d in fr) printf "CERT\t%d\t%s\t%s\n", fr[d], d, why[d] }')

  read -r _ n <<<"$(grep '^PFAIL' <<<"$P")"
  out "Failed panel logins: ${n:-0}"
  if (( ${n:-0} > 0 )); then
    out "  login names: $(grep '^PLOG' <<<"$P" | sort -t$'\t' -k2,2nr | head -5 | awk -F'\t' '{printf "%s%s ×%d", (NR > 1 ? ", " : ""), $3, $2}')"
    while IFS=$'\t' read -r _ n ip; do
      line+="${line:+, }$(geo_ref "$ip") ×$n"
    done < <(grep '^PIP' <<<"$P" | sort -t$'\t' -k2,2nr | head -5)
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
  done < <(grep '^CERT' <<<"$P" | sort -t$'\t' -k3,3)
  (( k )) || out "  none"
  return 0
}
