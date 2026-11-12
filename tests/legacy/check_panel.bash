# check_panel as it was in the main script before it became plugins/panel.sh (1.11.0),
# kept verbatim for the parity test in tests/panel.bats: the same fixture through this
# function and through the plugin must give the same report and the same alerts.
# Removed when the plugin contract is frozen.
# shellcheck shell=bash
legacy_check_panel() {
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
