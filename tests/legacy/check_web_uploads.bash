# check_web and check_uploads as they were inside the main script before WordPress became
# plugins/wordpress.sh – kept, unchanged, for the parity test in wordpress.bats.
# shellcheck shell=bash
legacy_check_web() {   # requests, 5xx, WordPress logins, PHP errors, attack patterns, peaks, ModSecurity
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

legacy_check_uploads() {   # new PHP files in wp-content/uploads
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
