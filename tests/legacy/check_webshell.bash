# check_webshell as it was inside the main script before its scan of .htaccess, .user.ini and
# php.ini became plugins/php-config.sh – kept, with php_config_backdoors, for the parity test in
# php-config.bats. Unchanged but for the names (legacy_…).
# shellcheck shell=bash
legacy_php_config_backdoors() {   # php_config_backdoors < list of files
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
legacy_check_webshell() {   # recently changed PHP files with typical backdoor code, PHP settings in .htaccess/.user.ini
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
             legacy_php_config_backdoors | head -30)
  done < <(docroots)
  # after a timeout the scan was incomplete: keep the old stamp, so the next scan looks again
  if [[ $(timeouts_seen) == "$nto" ]]; then can_write_state && { mv "$new" "$stamp"; : >"$STATE_DIR/webshell_conf_full"; }; fi
  [[ -n $out ]] && printf '%s' "$out"
  echo "  $n document root(s) scanned, $hits suspicious file(s)"
}
