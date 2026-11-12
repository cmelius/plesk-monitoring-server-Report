# shellcheck shell=bash
# shellcheck disable=SC2034  # the PLUGIN_ header is read by the main script
PLUGIN_NAME="php-config"
PLUGIN_API="0"
PLUGIN_SCHEDULE="daily"
PLUGIN_SECTION=""    # a daily check: it prints its own heading
PLUGIN_INPUTS="domains"
PLUGIN_SETTINGS="WEBSHELL_IGNORE"
PLUGIN_READS="the .htaccess, .user.ini and php.ini files in the document roots"
PLUGIN_OS="debian rhel"
PLUGIN_MAINTAINER="core"

# .htaccess / .user.ini / php.ini: settings that make the web server run attacker code – a file
# loaded before every PHP request (auto_prepend_file/auto_append_file, except known security
# plugins), PHP executed for image or text files, and the signature of a widespread WordPress
# malware campaign that blocks every PHP file except its own.
#
# These files are few and small: the first scan checks all of them, whatever their date – a
# backdoor may be older than the script. Later scans look only at files changed since the last
# complete scan (file date or inode change time; a backdated file still has a fresh ctime).
# State: "last_scan <Unix time with nanoseconds>" – printed only after a complete scan; a scan cut off by the
# time limit prints none, so the next one looks again.

# php_config_backdoors < list of files – prints "FILE<TAB>LINE" per hit
php_config_backdoors() {
  # shellcheck disable=SC2016  # awk program: its $0 is awk's, not the shell's
  xargs -r -d '\n' awk '
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

plugin_check() {
  local last now dom root f ln n=0 hits=0
  now=$(date +%s.%N)   # with nanoseconds, like the file times find compares it with
  last=$(awk '$1 == "last_scan" && $2 ~ /^[0-9]+(\.[0-9]+)?$/ { t = $2 } END { print t }' "$PSR_STATE")
  out ""; out "PHP settings in .htaccess, .user.ini and php.ini (code loaded before every request, PHP for image files, known malware):"
  while IFS=$'\t' read -r dom root; do
    [[ -n $root && -d $root ]] || continue
    n=$((n + 1))
    while IFS=$'\t' read -r f ln; do
      [[ -n $WEBSHELL_IGNORE && $f =~ $WEBSHELL_IGNORE ]] && continue
      hits=$((hits + 1))
      out "  $f: $ln (file date $(date -r "$f" '+%Y-%m-%d %H:%M'))"
      alert "Web: suspicious PHP setting in recently changed $f: $ln – check it (backdoor?)"
    done < <(if [[ -n $last ]]; then find "$root" -type f \( -name .htaccess -o -name .user.ini -o -name php.ini \) \( -newermt "@$last" -o -newerct "@$last" \) 2>/dev/null
             else find "$root" -type f \( -name .htaccess -o -name .user.ini -o -name php.ini \) 2>/dev/null; fi |
             php_config_backdoors | head -30)
  done <"$PSR_DOMAINS"
  out "  $n document root(s) scanned, $hits suspicious file(s)"
  state "last_scan $now"
  return 0
}
