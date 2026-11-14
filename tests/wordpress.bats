#!/usr/bin/env bats
# the plugin wordpress (plugins/wordpress.sh): login attempts from the access logs of all domains
# (fixtures/web – anonymized logs of a real server; the attacks written here by hand) and new PHP
# files in wp-content/uploads, with the time of the last scan as its state

load helper

setup() {
  load_script
  V="$BATS_TEST_TMPDIR/vhosts"; VHOST_LOGS="$V/system"
  mkdir -p "$VHOST_LOGS" "$V/d1.example/httpdocs/wp-content/uploads/2026/11" "$V/d2.example/httpdocs/wp-content/uploads"
  cp -r "$FIX/web/." "$VHOST_LOGS/"
  U1="$V/d1.example/httpdocs/wp-content/uploads"; U2="$V/d2.example/httpdocs/wp-content/uploads"
  : >"$U1/index.php"; : >"$U1/2026/11/photo.jpg"; : >"$U1/2026/11/x.php"; : >"$U2/shell.phtml"
  mkdir -p "$U1/mailchimp-for-wp"; : >"$U1/mailchimp-for-wp/debug-log.php"   # the log of Mailchimp for WP: ignored by default
  mkdir -p "$VHOST_LOGS/d1.example/wp-content/uploads"; : >"$VHOST_LOGS/d1.example/wp-content/uploads/no.php"   # below system/: not a site
  # git keeps no file times: everything was changed two days ago (the inode change time is now,
  # so a test that needs files older than a scan waits a second: wait_)
  find "$V" -exec touch -d '-2 days' {} +
}
wp() { run_plugin wordpress; }
state() { cat "$STATE_DIR/plugins/wordpress/state"; }
wait_() { sleep 1.1; }
# a GeoIP database for the tests: 198.18.5.x is abroad
foreign_ips() {
  GEO_OK=1; ALLOWED_COUNTRIES="DE"; GEO_TRUSTED_ORGS=""
  geo() { GEO_ORG=""; case $1 in 198.18.5.*) GEO_CC=US ;; *) GEO_CC=DE ;; esac; GEO_LABEL=$GEO_CC; }
}
# attacks on d2.example: 6 failed wp-login POSTs from 198.18.0.30, then a successful one; a
# successful login from abroad; 20 xmlrpc.php POSTs, none blocked; a lost-password POST
attacks() {
  mkdir -p "$VHOST_LOGS/d2.example/logs"
  local i l='"-" "Mozilla/5.0"'
  {
    for i in 1 2 3 4 5 6; do echo "198.18.0.30 - - [12/Nov/2026:10:00:0$i +0000] \"POST /wp-login.php HTTP/1.1\" 200 4000 $l"; done
    echo "198.18.0.30 - - [12/Nov/2026:10:00:07 +0000] \"POST /wp-login.php HTTP/1.1\" 302 0 $l"
    echo "198.18.5.9 - - [12/Nov/2026:10:01:00 +0000] \"POST /wp-login.php HTTP/1.1\" 302 0 $l"
    echo "198.18.0.31 - - [12/Nov/2026:10:01:30 +0000] \"POST /wp-login.php?action=lostpassword HTTP/1.1\" 302 0 $l"
    for i in $(seq 10 29); do echo "198.18.0.40 - - [12/Nov/2026:10:02:$i +0000] \"POST /xmlrpc.php HTTP/1.1\" 200 400 $l"; done
  } >"$VHOST_LOGS/d2.example/logs/access_ssl_log"
  echo "198.18.0.41 - - [12/Nov/2026:10:03:00 +0000] \"GET / HTTP/1.1\" 200 400 $l" >"$VHOST_LOGS/d2.example/logs/access_log"
}

@test "login POSTs per domain, in a section of its own" {
  wp
  run report
  [[ $output == *"== WORDPRESS (since last run) =="*"login POSTs (wp-login.php + xmlrpc.php) | domain:"*"      18  d1.example"* ]]
  [[ $output == *"WordPress login attacks (domains with at least 20 login POSTs):"* ]]
  [[ $output != *"d1.example: "* ]]                         # 18 POSTs: below WARN_LOGIN_DETAIL
  [ -z "$(alerts | grep 'login attempts')" ]
}

@test "attacks: details, brute force that succeeded, a login from abroad, xmlrpc not blocked" {
  attacks; foreign_ips; WARN_LOGIN_POSTS=20
  wp
  run report
  [[ $output == *"      29  d2.example"*"      18  d1.example"* ]]
  [[ $output == *"  d2.example: 29 POSTs from 4 IPs (busiest 198.18.0.40 (20))"* ]]
  [[ $output == *"    wp-login.php: 9, successful (302): 2 | xmlrpc.php: 20, blocked (4xx): 0 – xmlrpc.php is NOT blocked"* ]]
  [[ $output == *"    successful wp-login from: "* && $output == *"198.18.0.30 (DE), 6 failures before"* && $output == *"198.18.5.9 (US), 0 failures before"* ]]
  run alerts
  [[ $output == *"Web: d2.example received 29 login attempts (wp-login/xmlrpc)"* ]]
  [[ $output == *"Web: d2.example – successful WordPress login from 198.18.0.30 after repeated failures – brute force succeeded? Check the users of this site"* ]]
  [[ $output == *"Web: d2.example – successful WordPress login from 198.18.5.9 (US), outside DE"* ]]
  [[ $output != *"198.18.0.30 (DE), outside"* ]]
  WEB_IGNORE_DOMAINS="d2.example"; ALERTS=(); : >"$BODY"
  wp
  [ -z "$(alerts)" ]                                        # ignored: listed, no alerts
  [[ $(report) == *"  d2.example: 29 POSTs"* ]]
}

@test "upload folders: first run lists all PHP files but index.php; then only new ones" {
  wp
  run report
  [[ $output == *"PHP files in upload folders (wp-content/uploads):"*"First run – existing PHP files (excluding index.php): 2"* ]]
  [[ $output == *"  $U1/2026/11/x.php"* && $output == *"  $U2/shell.phtml"* ]]
  [[ $output != *"index.php"*"index.php"* && $output != *"debug-log.php"* && $output != *"no.php"* ]]   # UPLOADS_PHP_IGNORE, system/
  [[ $(alerts) == *"Web: 2 PHP file(s) found in wp-content/uploads – check whether legitimate"* ]]
  [[ $(state) =~ ^last_scan\ [0-9]{10}\.[0-9]{9}$ ]]
  wait_; ALERTS=(); : >"$BODY"
  wp
  [[ $(report) == *"New since last run: 0"* ]]
  [ -z "$(alerts)" ]
  wait_; : >"$U2/new.php"; touch -d '-30 days' "$U2/new.php"; ALERTS=(); : >"$BODY"   # date set back: found by its change time
  wp
  run report
  [[ $output == *"New since last run: 1"*"  $U2/new.php  (file date "*" is older than its last change – set back"* ]]
  [[ $(alerts) == *"Web: 1 new PHP file(s) in wp-content/uploads – possible malware"* ]]
}

@test "the scan time of version 1.x is taken over; --only stores no state" {
  wait_; touch "$STATE_DIR/last_scan"                       # 1.x: scanned after the files were made
  ONLY_MODE=1
  wp
  [[ $(report) == *"New since last run: 0"* ]]
  [ ! -e "$STATE_DIR/plugins/wordpress/state" ]
  ONLY_MODE=0; wp
  [[ $(state) == "last_scan "* ]]
}

@test "no log directory: skipped with a note" {
  VHOST_LOGS="$BATS_TEST_TMPDIR/none"
  wp
  [[ $(report) == *"== WORDPRESS (since last run) =="*"  skipped – log directory not found"* ]]
  [[ $(cat "$TMPD/notes") == *"log directory VHOST_LOGS="* ]]
}

@test "its own log positions: the main script and the plugin both read every line" {
  eval "$(sed -n '/^_new_lines() {/,/^}/p' "$BATS_TEST_DIRNAME/../plesk-server-report.sh")"   # the real one
  attacks; mkdir -p "$STATE_DIR/offsets"
  local f="$VHOST_LOGS/d2.example/logs/access_ssl_log"
  new_lines "$f" >/dev/null                                 # a run of version 1.x: the main script read it all
  echo '198.18.0.50 - - [12/Nov/2026:11:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 1 "-" "-"' >>"$f"
  run_hourly web wordpress                                  # the plugin starts where 1.x stopped
  [[ $(report) == *"       1  d2.example"* ]]
  grep -q " (plugin wordpress)\$" "$STATE_DIR/offsets/$(offset_key "$f" wordpress)"
  echo '198.18.0.51 - - [12/Nov/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 1 "-" "-"' >>"$f"
  : >"$BODY"; check_web
  [[ $(report) =~ \ +1\ +0\ +d2\.example ]]               # the main script: only the new line
  : >"$BODY"; wp
  [[ $(report) == *"       1  d2.example"* ]]               # the plugin too – not taken by the main script
}

@test "a log list with * in the header: every match, numbered by its entry" {
  attacks; rm "$VHOST_LOGS/d2.example/logs/access_log"
  plugin_fetch plugins/wordpress.sh "$TMPD/wp.sh"; plugin_header "$TMPD/wp.sh" wordpress hourly
  plugin_logs
  [ "${PL_LOGS[*]}" = "$VHOST_LOGS/d1.example/logs/access_ssl_log $VHOST_LOGS/d2.example/logs/access_ssl_log " ]
  [ "${PL_NUMS[*]}" = "1 1 2" ]
  [ "$PL_MISS" = 2 ]                                        # no access_log anywhere
}

# the login and upload lines, sorted; the successful logins of a domain in IP order (1.x listed
# them in the order awk keeps them)
lines() {
  grep -E '^  (  )?[a-z0-9.]+: |^    (wp-login|successful)|^  /|^New since|^First run' |
    awk '/^    successful wp-login from: / { l = $0; sub(/^[^:]*: /, "", l); n = 0
           while (match(l, /[0-9.]+ \([^)]*\), [0-9]+ failures before/)) { it[++n] = substr(l, RSTART, RLENGTH); l = substr(l, RSTART + RLENGTH) }
           for (i = 2; i <= n; i++) for (j = i; j > 1 && it[j] < it[j - 1]; j--) { x = it[j]; it[j] = it[j - 1]; it[j - 1] = x }
           o = ""; for (i = 1; i <= n; i++) o = o (i > 1 ? ", " : "") it[i]; print "    successful wp-login from: " o; next } 1' | sort
}

@test "parity: web and wordpress report what check_web and check_uploads reported" {
  # shellcheck source=legacy/check_web_uploads.bash
  source "$BATS_TEST_DIRNAME/legacy/check_web_uploads.bash"
  attacks; foreign_ips; WARN_LOGIN_POSTS=20
  A="$BATS_TEST_TMPDIR/a"; B="$BATS_TEST_TMPDIR/b"; mkdir -p "$A" "$B"
  both() {
    STATE_DIR=$A; ALERTS=(); : >"$BODY"; legacy_check_web; legacy_check_uploads; old=$(report); oa=$(alerts | sort)
    STATE_DIR=$B; ALERTS=(); : >"$BODY"; check_web; run_plugin wordpress; new=$(report); na=$(alerts | sort)
    [[ -n $oa && $oa == "$na" ]]
    # the same lines, wherever they are now: login details, upload files, everything else of WEB
    [ "$(lines <<<"$old")" = "$(lines <<<"$new")" ]
    [ "$(sed -n '/^PHP fatal/,/^== WEBROOTS/p' <<<"$old" | grep -v '^== ')" = "$(sed -n '/^PHP fatal/,/^== WORDPRESS/p' <<<"$new" | grep -v '^== ')" ]
  }
  both
  wait_; : >"$U1/2026/11/y.php"
  both
}

@test "an upload name with a line break: counted once, shown with ?, forges no alert" {
  wp; wait_; ALERTS=(); : >"$BODY"
  : >"$U2/x"$'\n'"ALERT forged.php"
  wp
  run report
  [[ $output == *"New since last run: 1"*"  $U2/x?ALERT forged.php"* ]]
  run alerts
  [[ $output == *"Web: 1 new PHP file(s) in wp-content/uploads – possible malware"* ]]
  [[ $output != *$'\n'"forged"* && $output != "forged"* ]]
  [ "$(grep -c . <<<"$output")" -eq 1 ]
}
