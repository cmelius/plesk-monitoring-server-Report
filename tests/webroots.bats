#!/usr/bin/env bats
# check_uploads (new PHP files in wp-content/uploads) and check_exposed (.env, .git, dumps in
# document roots, with the reachability test stubbed)

load helper

setup() {
  load_script
  V="$BATS_TEST_TMPDIR/vhosts"; VHOST_LOGS="$V/system"; mkdir -p "$VHOST_LOGS"
  UP="$V/a.example/httpdocs/wp-content/uploads"; mkdir -p "$UP/2026/11" "$V/system/b.example/wp-content/uploads"
}
newrun() { : >"$BODY"; : >"$DALERTS"; ALERTS=(); }

@test "uploads, first run: existing PHP files listed (not index.php), stamp stored" {
  touch "$UP/index.php" "$UP/2026/11/shell.php" "$UP/2026/11/photo.jpg" "$UP/2026/11/x.phtml"
  touch "$V/system/b.example/wp-content/uploads/ignored.php"     # below system/: not a website
  check_uploads
  run report
  [[ $output == *"First run – existing PHP files (excluding index.php): 2"* ]]
  [[ $output == *"$UP/2026/11/shell.php"* && $output == *"$UP/2026/11/x.phtml"* ]]
  [[ $output != *"$UP/index.php"* && $output != *ignored.php* && $output != *photo.jpg* ]]
  run alerts
  [[ $output == *"Web: 2 PHP file(s) found in wp-content/uploads – check whether legitimate"* ]]
  [ -f "$STATE_DIR/last_scan" ]
}

@test "uploads, next run: only files changed since the last scan, with an alert" {
  touch "$UP/2026/11/old.php"
  check_uploads; newrun
  sleep 1
  touch "$UP/2026/11/new.php"
  check_uploads
  run report
  [[ $output == *"New since last run: 1"* ]]
  [[ $output == *"$UP/2026/11/new.php"* && $output != *old.php* ]]
  run alerts
  [[ $output == *"Web: 1 new PHP file(s) in wp-content/uploads – possible malware"* ]]
}

@test "uploads: a file with its date set back is found by its change time, and said so" {
  check_uploads; newrun
  sleep 1
  touch -d '2020-01-01' "$UP/2026/11/backdated.php"           # mtime old, ctime now
  check_uploads
  run report
  [[ $output == *"New since last run: 1"* ]]
  [[ $output == *"backdated.php  (file date 2020-01-01 is older than its last change – set back"* ]]
}

@test "uploads: UPLOADS_PHP_IGNORE, and a line break in a name shown as ?" {
  mkdir -p "$UP/mailchimp-for-wp"; touch "$UP/mailchimp-for-wp/debug-log.php" "$UP/2026/11/"$'evil\nname.php'
  check_uploads
  run report
  [[ $output == *"existing PHP files (excluding index.php): 1"* ]]
  [[ $output == *"2026/11/evil?name.php"* && $output != *debug-log* ]]
}

@test "uploads: without the vhost log directory skipped, with a note" {
  VHOST_LOGS="$BATS_TEST_TMPDIR/none"
  check_uploads
  run report
  [[ $output == *"skipped – VHOST_LOGS not found"* ]]
  grep -q 'log directory VHOST_LOGS' "$TMPD/notes"
}

@test "uploads with --only: the stamp is not moved" {
  ONLY_MODE=1
  touch "$UP/2026/11/shell.php"
  check_uploads
  [ ! -f "$STATE_DIR/last_scan" ]
}

# --- check_exposed: the HTTP code per path comes from a map instead of curl
exposed_setup() {
  R="$BATS_TEST_TMPDIR/www/a.example"; mkdir -p "$R"
  docroots() { printf 'a.example\t%s\n' "$R"; }
  CODES="$BATS_TEST_TMPDIR/codes"; : >"$CODES"
  curl() { local u=${*: -1}; u=${u#https://a.example}; awk -v p="$u" '$1 == p {print $2; f=1} END {if (!f) print 404}' "$CODES"; }
}
code() { printf '%s %s\n' "$1" "$2" >>"$CODES"; }

@test "exposed: a publicly reachable .env raises an alert, blocked and missing ones are counted" {
  exposed_setup
  echo 'DB_PASSWORD=x' >"$R/.env"; mkdir -p "$R/.git"; echo x >"$R/dump.sql"; echo x >"$R/backup-2026.zip"
  code /.env 200; code /.git/HEAD 403; code /backup-2026.zip 403
  run check_exposed
  [[ $output == *"  a.example/.env – PUBLICLY REACHABLE (HTTP 200)"* ]]
  [[ $output == *"  a.example: 2 file(s) found but blocked by the web server (HTTP 403)"* ]]
  [[ $output == *"  a.example: 1 file(s) found, not served (server error/no answer), e.g. /dump.sql (HTTP 404)"* ]]
  [[ $output == *"1 document root(s) scanned, 4 finding(s)"* ]]
  [[ $output == *"check again right away"*"--only exposed"* ]]
  grep -q "Web: a.example exposes /.env publicly (HTTP 200)" "$DALERTS"
}

@test "exposed: node_modules, caches and EXPOSED_FILES_IGNORE are left out" {
  exposed_setup
  mkdir -p "$R/node_modules/pkg" "$R/wp-content/cache" "$R/wp-content/plugins/shop/sql"
  touch "$R/node_modules/pkg/.env" "$R/wp-content/cache/db.sql" "$R/wp-content/plugins/shop/sql/schema.sql"
  run check_exposed
  [[ $output == *"1 document root(s) scanned, 0 finding(s)"* ]]
  [ ! -s "$DALERTS" ]
}

@test "exposed: info and admin tools, wp-config copies and keys are found" {
  exposed_setup
  touch "$R/phpinfo.php" "$R/adminer-4.8.php" "$R/wp-config.php.bak" "$R/wp-config.php~" "$R/id_rsa" "$R/.htpasswd"
  touch "$R/wp-config.php" "$R/index.php"                       # the real ones: not findings
  code /phpinfo.php 200
  run check_exposed
  [[ $output == *"6 finding(s)"* ]]
  [[ $output == *"a.example/phpinfo.php – PUBLICLY REACHABLE"* ]]
}
