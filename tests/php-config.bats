#!/usr/bin/env bats
# the plugin php-config (plugins/php-config.sh): a daily plugin with a context file (domains)
# and a state (the time of the last complete scan)

load helper

setup() {
  load_script
  W="$BATS_TEST_TMPDIR/www"; mkdir -p "$W/d1" "$W/d2/sub"
  cp -r "$FIX/htaccess/prepend" "$FIX/htaccess/normal" "$W/d1/"
  cp -r "$FIX/htaccess/campaign" "$W/d2/sub/"
  # a backdoor one-liner, put together only here: as a line in this file, virus scanners take the
  # repository (and every download of it) for the backdoor itself
  printf '<?php %s(%s($%s["x"])); ?>\n' "ev""al" "base64_""decode" "_PO""ST" >"$W/d2/sub/x.php"
  # git keeps no file times: everything was changed two days ago (the inode change time is
  # now, so a test that needs the files to be older than a scan waits a second: wait_)
  find "$W" -exec touch -d '-2 days' {} +
  docroots() { printf 'd1.example\t%s\nd2.example\t%s\ngone.example\t%s\n' "$W/d1" "$W/d2" "$W/gone"; }
}
daily() { : >"$DALERTS"; run_plugin php-config daily; }
state() { cat "$STATE_DIR/plugins/php-config/state"; }
wait_() { sleep 1.1; }

@test "first run: all files, whatever their date; the state is stored" {
  run daily
  [[ $output == *"PHP settings in .htaccess, .user.ini and php.ini"* ]]
  [[ $output == *"  $W/d1/prepend/"*"auto_prepend_file"* ]]
  [[ $output == *"  $W/d2/sub/campaign/"* ]]
  [[ $output == *"  2 document root(s) scanned, 2 suspicious file(s)"* ]]
  [ "$(grep -c 'suspicious PHP setting' "$DALERTS")" -eq 2 ]
  [[ $(state) =~ ^last_scan\ [0-9]{10}\.[0-9]{9}$ ]]
}

@test "later runs: only files changed since the last scan" {
  wait_; daily >/dev/null
  run daily
  [[ $output == *"  2 document root(s) scanned, 0 suspicious file(s)"* ]]
  [ ! -s "$DALERTS" ]
  wait_; touch "$W/d2/sub/campaign/.htaccess"   # changed after the last scan
  run daily
  [[ $output == *"  $W/d2/sub/campaign/"* && $output != *"/prepend/"* ]]
  [[ $output == *"2 document root(s) scanned, 1 suspicious file(s)"* ]]
}

@test "the state of version 1.x is taken over; --only and a failed plugin store none" {
  wait_; touch "$STATE_DIR/webshell_scan"; : >"$STATE_DIR/webshell_conf_full"
  run daily
  [[ $output == *"0 suspicious file(s)"* ]]     # the files are older than the last 1.x scan
  write_state_readme
  [ ! -e "$STATE_DIR/webshell_conf_full" ]      # replaced by the plugin's state
  rm -r "$STATE_DIR/plugins"; ONLY_MODE=1
  daily >/dev/null
  [ ! -e "$STATE_DIR/plugins/php-config/state" ]
  ONLY_MODE=0                                   # a scan cut off by the time limit: the old state stays
  echo "last_scan 1" >"$BATS_TEST_TMPDIR/old"
  mkdir -p "$STATE_DIR/plugins/php-config"; cp "$BATS_TEST_TMPDIR/old" "$STATE_DIR/plugins/php-config/state"
  mkdir "$BATS_TEST_TMPDIR/bin"; printf '#!/bin/sh\nsleep 20\n' >"$BATS_TEST_TMPDIR/bin/find"; chmod +x "$BATS_TEST_TMPDIR/bin/find"
  PATH="$BATS_TEST_TMPDIR/bin:$PATH" FIND_TIMEOUT=1 daily >/dev/null
  cmp "$BATS_TEST_TMPDIR/old" "$STATE_DIR/plugins/php-config/state"
  grep -q 'check php-config (plugin) timed out after 3s' "$TMPD/timeouts"
}

@test "WEBSHELL_IGNORE, WEBSHELL_CHECK and PLUGINS_OFF" {
  WEBSHELL_IGNORE='/d1/'
  run daily
  [[ $output == *"1 suspicious file(s)"* && $output != *"/prepend/"* ]]
  WEBSHELL_CHECK=0
  ! check_enabled php-config
  WEBSHELL_CHECK=1; PLUGINS_OFF="php-config"
  ! check_enabled php-config
  check_enabled webshell
}

@test "run_daily runs it after webshell; webshell scans PHP files only" {
  run run_daily webshell php-config
  [[ $output == *"Suspicious code in recently changed PHP files (typical"*"$W/d2/sub/x.php"*"2 document root(s) scanned, 1 suspicious file(s)"*"PHP settings in .htaccess"*"2 document root(s) scanned, 2 suspicious file(s)"* ]]
}

# check_webshell as it was (tests/legacy/check_webshell.bash) against check_webshell and the
# plugin now: the same alerts and the same lines, in two sections instead of one.
@test "parity: webshell and php-config find what check_webshell found" {
  # shellcheck source=legacy/check_webshell.bash
  source "$BATS_TEST_DIRNAME/legacy/check_webshell.bash"
  A="$BATS_TEST_TMPDIR/a"; B="$BATS_TEST_TMPDIR/b"; mkdir -p "$A" "$B"
  both() {
    STATE_DIR=$A; : >"$DALERTS"; old=$(legacy_check_webshell || true); oa=$(sort "$DALERTS")
    STATE_DIR=$B; : >"$DALERTS"; new=$(check_webshell; run_plugin php-config daily); na=$(sort "$DALERTS")
    [[ -n $oa && $oa == "$na" ]]
    [ "$(grep '^  /' <<<"$old" | sort)" = "$(grep '^  /' <<<"$new" | sort)" ]
  }
  WEBSHELL_FIRST_DAYS=7; both
  touch "$W/d1/prepend/.htaccess" "$W/d2/sub/x.php"; sleep 1
  both
}
