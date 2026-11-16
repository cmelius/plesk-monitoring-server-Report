#!/usr/bin/env bats
# Configuration file and state folder: next to the script or in /etc, --init-config, the
# template, the mark of the state folder, first-report.txt. No root needed: the root and
# folder checks are stubbed.

load helper

setup() {
  load_script
  SELF="$BATS_TEST_DIRNAME/../plesk-server-report.sh"
  D="$BATS_TEST_TMPDIR/opt"; mkdir -p "$D"
  self_dir() { echo "$D"; }
  CONF_ETC="$BATS_TEST_TMPDIR/etc.conf"
  STATE_DIR_DEFAULT="$BATS_TEST_TMPDIR/varlib"
  STATE_DIR=$STATE_DIR_DEFAULT
  CONF_FOUND=0; CONF_LOCAL=0; CONF_CLI=""; STATE_NOTE=""
  is_root() { return 0; }
  root_only_dir() { return 0; }
  unset PSR_CONF_CREATED
}

@test "template: every setting commented out, valid bash, loading it changes nothing" {
  config_template "$SELF" >"$BATS_TEST_TMPDIR/t.conf"
  run grep -c '^#STATE_DIR=\|^#REMOTE=\|^#WARN_RC_LOCAL=\|^#IGNORE_FAILED_UNITS=' "$BATS_TEST_TMPDIR/t.conf"
  [ "$output" -eq 4 ]
  run grep -E '^[A-Z_][A-Z0-9_]*=' "$BATS_TEST_TMPDIR/t.conf"
  [ -z "$output" ]
  bash -n "$BATS_TEST_TMPDIR/t.conf"
  run bash -c "set -u; source '$BATS_TEST_TMPDIR/t.conf'; echo \${REMOTE:-unset}"
  [ "$output" = unset ]
}

@test "no configuration file: /etc, state in /var/lib" {
  find_conf
  [ "$CONF" = "$CONF_ETC" ]
  [ "$STATE_DIR" = "$STATE_DIR_DEFAULT" ]
}

@test "configuration next to the script: used, state in ./state next to it" {
  echo 'ALLOWED_COUNTRIES="DE"' >"$D/plesk-server-report.conf"
  echo 'REMOTE=""' >"$CONF_ETC"
  find_conf
  [ "$CONF" = "$D/plesk-server-report.conf" ]
  [ "$STATE_DIR" = "$D/state" ]
}

@test "next to the script, but an existing installation in /var/lib: the state stays there, with a note" {
  touch "$D/plesk-server-report.conf"; mkdir -p "$STATE_DIR_DEFAULT"
  find_conf
  [ "$STATE_DIR" = "$STATE_DIR_DEFAULT" ]
  [[ $STATE_NOTE == *"the state stays in $STATE_DIR_DEFAULT"* ]]
}

@test "--config FILE wins, the state stays in /var/lib" {
  touch "$D/plesk-server-report.conf"; echo x >"$BATS_TEST_TMPDIR/other.conf"
  CONF_CLI="$BATS_TEST_TMPDIR/other.conf"
  find_conf
  [ "$CONF" = "$BATS_TEST_TMPDIR/other.conf" ]
  [ "$STATE_DIR" = "$STATE_DIR_DEFAULT" ]
}

@test "--init-config: next to the script, chmod 600, never overwrites" {
  run init_config
  [ "$status" -eq 0 ]
  [ "$(stat -c %a "$D/plesk-server-report.conf")" = 600 ]
  grep -q '^#STATE_DIR=' "$D/plesk-server-report.conf"
  echo 'MINE=1' >>"$D/plesk-server-report.conf"
  CONF_FOUND=0
  run init_config
  [ "$status" -eq 1 ]
  [[ $output == *"exists already"* ]]
  grep -q '^MINE=1' "$D/plesk-server-report.conf"
}

@test "--init-config in a system folder: /etc, not next to the script; refuses when /etc has one" {
  self_dir() { echo /usr/local/sbin; }
  run init_config
  [ "$status" -eq 0 ]
  [ -s "$CONF_ETC" ]
  CONF_FOUND=0
  run init_config
  [ "$status" -eq 1 ]
}

@test "first run outside the system folders: the configuration is created next to the script" {
  maybe_create_conf
  grep -q '^#STATE_DIR=' "$D/plesk-server-report.conf"
  [ "$(stat -c %a "$D/plesk-server-report.conf")" = 600 ]
  [ "${PSR_CONF_CREATED:-}" = 1 ]
  find_conf
  [ "$STATE_DIR" = "$D/state" ]
}

@test "not created: in a system folder, with an existing installation, with /etc config, not as root, in a folder others can write" {
  self_dir() { echo /usr/local/sbin; }; maybe_create_conf; [ -z "${PSR_CONF_CREATED:-}" ]
  self_dir() { echo "$D"; }
  mkdir -p "$STATE_DIR_DEFAULT"; maybe_create_conf; [ ! -e "$D/plesk-server-report.conf" ]; rmdir "$STATE_DIR_DEFAULT"
  touch "$CONF_ETC"; maybe_create_conf; [ ! -e "$D/plesk-server-report.conf" ]; rm "$CONF_ETC"
  is_root() { return 1; }; maybe_create_conf; [ ! -e "$D/plesk-server-report.conf" ]
  is_root() { return 0; }; root_only_dir() { return 1; }; maybe_create_conf; [ ! -e "$D/plesk-server-report.conf" ]
}

@test "state folder: new, empty, marked or of an older version – accepted; with other files – refused" {
  STATE_DIR="$BATS_TEST_TMPDIR/new"; check_state_dir
  mkdir -p "$BATS_TEST_TMPDIR/empty"; STATE_DIR="$BATS_TEST_TMPDIR/empty"; check_state_dir
  mkdir -p "$BATS_TEST_TMPDIR/old"; touch "$BATS_TEST_TMPDIR/old/last_run"; STATE_DIR="$BATS_TEST_TMPDIR/old"; check_state_dir
  mkdir -p "$BATS_TEST_TMPDIR/marked"; touch "$BATS_TEST_TMPDIR/marked/$STATE_MARK" "$BATS_TEST_TMPDIR/marked/x"; STATE_DIR="$BATS_TEST_TMPDIR/marked"; check_state_dir
  mkdir -p "$BATS_TEST_TMPDIR/home"; touch "$BATS_TEST_TMPDIR/home/.bashrc"; STATE_DIR="$BATS_TEST_TMPDIR/home"
  run check_state_dir
  [ "$status" -eq 1 ]
  [[ $output == *"refusing to run – STATE_DIR=$BATS_TEST_TMPDIR/home contains other files"* ]]
}

@test "first-report.txt: written in the first run only, never replaced" {
  mkdir -p "$STATE_DIR"
  REPORT="$BATS_TEST_TMPDIR/r1.txt"; echo first >"$REPORT"
  FIRST_RUN=1; keep_first_report
  [ "$(cat "$STATE_DIR/first-report.txt")" = first ]
  echo second >"$REPORT"; keep_first_report
  [ "$(cat "$STATE_DIR/first-report.txt")" = first ]
  rm "$STATE_DIR/first-report.txt"; FIRST_RUN=0; keep_first_report
  [ ! -e "$STATE_DIR/first-report.txt" ]
}
