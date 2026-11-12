#!/usr/bin/env bats
# check_logins with AUTH_LOG pointing to an anonymized auth.log

load helper

setup() { load_script; AUTH_LOG="$FIX/auth.log"; PLESK_PANEL_LOG=/nonexistent; }

@test "first run: SSH logins listed and stored as known" {
  check_logins || true
  run report
  [[ $output == *"SSH   root           from 198.18.1.163     (publickey)"* ]]
  [[ $output == *"first run: all IPs stored as known"* ]]
  grep -q 198.18.1.163 "$STATE_DIR/known_login_ips"
}

@test "second run: a new IP raises an alert, a known one doesn't" {
  check_logins || true
  ALERTS=(); : >"$BODY"
  check_logins || true
  run alerts
  [[ $output != *198.18.1.163* ]]
  sed -i 's/198\.18\.1\.163/192.0.2.77/' "$STATE_DIR/known_login_ips"
  ALERTS=(); check_logins || true
  run alerts
  [[ $output == *198.18.1.163* ]]
}
