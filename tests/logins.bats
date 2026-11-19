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

@test "Plesk panel: a successful login (POST, then a panel page) and failed attempts" {
  AUTH_LOG=/nonexistent; PLESK_ERROR_LOG=/nonexistent; PLESK_PANEL_LOG="$FIX/panel/httpsd_access_log"
  check_logins || true
  run report
  [[ $output == *"1× Plesk -              from 198.18.0.18"* ]]
  [[ $output == *"Plesk panel: 5 failed login attempt(s)"* ]]
}

@test "Plesk panel: the user name from Plesk's action log (log_actions), matched by IP" {
  AUTH_LOG=/nonexistent; PLESK_ERROR_LOG=/nonexistent; PLESK_PANEL_LOG="$FIX/panel/httpsd_access_log"
  plesk() { [[ $* == *log_actions* ]] && printf '198.18.0.18\tadmin\n198.18.9.9\tother\n'; return 0; }
  check_logins || true
  run report
  [[ $output == *"1× Plesk admin          from 198.18.0.18"*"(panel)"* ]]
  [[ $output != *"user not logged"* ]]
  : >"$BODY"; ALERTS=()
  sed -i 's/198\.18\.0\.18/192.0.2.1/' "$STATE_DIR/known_login_ips"
  check_logins || true
  run alerts
  [[ $output == *"Login: Plesk panel login as admin from previously unknown IP 198.18.0.18"* ]]
}

@test "Plesk panel: IP not in the action log, or a strange user name – stays 'user not logged'" {
  AUTH_LOG=/nonexistent; PLESK_ERROR_LOG=/nonexistent; PLESK_PANEL_LOG="$FIX/panel/httpsd_access_log"
  plesk() { [[ $* == *log_actions* ]] && printf '198.18.0.18\tad min;rm\n'; return 0; }
  check_logins || true
  run report
  [[ $output == *"1× Plesk -              from 198.18.0.18"*"user not logged"* ]]
}
