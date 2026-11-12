#!/usr/bin/env bats
# the plugin panel (plugins/panel.sh) on an anonymized Plesk panel.log

load helper

setup() { load_script; PLESK_ERROR_LOG="$FIX/panel/panel.log"; run_plugin panel || true; }

@test "failed panel logins with login names and IPs" {
  run report
  [[ $output == *"Failed panel logins: 45"* ]]
  [[ $output == *"login names: admin ×33, root ×11, administrator ×1"* ]]
  [[ $output == *"top IPs: 198.18.1.166 ×19"* ]]
}

@test "failed certificate renewals with the reason" {
  run report
  [[ $output == *"d44.example: 2× – 198.18.0.12: Invalid response from https://d44.example/.well-known/acme-challenge/…"* ]]
  run alerts
  [[ $output == *"automatic renewal for d116.example failed"* ]]
  [[ $output == *"automatic renewal for d44.example failed"* ]]
}

# The check as it was inside the main script (tests/legacy/check_panel.bash) and the plugin must
# write the same report and the same alerts – with the log, without it, and with an ignored domain.
@test "parity: the plugin writes what check_panel wrote" {
  # shellcheck source=legacy/check_panel.bash
  source "$BATS_TEST_DIRNAME/legacy/check_panel.bash"
  both() {
    : >"$BODY"; ALERTS=(); legacy_check_panel; old=$(report; alerts)
    : >"$BODY"; ALERTS=(); run_plugin panel;   new=$(report; alerts)
    [[ -n $old && $old == "$new" ]]
  }
  both
  PLESK_ERROR_LOG=/nonexistent; both
  PLESK_ERROR_LOG=""; both
  PLESK_ERROR_LOG="$FIX/panel/panel.log"; WEB_IGNORE_DOMAINS="d44.example"; both
  [[ $new != *"renewal for d44.example"* && $new == *"renewal for d116.example"* ]]
  [ ! -s "$TMPD/notes" ]                       # the plugin's output was taken completely
}
