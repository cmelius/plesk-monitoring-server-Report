#!/usr/bin/env bats
# check_panel on an anonymized Plesk panel.log

load helper

setup() { load_script; PLESK_ERROR_LOG="$FIX/panel/panel.log"; check_panel || true; }

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
