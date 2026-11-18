#!/usr/bin/env bats
# check_services: failed systemd units, IGNORE_FAILED_UNITS, the hint for rc-local.service (stubbed systemctl)

load helper

setup() {
  load_script
  FAILED_UNITS=""
  systemctl() { local u; for u in $FAILED_UNITS; do printf '%s loaded failed failed Dummy\n' "$u"; done; }
  journalctl() { :; }
  IGNORE_FAILED_UNITS=""
}

@test "no failed unit: none, no alert" {
  check_services || true
  run report
  [[ $output == *"Failed units: none"* ]]
  [[ $output != *"without an alert"* ]]
  run alerts
  [ -z "$output" ]
}

@test "a failed unit raises an alert" {
  FAILED_UNITS="postfix.service"
  check_services || true
  run alerts
  [ "$output" = "Service(s) failed: postfix.service" ]
}

@test "a failed rc-local.service: a line, no alert (the daily check rclocal judges rc.local)" {
  FAILED_UNITS="rc-local.service postfix.service"
  check_services || true
  run report
  [[ $output == *"Failed units: postfix.service"* ]]
  [[ $output == *"rc-local.service failed at boot – see rc.local in the daily checks (no alert of its own)"* ]]
  [[ $output != *"systemctl status rc-local"* ]]   # explained once, in the daily check
  run alerts
  [ "$output" = "Service(s) failed: postfix.service" ]
}

@test "IGNORE_FAILED_UNITS: still listed, no alert; names without .service and patterns" {
  FAILED_UNITS="sync-old.service backup-nightly.service postfix.service"
  IGNORE_FAILED_UNITS="sync-old backup-*"
  check_services || true
  run report
  [[ $output == *"Failed units: postfix.service"* ]]
  [[ $output == *"Failed units without an alert (IGNORE_FAILED_UNITS): sync-old.service backup-nightly.service"* ]]
  run alerts
  [ "$output" = "Service(s) failed: postfix.service" ]
}

@test "all failed units ignored: none, no alert" {
  FAILED_UNITS="backup-nightly.service"
  IGNORE_FAILED_UNITS="backup-nightly.service"
  check_services || true
  run report
  [[ $output == *"Failed units: none"* ]]
  [[ $output == *"(IGNORE_FAILED_UNITS): backup-nightly.service"* ]]
  run alerts
  [ -z "$output" ]
}
