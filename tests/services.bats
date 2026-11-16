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

@test "rc-local.service gets a hint and stays critical" {
  FAILED_UNITS="rc-local.service"
  check_services || true
  run alerts
  [[ $output == "Service(s) failed: rc-local.service – rc-local.service: /etc/rc.local (deprecated) failed at boot"*"IGNORE_FAILED_UNITS" ]]
  [ "$(alert_severity "$output")" = critical ]
}

@test "IGNORE_FAILED_UNITS: still listed, no alert; names without .service and patterns" {
  FAILED_UNITS="rc-local.service backup-nightly.service postfix.service"
  IGNORE_FAILED_UNITS="rc-local backup-*"
  check_services || true
  run report
  [[ $output == *"Failed units: postfix.service"* ]]
  [[ $output == *"Failed units without an alert (IGNORE_FAILED_UNITS): rc-local.service backup-nightly.service"* ]]
  run alerts
  [ "$output" = "Service(s) failed: postfix.service" ]
}

@test "all failed units ignored: none, no alert" {
  FAILED_UNITS="rc-local.service"
  IGNORE_FAILED_UNITS="rc-local.service"
  check_services || true
  run report
  [[ $output == *"Failed units: none"* ]]
  [[ $output == *"(IGNORE_FAILED_UNITS): rc-local.service"* ]]
  run alerts
  [ -z "$output" ]
}
