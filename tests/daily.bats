#!/usr/bin/env bats
# daily_checks: once a day from the cache – again after the package database changed

load helper

setup() {
  load_script
  PKG_DB="$BATS_TEST_TMPDIR/status"; echo pkgs >"$PKG_DB"; touch -d '2 hours ago' "$PKG_DB"
  CONF=/nonexistent
  BOOT_ID_FILE="$BATS_TEST_TMPDIR/boot_id"; echo boot-1 >"$BOOT_ID_FILE"
  RUNS="$BATS_TEST_TMPDIR/runs"; : >"$RUNS"
  run_daily() { echo run >>"$RUNS"; echo "Updates available: 1, security updates: 1"; }
}

@test "second run of the day: the cached daily checks" {
  daily_checks; : >"$BODY"; daily_checks
  [ "$(wc -l <"$RUNS")" -eq 1 ]
  grep -q 'Updates available: 1' "$BODY"
}

@test "after apt upgrade (package database changed): the daily checks run again" {
  daily_checks
  touch "$PKG_DB"
  daily_checks
  [ "$(wc -l <"$RUNS")" -eq 2 ]
}

@test "after a reboot (new boot ID): the daily checks run again" {
  daily_checks
  echo boot-2 >"$BOOT_ID_FILE"
  daily_checks
  [ "$(wc -l <"$RUNS")" -eq 2 ]
}
