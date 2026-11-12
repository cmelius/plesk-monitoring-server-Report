#!/usr/bin/env bats
# check_web on anonymized vhost logs (VHOST_LOGS/<domain>/logs/)

load helper

setup() { load_script; VHOST_LOGS="$FIX/web"; check_web || true; }

@test "requests and login POSTs per domain" {
  run report
  [[ $output =~ 435\ +0\ +18\ +d1\.example\ +198\.18\.0\.69\ \(136\) ]]
}

@test "scanners calling WordPress files directly are not counted as PHP errors" {
  run report
  [[ $output == *"not counted – scanners calling WordPress files directly"*"d1.example ×2"* ]]
}

@test "sensitive-file probes are counted" {
  run report
  [[ $output == *"sensitive files 15/0"* ]]
}

@test "missing log directory is reported, not an error" {
  : >"$BODY"; VHOST_LOGS="$BATS_TEST_TMPDIR/none"
  run check_web
  [ "$status" -eq 0 ]
  [[ $(report) == *"skipped – log directory not found"* ]]
}
