#!/usr/bin/env bats
# check_web on anonymized vhost logs (VHOST_LOGS/<domain>/logs/); the WordPress part is the
# plugin wordpress since 2.0 (wordpress.bats)

load helper

setup() { load_script; VHOST_LOGS="$FIX/web"; check_web || true; }

@test "requests per domain (login POSTs: plugin wordpress)" {
  run report
  [[ $output == *"requests | 5xx | domain | busiest IP"* ]]
  [[ $output =~ 435\ +0\ +d1\.example\ +198\.18\.0\.69\ \(136\) ]]
  [[ $output != *"WordPress login attacks"* ]]
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

@test "ModSecurity hits per domain with the top rules" {
  run report
  [[ $output == *"16     16  d16.example – 210492  ×8; 210730 COMODO WAF: URL file extension is restricted by policy"* ]]
}
