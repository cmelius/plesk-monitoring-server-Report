#!/usr/bin/env bats
# check_fail2ban with the output of fail2ban-client of a real server (anonymized, stubbed)

load helper

setup() {
  load_script
  # "fail2ban-client status [JAIL]" from the saved output: the overview, or one jail's block
  fail2ban-client() {
    awk -v j="$2" 'j == "" && /^=== / { exit } j == "" { print; next }
                   $0 == "=== " j { p = 1; next } /^=== / { p = 0 } p' "$FIX/fail2ban/status.txt"
  }
}

@test "jails with bans or failures are listed, the others hidden" {
  check_fail2ban || true
  run report
  [[ $output =~ plesk-courierimap\ +banned:\ +50\ \(total\ 337\),\ currently\ failed:\ 35 ]]
  [[ $output =~ ssh\ +banned:\ +53 ]]
  [[ $output != *plesk-apache-badbot* ]]
  run alerts
  [ -z "$output" ]
}

@test "a banned IP that logged in to a mailbox before raises an alert" {
  echo "198.18.0.30 info@d1.example $(date +%s)" >"$STATE_DIR/known_mail_ips"
  check_fail2ban || true
  run alerts
  [[ $output == *"bans 198.18.0.30"*"mail logins of info@d1.example"*"Unban: fail2ban-client set "*" unbanip 198.18.0.30"* ]]
}

@test "fail2ban installed, but its server doesn't answer: critical alert 'not running'" {
  fail2ban-client() { echo "ERROR   Failed to access socket path: /var/run/fail2ban/fail2ban.sock. Is fail2ban running?"; return 255; }
  check_fail2ban || true
  run report
  [[ $output == *"fail2ban is installed, but its server doesn't answer"* ]]
  run alerts
  [[ $output == *"fail2ban is not running – "*"systemctl start fail2ban"* ]]
  [ "$(alert_severity "${ALERTS[0]}")" = critical ]
}

@test "fail2ban not installed: warning 'not installed', not 'not running'" {
  # a PATH without fail2ban-client, and no stub
  unset -f fail2ban-client
  mkdir -p "$BATS_TEST_TMPDIR/empty"; PATH="$BATS_TEST_TMPDIR/empty"
  check_fail2ban || true
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  run report
  [[ $output == *"fail2ban not installed"* ]]
  run alerts
  [[ $output == *"fail2ban is not installed – nothing bans password guessing"* ]]
  [[ $output != *"not running"* ]]
  [ "$(alert_severity "${ALERTS[0]}")" = warning ]
}
