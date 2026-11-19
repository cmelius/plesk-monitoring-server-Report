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

@test "the ban alert names the login that failed from there (outdated password)" {
  echo "198.18.0.30 info@d1.example $(date +%s)" >"$STATE_DIR/known_mail_ips"
  echo "198.18.0.30 office@d1.example 3 $(date +%s) 0
198.18.0.30 office@d1.example 2 $(date +%s) 0" >"$STATE_DIR/failed_from_known_ips"
  check_fail2ban || true
  run alerts
  [[ $output == *"bans 198.18.0.30"*"(mail logins of info@d1.example"*"); failed logins from there: office@d1.example ×5 – a device with an outdated password? Unban:"* ]]
  run report
  [[ $output == *"failed logins from there: office@d1.example ×5"* ]]
}

@test "the ban alert: a login that doesn't exist → remove the account from the device" {
  echo "198.18.0.30 info@d1.example $(date +%s)" >"$STATE_DIR/known_mail_ips"
  echo "198.18.0.30 iphone@d2.example 4 $(date +%s) 1" >"$STATE_DIR/failed_from_known_ips"
  check_fail2ban || true
  run alerts
  [[ $output == *"failed logins from there: iphone@d2.example ×4 (no such mailbox) – a device still set up for a mailbox that doesn't exist (any more)? Remove that account from the device. Unban:"* ]]
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

@test "jails active, none with bans or failures: they are named, no alert" {
  fail2ban-client() {
    if [[ -z ${2:-} ]]; then printf 'Status\n|- Number of jail:\t2\n`- Jail list:\tproftpd-iptables, ssh-iptables\n'
    else printf 'Status for the jail: %s\n|- Filter\n|  |- Currently failed:\t0\n`- Actions\n   |- Currently banned:\t0\n   |- Total banned:\t0\n   `- Banned IP list:\t\n' "$2"; fi
  }
  check_fail2ban || true
  run report
  [[ $output == *"2 jail(s) active, none with bans or failed logins right now: proftpd-iptables ssh-iptables"* ]]
  run alerts
  [ -z "$(printf '%s' "$output" | tr -d '\n')" ]
}

@test "fail2ban runs without a jail: warning" {
  fail2ban-client() { printf 'Status\n|- Number of jail:\t0\n`- Jail list:\t\n'; }
  check_fail2ban || true
  run report
  [[ $output == *"fail2ban runs, but no jail is active"* ]]
  run alerts
  [[ $output == *"fail2ban runs without any active jail – nothing is banned"* ]]
  [ "$(alert_severity "${ALERTS[0]}")" = warning ]
}
