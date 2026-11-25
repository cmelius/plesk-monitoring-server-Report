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

# an auth.log with one accepted SSH login per user
ssh_logins() {
  AUTH_LOG="$BATS_TEST_TMPDIR/auth.log"; : >"$AUTH_LOG"
  local u; for u in "$@"; do
    echo "Nov 25 10:00:00 host sshd[100]: Accepted publickey for $u from 198.18.1.163 port 50000 ssh2: ED25519 SHA256:x" >>"$AUTH_LOG"
  done
}
passwd_stub() {
  LOGIN_DEFS="$BATS_TEST_TMPDIR/login.defs"; echo "UID_MIN 1000" >"$LOGIN_DEFS"
  getent() {
    case "$1 $2" in
      "passwd www-data") echo "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin" ;;
      "passwd psaadm")   echo "psaadm:x:998:998::/opt/psa/admin:/bin/bash" ;;
      "passwd cust01")   echo "cust01:x:10001:1002::/var/www/vhosts/example.com:/usr/local/psa/bin/chrootsh" ;;
      "passwd cust02")   echo "cust02:x:10002:1002::/var/www/vhosts/example.org:/bin/false" ;;
      "passwd backup01") echo "backup01:x:10003:1002::/var/www/vhosts/example.net:/bin/bash" ;;
      "passwd admin1")   echo "admin1:x:1000:1000::/home/admin1:/bin/bash" ;;
      "group psacln")    echo "psacln:x:1002:" ;;
      *) return 2 ;;
    esac
  }
}

@test "SSH login of an account not meant for SSH: its own alert, also from a known IP" {
  passwd_stub
  ssh_logins root admin1 cust01 cust02 www-data psaadm backup01
  check_logins || true                       # first run: IP stored as known, no "unknown IP" alerts
  run alerts
  [[ $output == *"Login: SSH login as cust02 from 198.18.1.163 – not meant for SSH: its login shell /bin/false refuses logins"* ]]
  [[ $output == *"Login: SSH login as www-data from 198.18.1.163 – not meant for SSH: its login shell /usr/sbin/nologin refuses logins"* ]]
  [[ $output == *"Login: SSH login as psaadm from 198.18.1.163 – not meant for SSH: a system account (UID 998)"* ]]
  [[ $output == *"Login: SSH login as backup01 from 198.18.1.163 – not meant for SSH: a Plesk system user with a full shell (/bin/bash), not in ALLOWED_FULL_SHELL_USERS"* ]]
  [[ $output != *"as root "* && $output != *"as admin1 "* && $output != *"as cust01 "* ]]
  [ "$(alert_severity "Login: SSH login as cust02 from 198.18.1.163 – not meant for SSH: x")" = critical ]
  run report
  [[ $output == *"↳ cust02 is not meant to log in over SSH: its login shell /bin/false refuses logins"* ]]
}

@test "SSH login of a Plesk system user with a full shell in ALLOWED_FULL_SHELL_USERS: no alert" {
  passwd_stub; ALLOWED_FULL_SHELL_USERS="backup01"
  ssh_logins backup01
  check_logins || true
  run alerts
  [ -z "$output" ]
}
