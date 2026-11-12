#!/usr/bin/env bats
# the plugin webmail (plugins/webmail.sh) on hand-written Roundcube logs (fixtures/webmail)

load helper

setup() {
  load_script
  ROUNDCUBE_LOG_DIR="$FIX/webmail/logs"
  WARN_MAILS_PER_SASL=5; WARN_MAILS_PER_SENDER=20; WARN_IPS_PER_MAILBOX=1; WARN_LOGIN_BRUTE_FAILS=5; WARN_AUTH_FAIL=20
}
# a GeoIP database for the tests: 198.18.5.x is abroad
foreign_ips() {
  GEO_OK=1; ALLOWED_COUNTRIES="DE"; GEO_TRUSTED_ORGS=""
  geo() { GEO_ORG=""; case $1 in 127.*) GEO_CC=""; GEO_LABEL="this server"; return 0 ;; 198.18.5.*) GEO_CC=US ;; *) GEO_CC=DE ;; esac; GEO_LABEL=$GEO_CC; }
}

@test "mails sent per mailbox with the client IPs" {
  run_plugin webmail
  run report
  [[ $output == *"Webmail (Roundcube) – mails sent (mails, recipients, IPs):"* ]]
  [[ $output == *"       8     24 rcpt   1 IPs  sales@d44.example"*"          198.18.5.77 ×8"* ]]
  [[ $output == *"       3      4 rcpt   2 IPs  office@d44.example"*"          198.18.0.12 ×2, 198.18.0.40 ×1"* ]]
  [[ $output == *"       1      1 rcpt   1 IPs  info@d116.example"*"          127.0.0.1 (this server) ×1"* ]]
  [[ $output != *"== "* ]]                      # no section of its own: it continues MAIL
}

@test "failed webmail logins: total, top IPs, mailboxes in lower case" {
  run_plugin webmail
  run report
  [[ $output == *"Failed webmail logins: 27 – top IPs:"*"      14  198.18.1.166"*"       6  198.18.5.77"*"       5  198.18.1.9"* ]]
  [[ $output == *"Most attacked mailboxes (failed webmail logins):"*"      14  admin@d44.example"*"       5  info@d116.example"* ]]
  run alerts
  [[ $output == *"Mail: 27 failed webmail logins (brute force?)"* ]]
}

@test "alerts: many mails, many recipients, several IPs, mails after failed logins" {
  run_plugin webmail
  run alerts
  [[ $output == *"Mail: webmail user sales@d44.example sent 8 mails"* ]]
  [[ $output == *"Mail: webmail user sales@d44.example sent to 24 recipients"* ]]
  [[ $output == *"Mail: webmail user office@d44.example used from 2 different IPs – password compromised?"* ]]
  [[ $output == *"Mail: webmail user sales@d44.example sent 8 mails from 198.18.5.77 after 6 failed logins from that IP – password guessed?"* ]]
  [[ $output != *"outside"* ]]                  # no GeoIP database: no country alerts
}

@test "mails sent from abroad raise an alert, naming only the foreign IPs" {
  foreign_ips
  run_plugin webmail
  run alerts
  [[ $output == *"Mail: webmail user sales@d44.example sent mails from outside DE: 198.18.5.77 (US) – password compromised?"* ]]
  [ "$(grep -c 'from outside' <<<"$output")" -eq 1 ]
  [[ $output == *"sent 8 mails from 198.18.5.77 (US) after 6 failed logins"* ]]
  run report
  [[ $output == *"198.18.0.12 (DE) ×2, 198.18.0.40 (DE) ×1"* ]]
}

@test "empty logs and a missing directory" {
  ROUNDCUBE_LOG_DIR="$FIX/webmail/quiet"; run_plugin webmail
  run report
  [[ $output == *"Failed webmail logins: 0 – top IPs:"* ]]
  [ "${#ALERTS[@]}" -eq 0 ]
  ROUNDCUBE_LOG_DIR=/nonexistent; : >"$BODY"; run_plugin webmail
  run report
  [[ $output == *"  (no Roundcube log directory found)"* ]]
  run cat "$TMPD/notes"
  [[ $output == *"webmail: no Roundcube log directory found (ROUNDCUBE_LOG_DIR) – webmail not checked"* ]]
}

# The check as it was inside the main script (tests/legacy/check_webmail.bash) and the plugin
# must write the same report and the same alerts – without and with a GeoIP database.
@test "parity: the plugin writes what check_webmail wrote" {
  # shellcheck source=legacy/check_webmail.bash
  source "$BATS_TEST_DIRNAME/legacy/check_webmail.bash"
  both() {
    : >"$BODY"; ALERTS=(); : >"$TMPD/notes"; legacy_check_webmail || true; old=$(report; alerts; cat "$TMPD/notes")
    : >"$BODY"; ALERTS=(); : >"$TMPD/notes"; run_plugin webmail;           new=$(report; alerts; cat "$TMPD/notes")
    [[ -n $old && $old == "$new" ]]
  }
  both
  WARN_MAILS_PER_SASL=100; WARN_IPS_PER_MAILBOX=5; both
  ROUNDCUBE_LOG_DIR="$FIX/webmail/quiet"; both
  ROUNDCUBE_LOG_DIR=/nonexistent; both
  ROUNDCUBE_LOG_DIR="$FIX/webmail/logs"; foreign_ips; both
  [[ $new == *"from outside DE"* ]]
}
