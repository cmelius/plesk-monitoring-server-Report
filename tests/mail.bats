#!/usr/bin/env bats
# check_mail on anonymized Postfix/Courier/Dovecot logs (MAIL_LOG points to a fixture)

load helper

setup() { load_script; }

# the script runs without errexit; "|| true" keeps it off inside the check
mail_on() { MAIL_LOG="$FIX/mail/$1"; check_mail || true; }

@test "an hour of real traffic: counts and full mailbox" {
  mail_on hour.log
  run report
  [[ $output == *"4837 new lines"* ]]
  [[ $output == *"Delivered: 75 | deferred: 0 | bounced: 0"* ]]
  [[ $output == *"Mailbox full: info@d12.example – 29 delivery attempt(s) rejected"* ]]
  [[ $output == *"Spam filter: blocklist lookups answered (66 mail(s) scanned)"* ]]
  run alerts
  [[ $output == *"mailbox info@d12.example is full – 29 delivery attempt(s)"* ]]
}

@test "full mailbox: Plesk milter and Dovecot LMTP count, remote servers don't" {
  mail_on full.log
  run report
  [[ $output == *"Mailbox full: info@d12.example – 2 delivery"* ]]
  [[ $output == *"Mailbox full: user900@d901.example – 1 delivery"* ]]
  [[ $(grep -c '^Mailbox full:' <<<"$output") -eq 2 ]]
}

@test "device with an outdated password is named before the ban" {
  mail_on tablets.log
  run alerts
  [[ $output == *"170 failed logins of user16@d113.example from 198.18.0.11"* ]]
  [[ $output == *"logged in successfully from there: info@d113.example"* ]]
}

@test "login names that don't exist are counted" {
  mail_on nouser.log
  run report
  [[ $output == *"Login names that don't exist: 8 (8 attempts)"* ]]
}

@test "refused blocklist lookups of the spam filter" {
  mail_on uribl.log
  run report
  [[ $output == *"blocklist lookups refused in 8 of 40 scanned mail(s) – URIBL_BLOCKED ×8"* ]]
  run alerts
  [[ $output == *"SpamAssassin's blocklist lookups are refused"* ]]
}

@test "delivery confirmations to other servers, local ones not counted" {
  mail_on dsn.log
  run report
  [[ $output == *"Delivery confirmations (DSN) sent to other servers: 1 (e.g. to mail.d903.example)"* ]]
  run alerts
  [[ $output == *"1 delivery confirmation(s) (DSN) sent to other servers"* ]]
}

@test "DSN alert can be switched off" {
  WARN_DSN=0
  mail_on dsn.log
  run alerts
  [[ $output != *"DSN"* ]]
}
