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

@test "deferred: attempts and the distinct mails behind them, kept for the summary" {
  mail_on dsn.log
  run report
  [[ $output == *"d903.example               0 / 2 (1 mail) / 0"* ]]
  [ "$(cut -f2,3 "$STATE_DIR/deferred_mails")" = "$(printf 'd903.example\t51B2460193')" ]
}

@test "greylisting is no rejection for spam or a blocklist" {
  printf '%s\n' \
   'Nov 14 10:07:00 host postfix/smtp[1]: AB12345678: to=<info@d20.example>, relay=mail.d20.example[198.18.0.40]:25, delay=1, delays=0/0/0.5/0.1, dsn=4.2.0, status=deferred (host mail.d20.example[198.18.0.40] said: 450 4.2.0 <info@d20.example>: Recipient address rejected: Greylisted, see http://postgrey.schweikert.ch/help/d20.example.html (in reply to RCPT TO command))' \
   'Nov 14 10:08:00 host postfix/smtp[1]: CD12345678: to=<x@d21.example>, relay=mx.d21.example[198.18.0.41]:25, delay=1, delays=0/0/0.5/0.1, dsn=5.7.1, status=bounced (host mx.d21.example[198.18.0.41] said: 554 5.7.1 Service unavailable; Client host [203.0.113.10] blocked using zen.spamhaus.org (in reply to RCPT TO command))' \
   >"$BATS_TEST_TMPDIR/grey.log"
  MAIL_LOG="$BATS_TEST_TMPDIR/grey.log"; check_mail || true
  run report
  [[ $output == *"Rejections mentioning blocklist/reputation/spam/rate limit: 1"* ]]
  [[ $output != *Greylisted* ]]
  [[ $output == *"zen.spamhaus.org"* ]]
}
