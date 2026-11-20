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

@test "failed logins from a known IP are kept for the fail2ban ban alert" {
  mail_on tablets.log
  grep -q '^198.18.0.11 user16@d113.example 170 [0-9]* [01]$' "$STATE_DIR/failed_from_known_ips"
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

@test "rejections: who rejected and how to get the IP removed" {
  PUBIP=203.0.113.10
  mail_on rejections.log
  run report
  [[ $output == *"Rejections mentioning blocklist/reputation/spam/rate limit: 12"* ]]
  [[ $output == *"What to do, by who rejected (the IP is 203.0.113.10):"* ]]
  [[ $output == *"Trend Micro ERS (1×): look the IP up at https://servicecentral.trendmicro.com/en-us/ers/ip-lookup/?ip=203.0.113.10 "*"Dial-up User List"* ]]
  [[ $output == *"Spamhaus (1×): look the IP up at https://check.spamhaus.org/results?query=203.0.113.10 "* ]]
  [[ $output == *"Outlook.com/Hotmail (1×): request removal at https://sender.office.com"* ]]
  [[ $output == *"Microsoft 365 (1×): request removal at https://sender.office.com"* ]]
  [[ $output == *"GMX/WEB.DE/IONOS (1×)"* ]]
  [[ $output == *"T-Online (1×): write to the address named in the rejection"* ]]
  [[ $output == *"Cloudmark (Proofpoint) (1×): request a reset at https://csi.cloudmark.com/en/reset?ip=203.0.113.10 "* ]]
  [[ $output == *"Barracuda (1×)"*"removal-request"* ]]
  [[ $output == *"Gmail (1×): no removal form"* ]]
  [[ $output == *"Apple iCloud (1×)"* ]]
  [[ $output == *"SpamCop (1×): SpamCop takes no removal requests"* ]]
  # a rejection without a known name counts, but gets no hint line
  [ "$(grep -c '^    .*(1×): ' <<<"$output")" -eq 11 ]
  run alerts
  [[ $output == *"Mail: 12 rejections by remote servers"*"(rejected by: "*"Trend Micro ERS"*"what to do: see the report)"* ]]
}

@test "rejections without a known sender: the alert text stays as before" {
  printf '%s\n' 'Nov 17 10:01:00 host postfix/smtp[1]: AA00000001: to=<x@d37.example>, relay=mx.d37.example[198.18.1.1]:25, delay=1, delays=0/0/0.5/0.1, dsn=5.7.1, status=bounced (host mx.d37.example[198.18.1.1] said: 550 5.7.1 blocked by local policy (in reply to RCPT TO command))' >"$BATS_TEST_TMPDIR/r.log"
  WARN_BLOCKLIST=1
  MAIL_LOG="$BATS_TEST_TMPDIR/r.log"; check_mail || true
  run report
  [[ $output != *"What to do"* ]]
  run alerts
  [[ $output == *"– check the server IP and the examples" ]]
}

@test "rejection hints without a known or with a private server address: links without the IP" {
  PUBIP=10.0.0.5
  run rej_hint trendmicro
  [[ $output == *"/ers/ip-lookup/ – a listing"* ]]
  PUBIP=""
  run rej_hint spamhaus
  [[ $output == "look the IP up at https://check.spamhaus.org/ – it names"* ]]
  run rej_hint proofpoint
  [[ $output == *"https://www.proofpoint.com/us/ipcheck (IP,"* ]]
}

@test "rejection of a forwarded mail (SRS sender): counted apart, no alert" {
  printf '%s\n' \
   'Nov 19 15:28:30 host postfix/qmgr[1]: FW00000001: from=<SRS0=IPn8=JI=d40.example=chj+bncX@d41.example>, size=9000, nrcpt=1 (queue active)' \
   'Nov 19 15:28:39 host postfix/smtp[1]: FW00000001: to=<user@gmail.com>, relay=alt1.gmail-smtp-in.l.google.com[192.0.2.27]:25, delay=9, delays=0/0/0.5/0.1, dsn=4.7.28, status=deferred (host alt1.gmail-smtp-in.l.google.com[192.0.2.27] said: 421-4.7.28 Gmail has detected an unusual rate of mail originating from your DKIM 421-4.7.28 domain [d40.example 36]. (in reply to end of DATA command))' \
   'Nov 19 15:30:00 host postfix/qmgr[1]: CU00000001: from=<info@d41.example>, size=900, nrcpt=1 (queue active)' \
   'Nov 19 15:30:05 host postfix/smtp[1]: CU00000001: to=<x@d42.example>, relay=mx.d42.example[198.18.1.1]:25, delay=1, delays=0/0/0.5/0.1, dsn=5.7.1, status=bounced (host mx.d42.example[198.18.1.1] said: 554 5.7.1 Client host [203.0.113.10] blocked using zen.spamhaus.org (in reply to RCPT TO command))' \
   >"$BATS_TEST_TMPDIR/fw.log"
  WARN_BLOCKLIST=1
  MAIL_LOG="$BATS_TEST_TMPDIR/fw.log"; check_mail || true
  run report
  [[ $output == *"Rejections mentioning blocklist/reputation/spam/rate limit: 1"* ]]
  [[ $output == *"Rejections of forwarded mail: 1 (forwarding here, sender rewritten with SRS – not sent by a customer"* ]]
  [[ $output == *"  example (forwarded): Nov 19 15:28:39 gmail.com: host alt1.gmail-smtp-in"*"unusual rate"* ]]
  [[ $output != *"Gmail (1×)"* ]]
  run alerts
  [[ $output == *"Mail: 1 rejections by remote servers"*"Spamhaus"* ]]
  [[ $output != *Gmail* ]]
}

@test "only forwarded mail rejected: no rejection alert" {
  printf '%s\n' \
   'Nov 19 15:28:30 host postfix/qmgr[1]: FW00000002: from=<SRS0=ab12=JI=d40.example=x@d41.example>, size=9000, nrcpt=1 (queue active)' \
   'Nov 19 15:28:39 host postfix/smtp[1]: FW00000002: to=<user@gmail.com>, relay=alt1.gmail-smtp-in.l.google.com[192.0.2.27]:25, delay=9, delays=0/0/0.5/0.1, dsn=4.7.28, status=deferred (host alt1.gmail-smtp-in.l.google.com[192.0.2.27] said: 421-4.7.28 Gmail has detected this message exceeded its quota for sending messages with the same Message-ID. (in reply to end of DATA command))' \
   >"$BATS_TEST_TMPDIR/fw2.log"
  WARN_BLOCKLIST=1
  MAIL_LOG="$BATS_TEST_TMPDIR/fw2.log"; check_mail || true
  run report
  [[ $output == *"Rejections mentioning blocklist/reputation/spam/rate limit: 0"* ]]
  [[ $output == *"Rejections of forwarded mail: 1"* ]]
  run alerts
  [[ $output != *"rejections by remote servers"* ]]
}
