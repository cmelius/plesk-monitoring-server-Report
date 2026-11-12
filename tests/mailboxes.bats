#!/usr/bin/env bats
# check_mailboxes: fill level from maildirsize, limit from Plesk (mailbox, else subscription)

load helper

setup() { load_script; MAILNAMES_DIR="$FIX/mailboxes"; WARN_MAILBOX_PCT=95; }

@test "with Plesk: mailbox limit first, then the subscription default" {
  # address, mailbox limit (-1 = subscription default), subscription limit
  plesk() { printf '%s\t%s\t%s\n' info@d1.example -1 1677721600 office@d1.example -1 -1 \
                                   boss@d2.example 1073741824 -1 nomaildir@d1.example 1000000 -1; }
  run check_mailboxes
  [[ $output == *" 68 %  info@d1.example  (1.07 GB of 1.56 GB)"* ]]
  [[ $output == *" 98 %  boss@d2.example"* ]]
  [[ $output == *"2 mailbox(es) checked; 1 unlimited (no size limit set in Plesk; largest: office@d1.example "*", all together "*"), 1 without maildirsize"* ]]
  { check_mailboxes || true; } >/dev/null
  run cat "$DALERTS"
  [[ $output == *"mailbox boss@d2.example is 98 % full"* ]]
  [[ $output != *info@d1.example* ]]
}

@test "without Plesk: limit from the maildirsize header" {
  run check_mailboxes
  [[ $output == *" 53 %  info@d1.example"* ]]
  [[ $output == *" 98 %  boss@d2.example"* ]]
  [[ $output == *"2 mailbox(es) checked; 1 unlimited (no size limit set in maildirsize; largest: office@d1.example"* ]]
}

@test "warning level is configurable" {
  WARN_MAILBOX_PCT=50
  { check_mailboxes || true; } >/dev/null
  [ "$(grep -c 'Mail: mailbox' "$DALERTS")" -eq 2 ]
}

@test "mailboxes without a limit: size from du, warning above WARN_MAILBOX_UNLIMITED_GB" {
  # du reports 6 GB for office@d1.example (no limit), the fixture itself is tiny
  du() { [[ $2 == */d1.example/office/Maildir ]] && printf '6291456\t%s\n' "$2" || command du "$@"; }
  run check_mailboxes
  [[ $output == *"largest: office@d1.example 6.00 GB, all together 6.00 GB"* ]]
  { check_mailboxes || true; } >/dev/null
  run cat "$DALERTS"
  [[ $output == *"mailbox office@d1.example has no size limit and holds 6.00 GB (more than 5 GB)"* ]]
  : >"$DALERTS"; WARN_MAILBOX_UNLIMITED_GB=0
  { check_mailboxes || true; } >/dev/null
  run grep -c 'no size limit and holds' "$DALERTS"
  [ "$output" = 0 ]
}
