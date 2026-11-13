#!/usr/bin/env bats
# check_webmail on anonymized Roundcube logs (sendmail, errors)

load helper

setup() { load_script; ROUNDCUBE_LOG_DIR="$FIX/roundcube"; check_webmail || true; }

@test "mails sent through webmail, per mailbox with the client IP" {
  run report
  [[ $output == *"rcpt   1 IPs  office@d21.example"* ]]
  [[ $output == *"198.18.0.23 ×1"* ]]
}

@test "failed webmail login with mailbox and IP (the IP ends the log sentence)" {
  run report
  [[ $output == *"Failed webmail logins: 1 – top IPs:"* ]]
  [[ $output == *"1  198.18.0.20"* ]]
  [[ $output == *"1  info@d38.example"* ]]
}
