#!/usr/bin/env bats
# IP blocklists: test entry 127.0.0.2 first – "clean" only if the list answers (getent stubbed, no network)

load helper

setup() {
  load_script
  PUBIP=1.2.3.4; MAIL_LOG="$FIX/mail/nouser.log"
  DNSBL_LISTS="answers.example listed.example refuses.example silent.example"
  getent() {
    case $2 in
      2.0.0.127.silent.example) ;;                                  # doesn't answer this server
      *.refuses.example) echo "127.255.255.254 STREAM $2" ;;
      2.0.0.127.*) echo "127.0.0.2 STREAM $2" ;;                    # test entry answered
      4.3.2.1.listed.example) echo "127.0.0.3 STREAM $2" ;;
    esac
  }
  check_mail || true
}

@test "clean, listed, refused and silent lists are told apart" {
  run report
  [[ $output == *"DNS blocklists for 1.2.3.4: answers.example:clean listed.example:LISTED(127.0.0.3) refuses.example:query-refused silent.example:no-answer"* ]]
}

@test "only a listing raises an alert" {
  run alerts
  [[ $output == *"server IP 1.2.3.4 is listed on listed.example"* ]]
  [ "$(grep -c 'is listed on' <<<"$output")" -eq 1 ]
}
