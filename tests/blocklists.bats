#!/usr/bin/env bats
# IP blocklists: test entry 127.0.0.2 first – "clean" only if the list answers (getent stubbed, no network)

load helper

setup() {
  load_script
  PUBIP=1.2.3.4; MAIL_LOG="$FIX/mail/nouser.log"
  DNSBL_LISTS="answers.example listed.example refuses.example silent.example"; BLOCKLIST_RESOLVER=system
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
  [[ $output == *"DNS blocklists for 1.2.3.4 (all queried via system resolver): answers.example:clean listed.example:LISTED(127.0.0.3) refuses.example:query-refused silent.example:no-answer"* ]]
}

@test "only a listing raises an alert" {
  run alerts
  [[ $output == *"server IP 1.2.3.4 is listed on listed.example"* ]]
  [ "$(grep -c 'is listed on' <<<"$output")" -eq 1 ]
}

@test "a local resolver on 127.0.0.1 is used when it answers (dig stubbed)" {
  BLOCKLIST_RESOLVER=""; BL_VIA=""; : >"$BODY"
  getent() { echo "getent must not be used" >&2; return 1; }
  dig() {
    case "$*" in
      *"@127.0.0.1 . NS"*) echo ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1" ;;
      *"@127.0.0.1 2.0.0.127."*) echo 127.0.0.2 ;;
      *"@127.0.0.1 4.3.2.1.listed.example"*) echo 127.0.0.3 ;;
    esac
  }
  DNSBL_LISTS="answers.example listed.example"
  check_mail || true
  run report
  [[ $output == *"(all queried via 127.0.0.1): answers.example:clean listed.example:LISTED(127.0.0.3)"* ]]
}

@test "no resolver on 127.0.0.1: the system resolver" {
  BLOCKLIST_RESOLVER=""; BL_VIA=""; : >"$BODY"
  dig() { echo ";; communications error to 127.0.0.1#53: connection refused"; }
  DNSBL_LISTS="answers.example"
  check_mail || true
  run report
  [[ $output == *"(all queried via system resolver): answers.example:clean"* ]]
}
