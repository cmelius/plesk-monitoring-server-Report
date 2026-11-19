#!/usr/bin/env bats
# check_forwarding: mail forwarding to other providers – spam filter action of the forwarding
# addresses, SpamAssassin size limit, DNS blocklist for incoming mail (stubbed plesk, postconf, pgrep)

load helper

setup() {
  load_script
  PSA_CONF="$BATS_TEST_TMPDIR/psa.conf"
  echo "SA_MAX_MAIL_SIZE 5242880" >"$PSA_CONF"
  FWD=""
  RESTR='permit_mynetworks, permit_sasl_authenticated, reject_rbl_client zen.spamhaus.org=127.0.0.[2..11], warn_if_reject reject_rbl_client zen.spamhaus.org=127.255.255.[1..255]
permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'
  plesk() {
    case $* in
      *"FROM domains UNION"*) printf '%s\n' example.com Example.org alias.example.net ;;
      *mail_redir*) printf '%s' "$FWD" ;;
    esac
  }
  postconf() { printf '%s\n' "$RESTR"; }
  pgrep() { return 1; }
}

fwd() { FWD+=$(printf '%s\t%s\t%s\t%s' "$@")$'\n'; }

@test "no forwarding to other providers" {
  fwd info@example.com true move office@example.org        # target on this server (case ignored)
  fwd a@example.com true move b@alias.example.net
  run check_forwarding
  [[ $output == *"no address forwards to another provider"* ]]
  [[ $output == *"Spam filter size limit: 5242880 bytes (5.0 MB)"* ]]
  [[ $output == *"DNS blocklist for incoming mail: zen.spamhaus.org"* ]]
  [[ $output != *Recommendation* ]]
}

@test "delete, move, mark, no action, no filter – one line per address, targets grouped" {
  fwd del@example.com true delete x@gmail.example
  fwd mv@example.com true move x@gmail.example
  fwd mv@example.com true move y@outlook.example
  fwd mv@example.com true move z@gmail.example
  fwd mk@example.com true text x@t-online.example
  fwd na@example.com true - x@gmail.example
  fwd off@example.com false delete x@gmail.example
  check_forwarding >"$BODY" || true
  run report
  [[ $output == *"5 address(es) forward to other providers: 1 delete spam, 3 forward it, 1 without spam filter"* ]]
  [[ $output == *"! no spam filter: off@example.com → gmail.example"* ]]
  [[ $output == *"- spam forwarded too: mv@example.com → gmail.example, outlook.example (spam moved to the Spam folder)"* ]]
  [[ $output == *"- spam forwarded too: mk@example.com → t-online.example (spam marked)"* ]]
  [[ $output == *"- spam forwarded too: na@example.com → gmail.example (spam no action set)"* ]]
  [[ $output != *"del@example.com"* ]]
  [[ $output == *"plesk bin spamassassin --update ADDRESS -action del"* ]]
  run cat "$DALERTS"
  [[ $output == *"Mail: 1 address(es) forward to other providers without spam filter: off@example.com → gmail.example – "* ]]
}

@test "only recommendations without an address lacking a spam filter: no alert" {
  fwd mv@example.com true move x@gmail.example
  check_forwarding >"$BODY" || true
  [ ! -s "$DALERTS" ]
}

@test "size limit at Plesk's default or not set: recommendation" {
  echo "SA_MAX_MAIL_SIZE 256000" >"$PSA_CONF"
  run check_forwarding
  [[ $output == *"Spam filter size limit: 256000 bytes (Plesk's default)"* ]]
  [[ $output == *"SA_MAX_MAIL_SIZE 5242880 (5 MB)"* ]]
  : >"$PSA_CONF"
  run check_forwarding
  [[ $output == *"Spam filter size limit: 256000 bytes (Plesk's default)"* ]]
}

@test "no DNS blocklist for incoming mail: recommendation" {
  RESTR='permit_mynetworks, permit_sasl_authenticated
permit_mynetworks, reject_unauth_destination'
  run check_forwarding
  [[ $output == *"DNS blocklist for incoming mail: none – Recommendation: e.g. zen.spamhaus.org"* ]]
}

@test "Rspamd (Plesk Email Security): forwarding addresses not read" {
  pgrep() { return 0; }
  fwd off@example.com false delete x@gmail.example
  check_forwarding >"$BODY" || true
  run report
  [[ $output == *"Rspamd runs"* ]]
  [ ! -s "$DALERTS" ]
}

@test "without Plesk: not checked" {
  unset -f plesk
  PATH=/usr/bin:/bin
  run check_forwarding
  [[ $output == *"not a Plesk server – not checked"* ]]
}

@test "FORWARD_CHECK=0 switches the check off" {
  FORWARD_CHECK=0
  ! check_enabled forwarding
}
