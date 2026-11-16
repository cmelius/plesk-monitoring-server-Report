#!/usr/bin/env bats
# check_serverdns with a private server address (behind NAT), and persist_ports without public ports

load helper

setup() {
  load_script
  DIGQ() { :; }                         # no PTR anywhere
  postconf() { echo mail.example.com; }
  host_has_ip() { return 1; }
  PUBIP6=""
}

@test "private server address: reverse DNS and HELO not checked, no alert" {
  PUBIP=192.168.178.28
  run check_serverdns
  [[ $output == *"192.168.178.28: private address (behind NAT?) – reverse DNS not checked"* ]]
  [[ $output == *"HELO name: mail.example.com (not compared – the server's address is private)"* ]]
  [ -z "$(cat "$DALERTS")" ]
}

@test "public server address without PTR: alert as before" {
  PUBIP=203.0.113.10
  check_serverdns >/dev/null
  run cat "$DALERTS"
  [[ $output == *"server IP 203.0.113.10 has no reverse DNS"* ]]
}

@test "is_public_ipv4: private, loopback, link-local and CGNAT ranges are not public" {
  for ip in 10.1.2.3 192.168.0.1 172.16.5.5 172.31.0.1 127.0.0.1 169.254.1.1 100.64.0.1 100.127.255.1; do
    ! is_public_ipv4 "$ip"
  done
  is_public_ipv4 203.0.113.10
  is_public_ipv4 100.128.0.1
  is_public_ipv4 172.32.0.1
}

@test "listening ports: only loopback listeners give an empty list, not a failure" {
  printf '%s\n' 'State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process' \
    'LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=1,fd=1))' \
    'LISTEN 0 128 127.0.0.1:631 0.0.0.0:* users:(("cupsd",pid=2,fd=7))' \
    'LISTEN 0 128 [::1]:631 [::]:* users:(("cupsd",pid=2,fd=8))' \
    'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=3,fd=3))' >"$BATS_TEST_TMPDIR/ss"
  run persist_ports <"$BATS_TEST_TMPDIR/ss"
  [ "$output" = "$(printf '22\tsshd')" ]
  head -4 "$BATS_TEST_TMPDIR/ss" >"$BATS_TEST_TMPDIR/ss2"
  run persist_ports <"$BATS_TEST_TMPDIR/ss2"
  [ -z "$output" ]
}
