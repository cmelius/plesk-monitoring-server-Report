#!/usr/bin/env bats
# persist_keys reads the keys files sshd uses (AuthorizedKeysFile), not only ~/.ssh/authorized_keys –
# a key kept in /etc/ssh/authorized_keys/%u is watched as well

load helper

setup() {
  load_script
  H="$BATS_TEST_TMPDIR/home"; K="$BATS_TEST_TMPDIR/etc-keys"
  mkdir -p "$H/web1/.ssh" "$H/deputy/.ssh" "$K"
  echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB web1@pc" >"$H/web1/.ssh/authorized_keys"
  echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC deputy@laptop" >"$K/deputy"
  getent() { [[ $1 == passwd ]] && printf '%s\n' "web1:x:10000:1003::$H/web1:/opt/psa/bin/chrootsh" "deputy:x:10020:1003::$H/deputy:/bin/bash" "nobody:x:65534:65534::$H/none:/usr/sbin/nologin"; }
  MATCH=1
  sshd_has_match() { (( MATCH )); }
  sshd() {
    local u=${3#user=}; u=${u%%,*}
    if [[ $u == deputy ]]; then echo "authorizedkeysfile $K/%u"; else echo "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2"; fi
  }
}

@test "the key in the file sshd reads for the account is found, besides those in ~/.ssh" {
  run persist_keys
  [[ $output == *$'deputy\t'*$'\tdeputy@laptop'* ]]
  [[ $output == *$'web1\t'*$'\tweb1@pc'* ]]
}

@test "no Match block: the global setting for every account" {
  MATCH=0
  sshd() { echo "authorizedkeysfile $K/%u .ssh/authorized_keys"; }
  run persist_keys
  [[ $output == *"deputy@laptop"* ]]
  [[ $output == *"web1@pc"* ]]
}

@test "without sshd: ~/.ssh as before" {
  sshd_find() { return 1; }
  run persist_keys
  [[ $output == *"web1@pc"* ]]
  [[ $output != *"deputy@laptop"* ]]
}
