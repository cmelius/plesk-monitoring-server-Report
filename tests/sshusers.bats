#!/usr/bin/env bats
# check_sshusers: SSH access of the Plesk system users (group psacln) – full shell instead of chrooted,
# keys file the account can change itself. sshd -T answers from the settings of a real server
# (names invented): customers SFTP only via Match Group psacln, one deputy admin with a full shell
# and its keys in /etc/ssh/authorized_keys/%u

load helper

setup() {
  load_script
  ME=$(id -u); MYG=$(id -g)
  V="$BATS_TEST_TMPDIR/vhosts"; mkdir -p "$V"/a.example "$V"/b.example "$V"/c.example "$V"/d.example
  ETC="$BATS_TEST_TMPDIR/etc-ssh-keys"; mkdir -p "$ETC"; chmod 755 "$ETC"
  # the deputy's keys outside the web space – not changeable by the deputy (only by root, here: mode 444 in a 555 folder)
  echo "ssh-ed25519 AAAA deputy@laptop" >"$ETC/deputy"; chmod 444 "$ETC/deputy"; chmod 555 "$ETC"
  DUID=10020
  PASSWD="web1:x:10000:1003::$V/a.example:/opt/psa/bin/chrootsh
web2:x:10005:1003::$V/b.example:/usr/local/psa/bin/chrootsh
deputy:x:$DUID:1003::$V/c.example:/bin/bash
web3:x:10007:1003::$V/d.example:/bin/false
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33::/var/www:/usr/sbin/nologin"
  GROUP="psacln:x:1003:"
  getent() {
    case $1 in
      passwd) echo "$PASSWD" ;;
      group)  [[ $2 == psacln ]] && echo "$GROUP" ;;
    esac
  }
  id() { [[ $1 == -nG ]] && echo "psacln"; }
  SFTP_FOR="web1 web2"; KEYS_DEPUTY="$ETC/%u"; FWD=no; EXTRA=""
  sshd() {   # sshd -T -C user=NAME,host=…,addr=… – the lines check_sshusers reads
    local u=${3#user=}; u=${u%%,*}
    if [[ " $SFTP_FOR " == *" $u "* ]]; then
      echo "allowtcpforwarding $FWD"; echo "forcecommand /usr/lib/openssh/sftp-server"
      echo "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2"
    elif [[ $u == deputy ]]; then
      echo "allowtcpforwarding yes"; echo "forcecommand none"; echo "authorizedkeysfile $KEYS_DEPUTY"
    else
      echo "allowtcpforwarding yes"; echo "forcecommand none"; echo "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2"
    fi
    [[ -n $EXTRA ]] && echo "$EXTRA"
    return 0
  }
}
teardown() { chmod -R u+w "$BATS_TEST_TMPDIR" 2>/dev/null || true; }

@test "the real server: customers chrooted and SFTP only, the deputy's full shell allowed, keys outside the web space" {
  ALLOWED_FULL_SHELL_USERS="deputy"
  check_sshusers >"$BODY"
  run report
  [[ $output == *"SSH access of Plesk system users (group psacln, 4 accounts):"* ]]
  [[ $output == *"locked in their web space (chrooted): 2 | full shell: 1 | no SSH (Forbidden, /bin/false, nologin): 1"* ]]
  [[ $output == *"of the 3 with a shell: SFTP only (ForceCommand): 2"* ]]
  [[ $output == *"full shell: deputy (/bin/bash) – allowed (ALLOWED_FULL_SHELL_USERS)"* ]]
  [[ $output == *"keys of deputy: $ETC/deputy – not changeable by deputy"* ]]
  run alerts
  [[ $output != *"SSH:"* ]]
}

@test "chrootsh on Debian and RHEL paths both count as chrooted" {
  ALLOWED_FULL_SHELL_USERS="deputy"
  run check_sshusers
  [[ $output == *"chrooted): 2 |"* ]]
}

@test "full shell not allowed: warning with the Plesk setting" {
  check_sshusers >"$BODY"
  run report
  [[ $output == *"full shell: deputy (/bin/bash) – not locked in its web space"* ]]
  [[ $output == *"SSH access: /bin/bash (chrooted) or Forbidden"* ]]
  [[ $output == *'ALLOWED_FULL_SHELL_USERS="deputy"'* ]]
  run alerts
  [[ $output == *"SSH: Plesk system user deputy has a full shell (/bin/bash), not locked in its web space"* ]]
}

@test "full shell with the keys in its own web space: warning, even when the full shell is allowed" {
  PASSWD=${PASSWD//:10020:/:$ME:}
  ALLOWED_FULL_SHELL_USERS="deputy"
  KEYS_DEPUTY=".ssh/authorized_keys"
  mkdir -p "$V/c.example/.ssh"; echo "ssh-ed25519 AAAA x" >"$V/c.example/.ssh/authorized_keys"
  check_sshusers >"$BODY"
  run report
  [[ $output == *"keys of deputy: $V/c.example/.ssh/authorized_keys – $V/c.example/.ssh/authorized_keys can be changed by deputy itself"* ]]
  [[ $output == *"AuthorizedKeysFile /etc/ssh/authorized_keys/%u"* ]]
  run alerts
  [[ $output == *"SSH: the keys file of deputy ($V/c.example/.ssh/authorized_keys) can be changed by deputy itself"* ]]
  [[ $output != *"has a full shell"* ]]
}

@test "no keys file yet, but the account owns its home: it can create one" {
  PASSWD=${PASSWD//:10020:/:$ME:}
  ALLOWED_FULL_SHELL_USERS="deputy"
  KEYS_DEPUTY=".ssh/authorized_keys"
  check_sshusers >"$BODY"
  run report
  [[ $output == *"keys of deputy: $V/c.example/.ssh/authorized_keys – $V/c.example can be changed by deputy itself"* ]]
}

@test "full shell refused by sshd (DenyUsers): no warning" {
  EXTRA="denyusers deputy"
  check_sshusers >"$BODY"
  run report
  [[ $output == *"full shell: deputy (/bin/bash) – sshd refuses it (AllowUsers/DenyUsers…), no SSH login"* ]]
  [[ $output == *"refused by sshd (AllowUsers/DenyUsers…): 1"* ]]
  run alerts
  [[ $output != *"SSH:"* ]]
}

@test "AllowUsers without the account, with a pattern for it" {
  EXTRA="allowusers admin root"
  run ssh_denied deputy
  [ "$status" -eq 0 ]
  EXTRA="allowusers admin dep*@192.0.2.*"
  rm -f "$TMP".sshd.*
  run ssh_denied deputy
  [ "$status" -eq 1 ]
}

@test "sshd gives no answer: shells still rated, sshd settings not" {
  sshd() { return 1; }
  check_sshusers >"$BODY"
  run report
  [[ $output == *"sshd -T gave no answer"* ]]
  [[ $output == *"full shell: deputy (/bin/bash) – not locked in its web space"* ]]
}

@test "no group psacln: not a Plesk server" {
  GROUP=""
  run check_sshusers
  [[ $output == *"no group psacln – not a Plesk server, not checked"* ]]
}

@test "path_writable: owner with write permission, group, everyone, sticky folder" {
  d="$BATS_TEST_TMPDIR/pw"; mkdir -p "$d/x"; echo k >"$d/x/f"
  chmod 755 "$d" "$d/x"; chmod 644 "$d/x/f"
  [ "$(path_writable "$ME" 99999 "$d/x/f")" = "$d/x/f" ]
  [ "$(path_writable 99998 99999 "$d/x/f")" = "" ] || [[ $(path_writable 99998 99999 "$d/x/f") != "$d"* ]]
  chmod 664 "$d/x/f"
  [ "$(path_writable 99998 "$MYG" "$d/x/f")" = "$d/x/f" ]
  chmod 644 "$d/x/f"; chmod 1777 "$d/x"
  [[ $(path_writable 99998 99999 "$d/x/f") != "$d/x" ]]
}

@test "ssh_keyfiles: %h %u %U %%, relative paths in the home folder, none" {
  run ssh_keyfiles web1 /home/w 10000 ".ssh/authorized_keys /etc/ssh/keys/%u /k/%U/%h/x /p/%%u none"
  [ "${lines[0]}" = /home/w/.ssh/authorized_keys ]
  [ "${lines[1]}" = /etc/ssh/keys/web1 ]
  [ "${lines[2]}" = /k/10000//home/w/x ]
  [ "${lines[3]}" = /p/%u ]
  [ "${#lines[@]}" -eq 4 ]
}

@test "SSHUSERS_CHECK=0 switches it off" {
  SSHUSERS_CHECK=0
  ! check_enabled sshusers
}
