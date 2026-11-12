#!/usr/bin/env bats
# Log lines are written by attackers (login names, mail addresses, URLs, user agents).
# Whatever they contain must stay text: no command runs, no terminal control sequence
# reaches the report, no field shifts into a number the shell computes with.

load helper

setup() {
  load_script
  cd "$BATS_TEST_TMPDIR"
  E=$'\e'; TAB=$'\t'
  # payloads: command substitution, backticks, bash arithmetic with array subscript
  P1='$(touch pwned1)'; P2='`touch pwned2`'; P3='x[$(touch pwned3)]'
  {
    for i in 1 2 3 4 5; do
      echo "Nov 12 10:00:0$i host courier-pop3s[1]: LOGIN FAILED, user=$P1$TAB$P3@d1.example, ip=[::ffff:198.18.0.5]"
      echo "Nov 12 10:00:0$i host courier-imapd[1]: LOGIN, user=$P3@d1.example, ip=[::ffff:198.18.0.5], port=[1]"
      echo "Nov 12 10:00:0$i host postfix/cleanup[1]: A$i: milter-reject: END-OF-MESSAGE from unknown[198.18.0.6]: 4.2.2 Mailbox full; from=<$P2@d2.example> to=<$P3$TAB$P1@d1.example> proto=ESMTP helo=<x>"
      echo "Nov 12 10:00:0$i host postfix/smtpd[1]: B$i: client=unknown[198.18.0.7], sasl_method=LOGIN, sasl_username=$P3$TAB${E}]0;owned$E\\"
      echo "Nov 12 10:00:0$i host authpsa[1]: No such user '$P1$E[2J$P3' in mail authorization database"
    done
  } >mail.log
  {
    echo "Nov 12 10:00:01 host sshd[1]: Invalid user $P1$TAB$P3 from 198.18.0.8 port 1"
    echo "Nov 12 10:00:02 host sshd[1]: Accepted password for $P3$E[31m from 198.18.0.9 port 1 ssh2"
  } >auth.log
  mkdir -p web/d1.example/logs
  for i in 1 2 3; do
    echo "198.18.0.10 - - [12/Nov/2026:10:00:0$i +0000] \"POST /wp-login.php?$P1 HTTP/1.1\" 200 1 \"-\" \"$P3$E[2J$TAB$P2\""
  done >web/d1.example/logs/access_ssl_log
  echo "[Thu Nov 12 10:00:00 2026] [php:error] PHP Fatal error: $P1$E[2J$P3" >web/d1.example/logs/error_log
  mkdir rc; P4='x[$(id>pwned4)]'
  for i in 1 2 3 4 5 6; do
    echo "[12-Nov-2026 10:00:0$i +0100]: <s> User $P4@d1.example [198.18.0.12]; Message <$P2> for $P3@d2.example,$TAB$P1; 250: ok$E[2J"
    echo "[12-Nov-2026 10:00:0$i +0100]: <s> IMAP Error: Login failed for $P4@d1.example$E[31m against localhost from 198.18.0.12. $P2 :: {ips}"
  done >rc/sendmail.tmp
  grep ' User ' rc/sendmail.tmp >rc/sendmail; grep 'Login failed' rc/sendmail.tmp >rc/errors
  echo "[2026-11-12 10:00:00.000] 1:1 ERR [panel] Failed login attempt with username '$P3$E[2J$TAB$P1' from 198.18.0.11" >panel.log
}

@test "hostile log lines run nothing and leave no control characters in the report" {
  MAIL_LOG=$PWD/mail.log; AUTH_LOG=$PWD/auth.log; PLESK_PANEL_LOG=/nonexistent
  VHOST_LOGS=$PWD/web; PLESK_ERROR_LOG=$PWD/panel.log; ROUNDCUBE_LOG_DIR=$PWD/rc; WARN_LOGIN_BRUTE_FAILS=1
  REPORT=$PWD/report.txt; HOST=host; NOW=now; GEO_NOTE=""
  { check_mail || true; check_logins || true; check_web || true; run_plugin panel || true
    # second run: the logins of the first are in the state files now
    : >"$BODY"; check_mail || true; check_logins || true; run_plugin webmail || true; } 2>errors
  run grep -E 'syntax error|bad substitution|command not found' errors
  [ -z "$output" ]                                              # no payload reached the shell's arithmetic
  write_report
  run bash -c 'ls pwned* 2>/dev/null'
  [ -z "$output" ]                                              # nothing was executed
  run bash -c "LC_ALL=C grep -c \$'[\\x01-\\x08\\x0b-\\x1f\\x7f]' report.txt"
  [ "$output" = 0 ]                                             # no ESC, no stray control chars
  grep -qF '1 IPs  x[$(id>pwned4)]@d1.example' report.txt           # the webmail plugin reports it as text too
  grep -q 'touch pwned' report.txt                              # the payloads are reported as text
}
