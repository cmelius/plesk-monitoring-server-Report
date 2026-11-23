#!/usr/bin/env bats
# The report in themes (MAIL, ACCESS, WEB, SYSTEM): sections of the hourly checks, then the
# daily checks of the theme; the alerts at the top grouped the same way; summary.txt likewise

load helper

setup() {
  load_script
  HOST=host.example.com; NOW="2026-11-14 10:05 UTC"; RUN_START=""; GEO_NOTE=""
  MAIL_LOG="$FIX/mail/hour.log"; VHOST_LOGS="$FIX/web"; PLESK_ERROR_LOG="$FIX/panel/panel.log"
  CONF=/nonexistent; PKG_DB=/nonexistent; BOOT_ID_FILE=/nonexistent; detect_pubip6() { :; }
  DAILY_CHECKS="updates firewall php mailboxes"
  check_updates() { echo "Updates available: 0, security updates: 0"; }
  check_firewall() { echo "Firewall:"; echo "  active"; dalert "Access: port 3306 (MySQL) reachable from everywhere"; }
  check_php() { echo "PHP:"; echo "  8.4: 3 domains"; dalert "PHP: 8.3 is out of security support"; }
  check_mailboxes() { echo "Mailboxes:"; echo "  3 checked"; }
  STATE_DIR=$BATS_TEST_TMPDIR/s; OUT_DIR=$STATE_DIR/out; mkdir -p "$OUT_DIR"; REPORT=$OUT_DIR/report.txt
}
one_run() {
  ALERTS=(); ALERT_CHK=(); : >"$BODY"; rm -f "$TMPD/json" "$TMPD/notes"
  run_hourly mail web panel || true
  daily_checks; timeout_alerts; write_report
}
headings() { grep -E '^(######## |== )' "$REPORT"; }

@test "the themes in their order, each with its daily checks last" {
  one_run
  run headings
  [ "${lines[0]}" = "######## MAIL ########" ]
  [ "${lines[1]}" = "== MAIL: delivery & spam filter ==" ]
  [[ $output == *"== MAIL: failed logins =="*"== MAIL – daily checks (as of "*"######## ACCESS ########"*"== PLESK PANEL: failed logins =="*"== ACCESS – daily checks"*"######## WEB ########"*"== WEB (since last run) =="*"== CERTIFICATE RENEWALS"*"######## SYSTEM ########"*"== SYSTEM – daily checks"* ]]
  # each daily text under its theme
  sed -n '/^== ACCESS – daily checks/,/^########/p' "$REPORT" | grep -qx 'Firewall:'
  sed -n '/^== SYSTEM – daily checks/,$p' "$REPORT" | grep -qx 'PHP:'
  sed -n '/^== SYSTEM – daily checks/,$p' "$REPORT" | grep -q '^Daily checks took '
  ! grep -q 'DAILY CHECKS' "$REPORT"
}

@test "the cached daily checks: the same themes in the next run" {
  one_run; headings >"$BATS_TEST_TMPDIR/a"
  one_run; headings >"$BATS_TEST_TMPDIR/b"
  diff "$BATS_TEST_TMPDIR/a" "$BATS_TEST_TMPDIR/b"
  sed -n '/^== MAIL – daily checks/,/^########/p' "$REPORT" | grep -qx 'Mailboxes:'
}

@test "alerts grouped by theme, with their number" {
  one_run
  run sed -n '3,/^$/p' "$REPORT"
  [[ $output == "MAIL (1):"*" ! Mail: mailbox info@d12.example is full"*"ACCESS (1):"*" ! Access: port 3306"*"WEB ("*" ! Certificate: automatic renewal for "*"SYSTEM (1):"*" ! PHP: 8.3 is out of security support"* ]]
}

@test "within a theme the critical alerts first" {
  ALERTS=("Web: a warning" "Web: suspicious file x.php" "Mail: a warning")
  ALERT_CHK=("web 0" "web 0" "mail 0")
  sort_alerts
  [ "${ALERTS[*]}" = "Mail: a warning Web: suspicious file x.php Web: a warning" ]
  [ "${ALERT_THEME[*]}" = "MAIL WEB WEB" ]
}

@test "--only: only the themes of the checks that ran" {
  ONLY_MODE=1; DAILY_CHECKS=""
  ALERTS=(); ALERT_CHK=(); : >"$BODY"
  run_hourly web; write_report
  run headings
  [ "${lines[0]}" = "######## WEB ########" ]
  ! grep -q '######## MAIL' "$REPORT"
}

@test "summary.txt: the same themes, panel logins, renewals, fail2ban and the newest daily checks" {
  one_run; mv "$REPORT" "$OUT_DIR/report-20261114-0905.txt"
  check_mailboxes() { echo "Mailboxes:"; echo "  4 checked"; }
  rm -f "$STATE_DIR/daily_date"; one_run; mv "$REPORT" "$OUT_DIR/report-20261114-1005.txt"
  SUMMARY_HOURS=24; write_summary "$OUT_DIR/summary.txt" || true
  f=$OUT_DIR/summary.txt
  run grep -E '^(######## |== )' "$f"
  [[ $output == *"== ALERTS"*"######## MAIL ########"*"== MAIL – daily checks"*"######## ACCESS ########"*"== PLESK PANEL: failed logins (totals) =="*"== FAIL2BAN"*"== ACCESS – daily checks"*"######## WEB ########"*"== CERTIFICATE RENEWALS"*"######## SYSTEM ########"*"== SYSTEM – daily checks"* ]]
  # both runs read the whole panel log (the test has no offset for it): the totals are doubled
  grep -q '^Failed panel logins: 90 in total, most in one run: 45' "$f"
  grep -q '^  login names: admin ×66, root ×22, administrator ×2' "$f"
  grep -Eq '^ +4×  d44\.example  .* – .*  198\.18\.0\.12: Invalid response' "$f"
  # the daily checks of the newest report
  sed -n '/^== MAIL – daily checks/,/^$/p' "$f" | grep -qx '  4 checked'
  # alerts grouped
  sed -n '/^== ALERTS/,/^$/p' "$f" | grep -qx 'ACCESS (1):'
  ! grep -q 'latest.txt' "$f"
}
