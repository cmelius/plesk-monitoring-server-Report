#!/usr/bin/env bats
# JSON report (JSON_REPORT=1): an extra file next to the text report – the text stays the same

load helper

setup() {
  load_script
  HOST=host.example.com; NOW="2026-11-14 10:05 UTC"; RUN_START=1794650700; GEO_NOTE=""
  MAIL_LOG="$FIX/mail/hour.log"; VHOST_LOGS="$FIX/web"
  CONF=/nonexistent; PKG_DB=/nonexistent; BOOT_ID_FILE=/nonexistent
  DAILY_CHECKS="dummy"; detect_pubip6() { :; }
  check_dummy() { echo "Dummy daily: 2 things"; dalert "Dummy: something daily"; }
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
  diff <(grep -v '^As of:' "$BATS_TEST_TMPDIR/a/out/report.txt") <(grep -v '^As of:' "$BATS_TEST_TMPDIR/s/out/report.txt")
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
