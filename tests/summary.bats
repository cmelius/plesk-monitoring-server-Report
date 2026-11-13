#!/usr/bin/env bats
# write_summary from the hourly reports of a real server (anonymized): 26 reports, of which 19
# are within the 24 hours before the newest. summary-real.txt is the summary the server wrote
# (anonymized); summary-expected.txt is what this version writes from the same reports.

load helper

setup() {
  load_script
  OUT_DIR="$BATS_TEST_TMPDIR/out"; mkdir -p "$OUT_DIR"; cp "$FIX"/summary/reports/report-*.txt "$OUT_DIR/"
  # file times as on the server, relative to now: the newest report is from just now
  local now newest f b t
  now=$(date +%s); newest=$(date -u -d '2026-11-13 06:05' +%s)
  for f in "$OUT_DIR"/report-*.txt; do
    b=${f##*/report-}; b=${b%.txt}
    t=$(date -u -d "${b:0:4}-${b:4:2}-${b:6:2} ${b:9:2}:${b:11:2}" +%s)
    touch -d "@$(( now - (newest - t) ))" "$f"
  done
  HOST=host.example.com; SUMMARY_HOURS=24
  write_summary "$BATS_TEST_TMPDIR/summary.txt" || true
}

section() { sed -n "/^== $1/,/^\$/p" "$2"; }

@test "runs and alerts are the same as in the summary the server wrote" {
  [ "$(section RUNS "$BATS_TEST_TMPDIR/summary.txt")" = "$(section RUNS "$FIX/summary/summary-real.txt")" ]
  [ "$(section ALERTS "$BATS_TEST_TMPDIR/summary.txt")" = "$(section ALERTS "$FIX/summary/summary-real.txt")" ]
}

@test "only the reports of the last 24 hours" {
  run head -1 "$BATS_TEST_TMPDIR/summary.txt"
  [[ $output == *"last 24 h: 19 report(s), 2026-11-12 07:00 UTC to 2026-11-13 06:05 UTC"* ]]
}

@test "the whole summary is unchanged (update summary-expected.txt on purpose)" {
  run diff <(tail -n +2 "$BATS_TEST_TMPDIR/summary.txt") "$FIX/summary/summary-expected.txt"
  echo "$output"
  [ "$status" -eq 0 ]
}
