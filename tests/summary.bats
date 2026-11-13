#!/usr/bin/env bats
# write_summary from the hourly reports of a real server (anonymized): 21 reports, of which 19
# are within the 24 hours before the newest (one of the others exactly 24 hours before). summary-real.txt is the summary the server wrote
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

@test "reports in the layout of 2.0 (WordPress in a section of its own) give the same summary" {
  # the same reports, rewritten the way 2.0 writes them: WEB without the column login POSTs; login
  # POSTs, login attacks and PHP files in upload folders in WORDPRESS instead of WEB and WEBROOTS
  local f
  for f in "$OUT_DIR"/report-*.txt; do
    awk '
      /^== / { sec = $0 }
      sec ~ /^== WEB / && /^requests \| 5xx \| login POSTs/ { print "requests | 5xx | domain | busiest IP"; tbl = 1; next }
      tbl && /^ +[0-9]+ +[0-9]+ +[0-9]+  / { r = $0; sub(/^ +[0-9]+ +[0-9]+ +[0-9]+  /, "", r)
                                             printf "  %7d %5d  %s\n", $1, $2, r; if ($3 > 0) lg = lg sprintf("  %6d  %s\n", $3, $4); next }
      { tbl = 0 }
      sec ~ /^== WEB / && /^WordPress login attacks/ { wp = 1; wpt = $0 "\n"; next }
      wp && /^PHP fatal/ { wp = 0 }
      wp { wpt = wpt $0 "\n"; next }
      /^== WEBROOTS/ { print "== WORDPRESS (since last run) =="; print "login POSTs (wp-login.php + xmlrpc.php) | domain:"
                       printf "%s\n%s", lg, wpt; print "PHP files in upload folders (wp-content/uploads):"; lg = ""; wpt = ""; next }
      { print }' "$f" >"$f.new"
    touch -r "$f" "$f.new"; mv "$f.new" "$f"
  done
  grep -q '^== WORDPRESS' "$OUT_DIR"/report-20261113-0605.txt
  ! grep -q 'login POSTs | domain | busiest' "$OUT_DIR"/report-*.txt
  write_summary "$BATS_TEST_TMPDIR/summary2.txt" || true
  run diff <(tail -n +2 "$BATS_TEST_TMPDIR/summary2.txt") "$FIX/summary/summary-expected.txt"
  echo "$output"
  [ "$status" -eq 0 ]
}
