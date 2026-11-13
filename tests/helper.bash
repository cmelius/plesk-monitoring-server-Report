# Shared setup for the bats tests: load the script's functions without running it,
# point everything at the test directory, and make every log line "new".
#
# AWK_DIR: a directory with an "awk" link to mawk or gawk, put first in PATH, so the
# tests run with the awk of Debian (mawk) and of RHEL (gawk).

# shellcheck disable=SC2034,SC2329  # variables and stubs are used by the sourced script
FIX="$BATS_TEST_DIRNAME/fixtures"

load_script() {
  # shellcheck source=../plesk-server-report.sh
  source "$BATS_TEST_DIRNAME/../plesk-server-report.sh"
  set +u                                  # bats itself does not run under nounset
  PATH="${AWK_DIR:+$AWK_DIR:}$PATH"       # the script resets PATH when loaded
  STATE_DIR="$BATS_TEST_TMPDIR/state"; mkdir -p "$STATE_DIR"
  TMPD="$BATS_TEST_TMPDIR/tmp"; mkdir -p "$TMPD"
  TMP="$TMPD/t"; BODY="$TMPD/body"; DALERTS="$TMPD/dalerts"; : >"$BODY"; : >"$DALERTS"
  ALERTS=(); ONLY_MODE=0; LOCKED_OUT=0; SUMMARY_ONLY=0
  PUBIP=203.0.113.10; GEO_OK=0; ALLOWED_COUNTRIES=""; DNSBL_LISTS=""; BLOCKLIST_RESOLVER=system
  _new_lines() { [[ -r $1 ]] && cat "$1"; return 0; }             # whole fixtures, through log_clean
  postqueue() { :; }
  T() { shift; "$@"; }                   # no time limits needed in tests
}

# the report text and the alerts of one check, for assertions
report() { cat "$BODY"; }
alerts() { printf '%s\n' "${ALERTS[@]}"; cat "$DALERTS"; }
