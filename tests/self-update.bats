#!/usr/bin/env bats
# --self-update of version 1: download, test and replace the script, --rollback, --major.
# No network: the release query and the download are stubbed.

load helper

setup() {
  load_script
  INST="$BATS_TEST_TMPDIR/sbin"; mkdir -p "$INST"
  SU_SELF="$INST/plesk-server-report.sh"
  # the tests pretend 1.12.0 is installed, whatever the version of the script under test
  sed 's/^VERSION=.*/VERSION=1.12.0/' "$BATS_TEST_DIRNAME/../plesk-server-report.sh" >"$SU_SELF"; chmod 700 "$SU_SELF"
  VERSION=1.12.0; ORIG="$BATS_TEST_TMPDIR/orig.sh"; cp "$SU_SELF" "$ORIG"
  NEW="$BATS_TEST_TMPDIR/new.sh"
  sed 's/^VERSION=.*/VERSION=1.12.1/' "$SU_SELF" >"$NEW"
  LATEST=1.12.1; OVERALL=1.12.1
  is_root() { return 0; }
  su_by_hand() { return 0; }
  latest_release_in_major() { [[ $1 == 1 ]] && echo "$LATEST"; }
  latest_release() { echo "$OVERALL"; }
  su_fetch() {
    case $1 in
      */v$LATEST/plesk-server-report.sh) cp "$NEW" "$2" ;;
      */v$LATEST/CHANGELOG.md) printf '# Changelog\n\n## [1.12.1] – test\n- a fix\n\n## [1.12.0] – before\n- old\n' >"$2" ;;
      *) return 1 ;;
    esac
  }
  SU_YES=1
  BK="$INST/plesk-server-report-backup"
}

installed() { bash "$SU_SELF" --version; }
nkept() { find "$BK" -mindepth 1 -maxdepth 1 -name 'plesk-server-report-*' 2>/dev/null | wc -l; }   # also catches leftover .tmp
leftovers() { find "$INST" -name '.plesk-server-report.*' | wc -l; }

@test "only as root" {
  is_root() { return 1; }
  run self_update_1x
  [ "$status" -eq 1 ]
  [[ $output == *"run it as root"* ]]
}

@test "not from cron: without a terminal it refuses, also with --yes" {
  su_by_hand() { return 1; }
  run self_update_1x
  [ "$status" -eq 1 ]
  [[ $output == *"start it by hand in a terminal"* ]]
}

@test "a git checkout is not replaced" {
  mkdir "$INST/.git"
  run self_update_1x
  [ "$status" -eq 1 ]
  [[ $output == *"git checkout – update it with git pull"* ]]
  [ "$(installed)" = "plesk-server-report 1.12.0" ]
}

@test "already up to date (same file as the release): nothing changes" {
  LATEST=1.12.0; OVERALL=1.12.0; cp "$SU_SELF" "$NEW"
  run self_update_1x
  [ "$status" -eq 0 ]
  [[ $output == *"version 1.12.0 is up to date (latest 1.x release: 1.12.0)"* ]]
  [ "$(nkept)" -eq 0 ]
}

@test "newer than the latest release (from main): nothing to do" {
  LATEST=1.11.0; OVERALL=1.11.0
  run self_update_1x
  [ "$status" -eq 0 ]
  [[ $output == *"version 1.12.0 is newer than the latest 1.x release 1.11.0 (development version from main) – nothing to do"* ]]
  cmp -s "$SU_SELF" "$ORIG"
}

@test "version 2 released: 1.x is not replaced by it, only a note" {
  LATEST=1.12.0; OVERALL=2.0.0; cp "$SU_SELF" "$NEW"
  run self_update_1x
  [ "$status" -eq 0 ]
  [[ $output == *"Version 2.0.0 is available. It can't be installed with --self-update of version 1"* ]]
  cmp -s "$SU_SELF" "$ORIG"
  [ "$(nkept)" -eq 0 ]
}

@test "--major is recognised, but not available in 1.x yet" {
  SU_MAJOR=1; OVERALL=2.0.0
  run self_update_1x
  [ "$status" -eq 0 ]
  [[ $output == *"switching to version 2 is not available in this version yet"* ]]
  cmp -s "$SU_SELF" "$ORIG"
}

@test "a broken download (bash -n) is not installed" {
  printf 'VERSION=1.12.1\nif then fi (\n' >"$NEW"
  run self_update_1x
  [ "$status" -eq 1 ]
  [[ $output == *"failed its test"*"nothing installed"* ]]
  [ "$(installed)" = "plesk-server-report 1.12.0" ]
  [ "$(leftovers)" -eq 0 ]
}

@test "a download that reports another version is not installed" {
  sed -i 's/^VERSION=.*/VERSION=1.12.5/' "$NEW"
  run self_update_1x
  [ "$status" -eq 1 ]
  [[ $output == *"not version 1.12.1"* ]]
  [ "$(installed)" = "plesk-server-report 1.12.0" ]
  [ "$(leftovers)" -eq 0 ]
}

@test "update: changes shown, script replaced, old version kept next to the script, not in the state folder" {
  run self_update_1x
  [ "$status" -eq 0 ]
  [[ $output == *"version 1.12.1 is available (installed: 1.12.0)"* ]]
  [[ $output == *"- a fix"* ]]
  [[ $output != *"- old"* ]]
  [ "$(installed)" = "plesk-server-report 1.12.1" ]
  [ "$(stat -c %a "$SU_SELF")" = 700 ]
  [ "$(bash "$BK/plesk-server-report-1.12.0.sh" --version)" = "plesk-server-report 1.12.0" ]
  [ "$(stat -c %a "$BK/plesk-server-report-1.12.0.sh")" = 600 ]
  [ "$(stat -c %a "$BK")" = 700 ]
  [ "$(nkept)" -eq 1 ]
  [ ! -e "$STATE_DIR/plesk-server-report.sh.old" ]
  [[ $output == *"is kept in $BK/plesk-server-report-1.12.0.sh"* ]]
  [ "$(leftovers)" -eq 0 ]
}

@test "one-folder installation: backup/ next to the script; BACKUP_DIR overrides it" {
  [ "$(CONF_LOCAL=1 backup_dir /opt/psr/plesk-server-report.sh)" = /opt/psr/backup ]
  [ "$(CONF_LOCAL=0 backup_dir /usr/local/sbin/plesk-server-report.sh)" = /usr/local/sbin/plesk-server-report-backup ]
  [ "$(BACKUP_DIR=/srv/keep backup_dir /usr/local/sbin/plesk-server-report.sh)" = /srv/keep ]
  CONF_LOCAL=1 self_update_1x >/dev/null
  [ -e "$INST/backup/plesk-server-report-1.12.0.sh" ]
}

@test "the copy kept by 1.15.x in the state folder moves to the backup folder" {
  mkdir -p "$STATE_DIR"; sed 's/^VERSION=.*/VERSION=1.11.0/' "$ORIG" >"$STATE_DIR/plesk-server-report.sh.old"
  touch -d '2026-01-01' "$STATE_DIR/plesk-server-report.sh.old"
  self_update_1x >/dev/null
  [ ! -e "$STATE_DIR/plesk-server-report.sh.old" ]
  [ "$(bash "$BK/plesk-server-report-1.11.0.sh" --version)" = "plesk-server-report 1.11.0" ]
  [ "$(date -r "$BK/plesk-server-report-1.11.0.sh" +%F)" = 2026-01-01 ]
  [ -e "$BK/plesk-server-report-1.12.0.sh" ]
}

@test "SCRIPT_RETENTION: only the newest versions are kept, other files in the folder stay" {
  mkdir -p "$BK"; local v
  for v in 1.9.0 1.10.0 1.11.0; do
    sed "s/^VERSION=.*/VERSION=$v/" "$ORIG" >"$BK/plesk-server-report-$v.sh"
  done
  touch -d '2026-01-01' "$BK/plesk-server-report-1.9.0.sh"; touch -d '2026-02-01' "$BK/plesk-server-report-1.10.0.sh"
  touch -d '2026-03-01' "$BK/plesk-server-report-1.11.0.sh"; touch "$BK/notes.txt"
  SCRIPT_RETENTION=2 self_update_1x >/dev/null
  [ -e "$BK/plesk-server-report-1.12.0.sh" ] && [ -e "$BK/plesk-server-report-1.11.0.sh" ]
  [ ! -e "$BK/plesk-server-report-1.10.0.sh" ] && [ ! -e "$BK/plesk-server-report-1.9.0.sh" ]
  [ -e "$BK/notes.txt" ]
}

@test "SCRIPT_RETENTION=0 still keeps one version (for --rollback)" {
  SCRIPT_RETENTION=0 self_update_1x >/dev/null
  [ "$(nkept)" -eq 1 ]
}

@test "the same version number with other content gets a name of its own" {
  mkdir -p "$BK"; sed 's/^# deleted binaries/# (main) deleted binaries/' "$ORIG" >"$BK/plesk-server-report-1.12.0.sh"
  self_update_1x >/dev/null
  [ "$(nkept)" -eq 2 ]
  ls "$BK" | grep -Eq '^plesk-server-report-1\.12\.0-[0-9]{8}-[0-9]{6}\.sh$'
}

@test "update into a new state folder: marked, so the next run accepts it (issue #3)" {
  STATE_DIR="$BATS_TEST_TMPDIR/new-state"
  self_update_1x >/dev/null
  [ -e "$STATE_DIR/$STATE_MARK" ]
  [ -e "$STATE_DIR/lock" ]
  [ "$(stat -c %a "$STATE_DIR")" = 700 ]
  run check_state_dir
  [ "$status" -eq 0 ]
}

@test "a state folder left by an update of 1.15.0 (only lock and the kept copy, no mark) is accepted" {
  STATE_DIR="$BATS_TEST_TMPDIR/old-state"; mkdir -p "$STATE_DIR"
  touch "$STATE_DIR/lock" "$STATE_DIR/plesk-server-report.sh.old"
  run check_state_dir
  [ "$status" -eq 0 ]
}

@test "no update into a state folder with other files" {
  STATE_DIR="$BATS_TEST_TMPDIR/home"; mkdir -p "$STATE_DIR"; touch "$STATE_DIR/.bashrc"
  run self_update_1x
  [ "$status" -eq 1 ]
  [[ $output == *"refusing to run"* ]]
  [ "$(nkept)" -eq 0 ]
  [ "$(installed)" = "plesk-server-report 1.12.0" ]
}

@test "answer no: nothing changes" {
  SU_YES=0
  run self_update_1x <<<"n"
  [ "$status" -eq 0 ]
  [[ $output == *"nothing changed"* ]]
  [ "$(installed)" = "plesk-server-report 1.12.0" ]
  [ "$(leftovers)" -eq 0 ]
}

@test "--rollback brings the newest kept version back, keeps the replaced one, and goes forward again" {
  self_update_1x >/dev/null
  [ "$(installed)" = "plesk-server-report 1.12.1" ]
  SU_ROLLBACK=1
  run self_update_1x
  [ "$status" -eq 0 ]
  [[ $output == *"back to 1.12.0"* ]]
  [ "$(installed)" = "plesk-server-report 1.12.0" ]
  [ "$(bash "$BK/plesk-server-report-1.12.1.sh" --version)" = "plesk-server-report 1.12.1" ]
  [ "$(stat -c %a "$SU_SELF")" = 700 ]
  [ "$(stat -c %a "$BK/plesk-server-report-1.12.1.sh")" = 600 ]
  sleep 1; run self_update_1x
  [ "$status" -eq 0 ]
  [ "$(installed)" = "plesk-server-report 1.12.1" ]
}

@test "--rollback VERSION: that version, not the newest" {
  mkdir -p "$BK"; sed 's/^VERSION=.*/VERSION=1.10.0/' "$ORIG" >"$BK/plesk-server-report-1.10.0.sh"
  touch -d '2026-01-01' "$BK/plesk-server-report-1.10.0.sh"
  self_update_1x >/dev/null
  SU_ROLLBACK=1; SU_ROLLBACK_TO=1.10.0
  run self_update_1x
  [ "$status" -eq 0 ]
  [ "$(installed)" = "plesk-server-report 1.10.0" ]
  SU_ROLLBACK_TO=1.8.0
  run self_update_1x
  [ "$status" -eq 1 ]
  [[ $output == *"no kept version 1.8.0"*"kept:"*"1.12.1"* ]]
}

@test "--rollback with only the copy kept by 1.15.x in the state folder" {
  mkdir -p "$STATE_DIR"; sed 's/^VERSION=.*/VERSION=1.11.0/' "$ORIG" >"$STATE_DIR/plesk-server-report.sh.old"
  SU_ROLLBACK=1
  run self_update_1x
  [ "$status" -eq 0 ]
  [ "$(installed)" = "plesk-server-report 1.11.0" ]
  [ ! -e "$STATE_DIR/plesk-server-report.sh.old" ]
  [ -e "$BK/plesk-server-report-1.12.0.sh" ]
}

@test "--rollback without a kept version" {
  SU_ROLLBACK=1
  run self_update_1x
  [ "$status" -eq 1 ]
  [[ $output == *"no kept version in $BK – kept: none"* ]]
}

@test "deleting the state folder keeps the versions for --rollback" {
  self_update_1x >/dev/null
  rm -rf "$STATE_DIR"
  SU_ROLLBACK=1
  run self_update_1x
  [ "$status" -eq 0 ]
  [ "$(installed)" = "plesk-server-report 1.12.0" ]
}

@test "--rollback VERSION is parsed, --rollback alone too" {
  parse_args --self-update --rollback 1.14.0
  [ "$SU_ROLLBACK" = 1 ] && [ "$SU_ROLLBACK_TO" = 1.14.0 ]
  SU_ROLLBACK_TO=""; parse_args --self-update --rollback --yes
  [ "$SU_ROLLBACK" = 1 ] && [ -z "$SU_ROLLBACK_TO" ] && [ "$SU_YES" = 1 ]
}

@test "--yes, --rollback and --major only with --self-update" {
  run bash "$BATS_TEST_DIRNAME/../plesk-server-report.sh" --rollback
  [ "$status" -eq 2 ]
  run bash "$BATS_TEST_DIRNAME/../plesk-server-report.sh" --major
  [ "$status" -eq 2 ]
}

@test "nothing of the new version runs before the answer" {
  { echo '#!/bin/bash'; echo "touch '$BATS_TEST_TMPDIR/ran'"; tail -n +2 "$NEW"; } >"$NEW.x"; mv "$NEW.x" "$NEW"
  SU_YES=0
  run self_update_1x <<<"n"
  [ "$status" -eq 0 ]
  [ ! -e "$BATS_TEST_TMPDIR/ran" ]
  [ "$(installed)" = "plesk-server-report 1.12.0" ]
}

@test "same version, but a copy from main that differs from the release: offered as an update" {
  LATEST=1.12.0
  sed 's/^# deleted binaries/# (release) deleted binaries/' "$SU_SELF" >"$NEW"
  run self_update_1x
  [ "$status" -eq 0 ]
  [[ $output == *"your copy of 1.12.0 differs from the release 1.12.0"* ]]
  cmp -s "$SU_SELF" "$NEW"
  [ -e "$BK/plesk-server-report-1.12.0.sh" ]
  [ "$(leftovers)" -eq 0 ]
}

# fake GitHub API: three commits that changed the script, newest first; the installed copy is the oldest
fake_api() {
  local c1=1111111111111111111111111111111111111111 c2=2222222222222222222222222222222222222222 c3=3333333333333333333333333333333333333333
  blobof() { { printf 'blob %d\0' "$(stat -c %s "$1")"; cat "$1"; } | sha1sum | cut -d' ' -f1; }
  case $1 in
    commits\?*) printf '[\n  {\n    "sha": "%s",\n    "commit": {\n      "message": "Fix the release\\n\\nCo-Authored-By: x",\n      "tree": {\n        "sha": "aaaa"\n      }\n    }\n  },\n  {\n    "sha": "%s",\n    "commit": {\n      "message": "Second change – with a dash",\n    }\n  },\n  {\n    "sha": "%s",\n    "commit": {\n      "message": "The copy you have",\n    }\n  }\n]\n' $c3 $c2 $c1 ;;
    contents/*ref=$c3) printf '{\n  "name": "plesk-server-report.sh",\n  "sha": "%s",\n}\n' "$(blobof "$NEW")" ;;
    contents/*ref=$c2) printf '{\n  "sha": "%s",\n}\n' 0000000000000000000000000000000000000000 ;;
    contents/*ref=$c1) printf '{\n  "sha": "%s",\n}\n' "$(blobof "${FAKE_INSTALLED:-$SU_SELF}")" ;;
  esac
}

@test "copy from main: the commits since that copy are listed" {
  LATEST=1.12.0; SU_YES=0
  sed 's/^# deleted binaries/# (release) deleted binaries/' "$SU_SELF" >"$NEW"
  su_api() { fake_api "$@"; }
  run self_update_1x <<<"n"
  [[ $output == *"Your copy is from commit 1111111; the release adds:"* ]]
  [[ $output == *"  - Fix the release"* ]]
  [[ $output == *"  - Second change – with a dash"* ]]
  [[ $output != *"The copy you have"* ]]
  [[ $output != *"Co-Authored-By"* ]]
}

@test "copy from main not found among the commits: the release's CHANGELOG section instead" {
  LATEST=1.12.0; SU_YES=0; FAKE_INSTALLED=/dev/null
  sed 's/^# deleted binaries/# (release) deleted binaries/' "$SU_SELF" >"$NEW"
  su_api() { fake_api "$@"; }
  su_fetch() {
    case $1 in
      */plesk-server-report.sh) cp "$NEW" "$2" ;;
      */CHANGELOG.md) printf '## [1.12.0] – test\n- the release section\n\n## [1.11.0] – before\n- old\n' >"$2" ;;
    esac
  }
  run self_update_1x <<<"n"
  [[ $output == *"Changes in 1.12.0 (your copy may contain some of them already):"* ]]
  [[ $output == *"- the release section"* ]]
  [[ $output != *"- old"* ]]
}

@test "changes: only the sections newer than the installed version, also without a section of its own" {
  su_fetch() {
    case $1 in
      */plesk-server-report.sh) cp "$NEW" "$2" ;;
      */CHANGELOG.md) printf '# Changelog\n\n## [1.12.1] – new\n- a fix\n\n## [1.11.0] – older\n- older entry\n' >"$2" ;;
    esac
  }
  # the installed 1.12.0 has no section here (like a number that never became a release)
  run self_update_1x
  [[ $output == *"- a fix"* ]]
  [[ $output != *"older entry"* ]]
}

@test "the downloaded CHANGELOG can't put terminal control sequences on the screen" {
  su_fetch() {
    case $1 in
      */plesk-server-report.sh) cp "$NEW" "$2" ;;
      */CHANGELOG.md) printf '## [1.12.1] – new\n- a fix \033[2J\033]0;owned\a\n\n## [1.12.0] – before\n' >"$2" ;;
    esac
  }
  run self_update_1x
  [[ $output == *"- a fix"* ]]
  run bash -c "LC_ALL=C grep -c \$'\\x1b' <<<\"\$1\"" _ "$output"
  [ "$output" = 0 ]
}

# --self-update --edge: fake GitHub – the newest commit on main, its tests (CHECKS: success,
# failure or running) and the script at that commit ($NEW, version 1.12.1)
edge_api() {
  local sha=4444444444444444444444444444444444444444
  case $1 in
    commits/main) printf '{\n  "sha": "%s",\n  "commit": {\n  }\n}\n' $sha ;;
    commits/$sha/check-runs*)
      case ${CHECKS:-success} in
        success) printf '{\n  "total_count": 2,\n  "check_runs": [\n    {\n      "status": "completed",\n      "conclusion": "success"\n    },\n    {\n      "status": "completed",\n      "conclusion": "success"\n    }\n  ]\n}\n' ;;
        failure) printf '{\n  "total_count": 2,\n  "check_runs": [\n    {\n      "status": "completed",\n      "conclusion": "success"\n    },\n    {\n      "status": "completed",\n      "conclusion": "failure"\n    }\n  ]\n}\n' ;;
        running) printf '{\n  "total_count": 1,\n  "check_runs": [\n    {\n      "status": "in_progress",\n      "conclusion": null\n    }\n  ]\n}\n' ;;
      esac ;;
    commits\?*sha=$sha*) printf '[\n  {\n    "sha": "%s",\n    "commit": {\n      "message": "A change on main",\n    }\n  }\n]\n' $sha ;;
    contents/*ref=$sha) printf '{\n  "sha": "%s",\n}\n' 0000000000000000000000000000000000000000 ;;
  esac
}
edge_setup() {
  SU_EDGE=1
  su_api() { edge_api "$@"; }
  su_fetch() {
    case $1 in
      */4444444444444444444444444444444444444444/plesk-server-report.sh) cp "$NEW" "$2" ;;
      */4444444444444444444444444444444444444444/CHANGELOG.md) printf '## [1.12.1] – not yet released (on `main`)\n- edge change\n\n## [1.12.0] – before\n- old\n' >"$2" ;;
      *) return 1 ;;
    esac
  }
}

@test "--edge: tests passed – the script of the newest commit on main is installed, the old copy kept" {
  edge_setup
  run self_update_1x
  [ "$status" -eq 0 ]
  [[ $output == *"commit 4444444, version 1.12.1 (installed: 1.12.0) – tests passed"* ]]
  [[ $output == *"NOT A RELEASE"* ]]
  [[ $output == *"- edge change"* ]]
  [ "$(installed)" = "plesk-server-report 1.12.1" ]
  [ "$(bash "$BK/plesk-server-report-1.12.0.sh" --version)" = "plesk-server-report 1.12.0" ]
  [ "$(leftovers)" -eq 0 ]
}

@test "--edge: failed or running tests – nothing is installed" {
  edge_setup
  CHECKS=failure run self_update_1x
  [ "$status" -eq 1 ]
  [[ $output == *"did not pass – not installed"* ]]
  CHECKS=running run self_update_1x
  [ "$status" -eq 1 ]
  [[ $output == *"still running"* ]]
  cmp -s "$SU_SELF" "$ORIG"
  [ "$(leftovers)" -eq 0 ]
}

@test "--edge: another major version on main is not installed" {
  edge_setup
  sed -i 's/^VERSION=.*/VERSION=2.0.0/' "$NEW"
  run self_update_1x
  [ "$status" -eq 1 ]
  [[ $output == *"main is at version 2.0.0 – --edge stays within version 1"* ]]
  cmp -s "$SU_SELF" "$ORIG"
}

@test "--edge: already the same as the version on main" {
  edge_setup
  cp "$SU_SELF" "$NEW"
  run self_update_1x
  [ "$status" -eq 0 ]
  [[ $output == *"your copy is the same as the version on main (newest commit"* ]]
  [ "$(leftovers)" -eq 0 ]
}

@test "--edge: answer no – nothing changes" {
  edge_setup; SU_YES=0
  run self_update_1x <<<"n"
  [[ $output == *"nothing changed"* ]]
  cmp -s "$SU_SELF" "$ORIG"
  [ "$(leftovers)" -eq 0 ]
}

@test "--edge only with --self-update, not with --rollback or --major" {
  run bash "$BATS_TEST_DIRNAME/../plesk-server-report.sh" --edge
  [ "$status" -eq 2 ]
  run bash "$BATS_TEST_DIRNAME/../plesk-server-report.sh" --self-update --edge --rollback
  [ "$status" -eq 2 ]
}
