#!/usr/bin/env bats
# --self-update of version 1: download, test and replace the script, --rollback, --major.
# No network: the release query and the download are stubbed.

load helper

setup() {
  load_script
  INST="$BATS_TEST_TMPDIR/sbin"; mkdir -p "$INST"
  SU_SELF="$INST/plesk-server-report.sh"
  cp "$BATS_TEST_DIRNAME/../plesk-server-report.sh" "$SU_SELF"; chmod 700 "$SU_SELF"
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
}

installed() { bash "$SU_SELF" --version; }
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

@test "already up to date: nothing changes" {
  LATEST=1.12.0; OVERALL=1.12.0
  run self_update_1x
  [ "$status" -eq 0 ]
  [[ $output == *"version 1.12.0 is up to date (latest 1.x release: 1.12.0)"* ]]
  [ ! -e "$STATE_DIR/plesk-server-report.sh.old" ]
}

@test "version 2 released: 1.x is not replaced by it, only a note" {
  LATEST=1.12.0; OVERALL=2.0.0
  run self_update_1x
  [ "$status" -eq 0 ]
  [[ $output == *"Version 2.0.0 is available. It can't be installed with --self-update of version 1"* ]]
  cmp -s "$SU_SELF" "$BATS_TEST_DIRNAME/../plesk-server-report.sh"
  [ ! -e "$STATE_DIR/plesk-server-report.sh.old" ]
}

@test "--major is recognised, but not available in 1.x yet" {
  SU_MAJOR=1; OVERALL=2.0.0
  run self_update_1x
  [ "$status" -eq 0 ]
  [[ $output == *"switching to version 2 is not available in this version yet"* ]]
  cmp -s "$SU_SELF" "$BATS_TEST_DIRNAME/../plesk-server-report.sh"
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

@test "update: changes shown, script replaced, old version kept in the state directory" {
  run self_update_1x
  [ "$status" -eq 0 ]
  [[ $output == *"version 1.12.1 is available (installed: 1.12.0)"* ]]
  [[ $output == *"- a fix"* ]]
  [[ $output != *"- old"* ]]
  [ "$(installed)" = "plesk-server-report 1.12.1" ]
  [ "$(stat -c %a "$SU_SELF")" = 700 ]
  [ "$(bash "$STATE_DIR/plesk-server-report.sh.old" --version)" = "plesk-server-report 1.12.0" ]
  [ "$(leftovers)" -eq 0 ]
}

@test "answer no: nothing changes" {
  SU_YES=0
  run self_update_1x <<<"n"
  [ "$status" -eq 0 ]
  [[ $output == *"nothing changed"* ]]
  [ "$(installed)" = "plesk-server-report 1.12.0" ]
  [ "$(leftovers)" -eq 0 ]
}

@test "--rollback brings the kept version back, and swaps again" {
  self_update_1x >/dev/null
  [ "$(installed)" = "plesk-server-report 1.12.1" ]
  SU_ROLLBACK=1
  run self_update_1x
  [ "$status" -eq 0 ]
  [[ $output == *"back to 1.12.0"* ]]
  [ "$(installed)" = "plesk-server-report 1.12.0" ]
  [ "$(bash "$STATE_DIR/plesk-server-report.sh.old" --version)" = "plesk-server-report 1.12.1" ]
}

@test "--rollback without a kept version" {
  SU_ROLLBACK=1
  run self_update_1x
  [ "$status" -eq 1 ]
  [[ $output == *"there is no previous version"* ]]
}

@test "--yes, --rollback and --major only with --self-update" {
  run bash "$BATS_TEST_DIRNAME/../plesk-server-report.sh" --rollback
  [ "$status" -eq 2 ]
  run bash "$BATS_TEST_DIRNAME/../plesk-server-report.sh" --major
  [ "$status" -eq 2 ]
}
