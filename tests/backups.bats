#!/usr/bin/env bats
# the plugin backups (plugins/backups.sh) on hand-written backup logs (fixtures/backups)

load helper

setup() {
  load_script
  B="$BATS_TEST_TMPDIR/backups"; cp -r "$FIX/backups" "$B"
  # git keeps no file times: the backups ran 3.5 hours ago, the failed one 30.5 hours ago
  touch -d "@$(( $(date +%s) - 12600 ))" "$B"/*/backup-*
  touch -d "@$(( $(date +%s) - 109800 ))" "$B"/failed/backup-*
}
backups() { : >"$BODY"; ALERTS=(); PLESK_BACKUP_LOGS="$B/$1"; run_plugin backups; }

@test "a backup without errors: time, age and status, no alert" {
  backups ok
  run report
  [[ $output == *"== BACKUPS =="* ]]
  [[ $output == *"Plesk backup: last run "*" (3 h ago, backup-2026-11-11-01-00-03-102), status: OK (exit code 0)"* ]]
  [ "${#ALERTS[@]}" -eq 0 ]
}

@test "a failed and old backup: first error line and both alerts" {
  backups failed
  run report
  [[ $output == *"(30 h ago, backup-2026-11-10-01-00-02-417), status: ERROR (2 error lines, exit code 121)"* ]]
  [[ $output == *"  first error: [2026-11-10 01:03:10.002|48230] ERROR: Unable to upload the backup to the remote storage"* ]]
  run alerts
  [[ $output == *"Backup: latest Plesk backup is 30 hours old"* ]]
  [[ $output == *"Backup: latest Plesk backup finished with errors"* ]]
  WARN_BACKUP_HOURS=48; backups failed
  run alerts
  [[ $output != *"hours old"* && $output == *"finished with errors"* ]]
}

@test "warnings, a backup without log, no backups, no directory" {
  backups warnings
  run report
  [[ $output == *"status: OK with 1 warnings"* ]]
  backups nolog
  run report
  [[ $output == *"status: unknown (no backup.log)"* ]]
  backups empty
  run report
  [[ $output == *"Plesk backup: no backup logs found in $B/empty"* ]]
  backups nonexistent
  run report
  [[ $output == *"Plesk backup: no backup logs found in $B/nonexistent"* ]]
  [ "${#ALERTS[@]}" -eq 0 ]
}

# The check as it was inside the main script (tests/legacy/check_backups.bash) and the plugin
# must write the same report and the same alerts. (|| true: the old function ran without errexit.)
@test "parity: the plugin writes what check_backups wrote" {
  # shellcheck source=legacy/check_backups.bash
  source "$BATS_TEST_DIRNAME/legacy/check_backups.bash"
  for c in ok failed warnings nolog empty nonexistent; do
    PLESK_BACKUP_LOGS="$B/$c"
    : >"$BODY"; ALERTS=(); legacy_check_backups || true; old=$(report; alerts)
    : >"$BODY"; ALERTS=(); run_plugin backups;   new=$(report; alerts)
    [[ -n $old && $old == "$new" ]]
  done
  PLESK_BACKUP_LOGS=""
  : >"$BODY"; ALERTS=(); legacy_check_backups || true; old=$(report; alerts)
  : >"$BODY"; ALERTS=(); run_plugin backups;   new=$(report; alerts)
  [[ -n $old && $old == "$new" ]]
  [ ! -s "$TMPD/notes" ]
}
