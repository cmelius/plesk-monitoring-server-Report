#!/usr/bin/env bats
# the plugin backups (plugins/backups.sh) on Plesk backup logs (BACKUP_LOG_DIR/backup-*/backup.log)
# ok/: excerpt of a real, anonymized log; error/: the same with a made-up error line

load helper

setup() { load_script; WARN_BACKUP_HOURS=999999; }   # fixture dates are fixed, the age is not tested
backups() { : >"$BODY"; ALERTS=(); run_plugin backups; }

@test "successful backup: status OK with the exit code" {
  BACKUP_LOG_DIR="$FIX/backup/ok"; backups
  run report
  [[ $output == *"backup-2026-11-13-03-23-11-000), status: OK (exit code 0)"* ]]
  run alerts
  [[ $output != *Backup* ]]
}

@test "backup with errors: status, first error line and alert" {
  BACKUP_LOG_DIR="$FIX/backup/error"; backups
  run report
  [[ $output == *"status: ERROR (1 error lines, exit code 121)"* ]]
  [[ $output == *"first error: "*"ERROR: Unable to upload the backup"* ]]
  run alerts
  [[ $output == *"Backup: latest Plesk backup finished with errors"* ]]
}

@test "old backup raises an alert" {
  BACKUP_LOG_DIR="$BATS_TEST_TMPDIR/pmm"; mkdir -p "$BACKUP_LOG_DIR"
  cp -r "$FIX/backup/ok/backup-2026-11-13-03-23-11-000" "$BACKUP_LOG_DIR/"
  touch -d '3 days ago' "$BACKUP_LOG_DIR/backup-2026-11-13-03-23-11-000"
  WARN_BACKUP_HOURS=30; backups
  run alerts
  [[ $output == *"Backup: latest Plesk backup is 7"?" hours old"* ]]
}

# cases the real logs don't have, made from them
edge_cases() {
  E="$BATS_TEST_TMPDIR/edge"; mkdir -p "$E/warnings" "$E/nolog/backup-2026-11-13-03-23-11-000" "$E/empty"
  cp -r "$FIX/backup/ok/backup-2026-11-13-03-23-11-000" "$E/warnings/"
  sed -i '2a [2026-11-13 03:24:00.000|1] WARNING: made-up warning for the test' "$E/warnings/backup-2026-11-13-03-23-11-000/backup.log"
}

@test "warnings, a backup without log, no backups, no directory" {
  edge_cases
  BACKUP_LOG_DIR="$E/warnings"; backups
  run report
  [[ $output == *"status: OK with 1 warnings"* ]]
  BACKUP_LOG_DIR="$E/nolog"; backups
  run report
  [[ $output == *"status: unknown (no backup.log)"* ]]
  BACKUP_LOG_DIR="$E/empty"; backups
  run report
  [[ $output == *"Plesk backup: no backup logs found in $E/empty"* ]]
  BACKUP_LOG_DIR="$E/nonexistent"; backups
  run report
  [[ $output == *"Plesk backup: log directory not found"* ]]
  [ "${#ALERTS[@]}" -eq 0 ]
}

# The check as it was in release 1.11.1 (tests/legacy/check_backups.bash) and the plugin must
# write the same report and the same alerts. (|| true: the old function ran without errexit.)
@test "parity: the plugin writes what check_backups wrote" {
  # shellcheck source=legacy/check_backups.bash
  source "$BATS_TEST_DIRNAME/legacy/check_backups.bash"
  edge_cases
  WARN_BACKUP_HOURS=30
  for d in "$FIX/backup/ok" "$FIX/backup/error" "$E/warnings" "$E/nolog" "$E/empty" "$E/nonexistent" ""; do
    BACKUP_LOG_DIR=$d
    : >"$BODY"; ALERTS=(); legacy_check_backups || true; old=$(report; alerts)
    backups;                                          new=$(report; alerts)
    [[ -n $old && $old == "$new" ]]
  done
  [ ! -s "$TMPD/notes" ]
}
