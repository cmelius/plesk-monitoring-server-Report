#!/usr/bin/env bats
# check_backups on Plesk backup logs (BACKUP_LOG_DIR/backup-*/backup.log)
# ok/: excerpt of a real, anonymized log; error/: the same with a made-up error line

load helper

setup() { load_script; WARN_BACKUP_HOURS=999999; }   # fixture dates are fixed, the age is not tested

@test "successful backup: status OK with the exit code" {
  BACKUP_LOG_DIR="$FIX/backup/ok"; check_backups || true
  run report
  [[ $output == *"backup-2026-11-13-03-23-11-000), status: OK (exit code 0)"* ]]
  run alerts
  [[ $output != *Backup* ]]
}

@test "backup with errors: status, first error line and alert" {
  BACKUP_LOG_DIR="$FIX/backup/error"; check_backups || true
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
  WARN_BACKUP_HOURS=30; check_backups || true
  run alerts
  [[ $output == *"Backup: latest Plesk backup is 7"?" hours old"* ]]
}
