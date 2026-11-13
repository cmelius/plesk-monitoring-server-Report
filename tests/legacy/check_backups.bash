# check_backups as it was inside the main script (release 1.11.1) before it became
# plugins/backups.sh – kept, unchanged, for the parity test in backup.bats.
# shellcheck shell=bash
legacy_check_backups() {   # latest Plesk backup (time, age, errors), Acronis agent – every run, so the age is current
  local pmm last age st now mt
  now=$(date +%s)
  section "BACKUPS"
  for pmm in ${BACKUP_LOG_DIR:-/var/log/plesk/PMM /usr/local/psa/PMM/logs /opt/psa/PMM/logs}; do [[ -d $pmm ]] && break; pmm=""; done
  if [[ -n $pmm ]]; then
    last=$(T "$CMD_TIMEOUT" find -L "$pmm" -maxdepth 2 -type d -name 'backup-*' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)
    if [[ -n $last ]]; then
      mt=$(stat -c %Y "$last"); age=$(( (now - mt) / 3600 ))
      local blog="$last/backup.log" nerr=0 nwarn=0 ec="" ex=""
      if [[ -r $blog ]]; then
        nerr=$(grep -cE '\] (ERROR|CRITICAL|FATAL):' "$blog"); nwarn=$(grep -cE '\] WARNING:' "$blog")
        ec=$(grep -oE 'Exit code: [0-9]+' "$blog" | tail -1 | grep -oE '[0-9]+$')
        ex=$(grep -m1 -E '\] (ERROR|CRITICAL|FATAL):' "$blog" | cut -c1-220)
      fi
      if [[ ! -r $blog ]]; then st="unknown (no backup.log)"
      elif (( nerr > 0 )) || [[ -n $ec && $ec != 0 ]]; then st="ERROR ($nerr error lines, exit code ${ec:-?})"
      elif (( nwarn > 0 )); then st="OK with $nwarn warnings"
      else st="OK (exit code ${ec:-?})"; fi
      out "Plesk backup: last run $(date -d "@$mt" '+%Y-%m-%d %H:%M %Z') ($age h ago, $(basename "$last")), status: $st"
      [[ -n $ex ]] && out "  first error: $ex"
      (( age > WARN_BACKUP_HOURS )) && alert "Backup: latest Plesk backup is $age hours old"
      [[ $st == ERROR* ]] && alert "Backup: latest Plesk backup finished with errors"
    else
      out "Plesk backup: no backup logs found in $pmm"
    fi
  else
    out "Plesk backup: log directory not found"
  fi
  # Acronis agent (used by several hosting providers for image backups) – only if installed
  if pgrep -x aakore >/dev/null || pgrep -f '[a]cronis' >/dev/null; then
    out "Acronis agent: running"
  elif [[ -d /usr/lib/Acronis || -d /opt/acronis || -d /var/lib/Acronis ]]; then
    out "Acronis agent: installed but NOT running"; alert "Backup: Acronis agent is not running"
  fi
  return 0
}
