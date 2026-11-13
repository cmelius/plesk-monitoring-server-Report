# shellcheck shell=bash
# shellcheck disable=SC2034  # the PLUGIN_ header is read by the main script
PLUGIN_NAME="backups"
PLUGIN_API="0"
PLUGIN_SCHEDULE="hourly"
PLUGIN_SECTION="BACKUPS"
PLUGIN_SETTINGS="WARN_BACKUP_HOURS BACKUP_LOG_DIR"
PLUGIN_READS="/var/log/plesk/PMM /usr/local/psa/PMM/logs /opt/psa/PMM/logs"
PLUGIN_OS="debian rhel"
PLUGIN_MAINTAINER="core"

# Latest Plesk backup (time, age, errors) and the Acronis agent – every run, so the age is
# current. Plesk keeps one directory backup-<time> with a backup.log per backup run.
plugin_check() {
  local pmm last age st now mt
  now=$(date +%s)
  for pmm in ${BACKUP_LOG_DIR:-/var/log/plesk/PMM /usr/local/psa/PMM/logs /opt/psa/PMM/logs}; do [[ -d $pmm ]] && break; pmm=""; done
  if [[ -n $pmm ]]; then
    last=$(find -L "$pmm" -maxdepth 2 -type d -name 'backup-*' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)
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
