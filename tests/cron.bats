#!/usr/bin/env bats
# cron_note: a note when no cron line or systemd unit runs this copy of the script

load helper

setup() {
  load_script
  C="$BATS_TEST_TMPDIR/etc"; mkdir -p "$C/cron.d" "$C/systemd" "$BATS_TEST_TMPDIR/opt"
  SELF="$BATS_TEST_TMPDIR/opt/plesk-server-report.sh"; touch "$SELF"
  script_self() { echo "$SELF"; }
  CRON_FILES="$C/crontab $C/cron.d/* $C/root $C/systemd/*.service"
}
notes() { cat "$TMPD/notes" 2>/dev/null; }

@test "a line in cron.d runs this copy: no note" {
  echo "5 * * * * root $SELF" >"$C/cron.d/plesk-server-report"
  cron_note
  [ -z "$(notes)" ]
}

@test "root's crontab, a symlink to the script, or a systemd unit count too" {
  ln -s "$SELF" "$BATS_TEST_TMPDIR/psr"
  echo "@hourly $BATS_TEST_TMPDIR/psr --no-upload >/dev/null 2>&1" >"$C/root"
  cron_note; [ -z "$(notes)" ]
  rm "$C/root"; printf '[Service]\nExecStart=%s\n' "$SELF" >"$C/systemd/psr.service"
  cron_note; [ -z "$(notes)" ]
}

@test "no cron line: a note with the line to add (hourly), no alert" {
  echo "0 3 * * * root /usr/bin/other-job" >"$C/crontab"
  cron_note
  [[ $(notes) == "cron: no cron line or systemd unit runs $SELF"*"echo '5 * * * * root $SELF' > /etc/cron.d/plesk-server-report"* ]]
  [ -z "$(alerts)" ]
}

@test "a cron line with the old path after a move: named in the note" {
  echo "5 * * * * root /usr/local/sbin/plesk-server-report.sh" >"$C/cron.d/plesk-server-report"
  cron_note
  [[ $(notes) == "cron: no cron line runs this copy ($SELF) – $C/cron.d/plesk-server-report runs /usr/local/sbin/plesk-server-report.sh; moved the script, or is this a second copy?"* ]]
}

@test "commented-out lines don't count" {
  echo "# 5 * * * * root $SELF" >"$C/cron.d/plesk-server-report"
  cron_note
  [[ $(notes) == "cron: no cron line or systemd unit runs"* ]]
}
