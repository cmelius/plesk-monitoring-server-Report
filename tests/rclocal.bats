#!/usr/bin/env bats
# check_rclocal: /etc/rc.local missing, not executable, executable without commands, in use

load helper

setup() {
  load_script
  RC_LOCAL="$BATS_TEST_TMPDIR/rc.local"
  WARN_RC_LOCAL=1
  RCL_FAILED=0
  systemctl() { [[ $* == "is-failed --quiet rc-local.service" ]] && (( RCL_FAILED )); }
}

@test "missing: not used, no alert" {
  run check_rclocal
  [[ $output == *"rc.local: not used ("*"doesn't exist)"* ]]
  [ -z "$(cat "$DALERTS")" ]
}

@test "not executable (RHEL default): not used, no alert" {
  printf '#!/bin/bash\ntouch /var/lock/subsys/local\n' >"$RC_LOCAL"; chmod 644 "$RC_LOCAL"
  run check_rclocal
  [[ $output == *"rc.local: not used ("*"is not executable"* ]]
  [ -z "$(cat "$DALERTS")" ]
}

@test "executable, only comments and exit 0: recommendation, no alert" {
  printf '#!/bin/sh -e\n#\n# rc.local\n\n  exit 0\n' >"$RC_LOCAL"; chmod 755 "$RC_LOCAL"
  run check_rclocal
  [[ $output == *"is executable but has no commands"*"chmod -x"* ]]
  [ -z "$(cat "$DALERTS")" ]
}

@test "executable with commands: line and a daily warning" {
  printf '#!/bin/sh\n# start the old thing\n/opt/old/start.sh &\nsysctl -w vm.swappiness=10\nexit 0\n' >"$RC_LOCAL"; chmod 755 "$RC_LOCAL"
  check_rclocal >"$BODY"
  run report
  [[ $output == *"rc.local: in use (2 command line(s) in"*"deprecated"*"systemd unit"* ]]
  run cat "$DALERTS"
  [[ $output == "rc.local: "*"runs 2 command line(s) at boot – deprecated"*"WARN_RC_LOCAL=0"* ]]
  [ "$(alert_severity "$output")" = warning ]
}

@test "WARN_RC_LOCAL=0: only the line" {
  printf '#!/bin/sh\n/opt/old/start.sh &\n' >"$RC_LOCAL"; chmod 755 "$RC_LOCAL"
  WARN_RC_LOCAL=0
  run check_rclocal
  [[ $output == *"rc.local: in use (1 command line(s)"* ]]
  [ -z "$(cat "$DALERTS")" ]
}

@test "failed rc-local.service with commands: said in the line and the warning" {
  printf '#!/bin/sh\n/opt/old/start.sh &\n' >"$RC_LOCAL"; chmod 755 "$RC_LOCAL"
  RCL_FAILED=1
  check_rclocal >"$BODY"
  run report
  [[ $output == *"rc.local: in use (1 command line(s)"*"rc-local.service failed at boot (systemctl status rc-local shows why)."* ]]
  run cat "$DALERTS"
  [[ $output == "rc.local: "*"runs 1 command line(s) at boot (and failed) – deprecated"* ]]
  [ "$(alert_severity "$output")" = warning ]
}

@test "failed rc-local.service without commands: recommendation, no alert" {
  printf '#!/bin/bash\nexit 0\n' >"$RC_LOCAL"; chmod 755 "$RC_LOCAL"
  RCL_FAILED=1
  run check_rclocal
  [[ $output == *"has no commands"*"chmod -x"*"rc-local.service failed at boot"* ]]
  [ -z "$(cat "$DALERTS")" ]
}
