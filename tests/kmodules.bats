#!/usr/bin/env bats
# check_kmodules: kernel modules of rarely used network protocols – loaded, blocked, blacklisted,
# not installed, built in or loadable (stubbed modprobe, modinfo, uname; /sys/module and /lib/modules
# in the test directory)

load helper

setup() {
  load_script
  RARE_MODULES="sctp dccp tipc rds"
  MODULES_SYS="$BATS_TEST_TMPDIR/sys"; MODULES_DIR="$BATS_TEST_TMPDIR/lib"
  mkdir -p "$MODULES_SYS" "$MODULES_DIR/6.1.0-test"
  : >"$MODULES_DIR/6.1.0-test/modules.builtin"
  RULES=""; INSTALLED="sctp dccp tipc rds"
  uname() { echo 6.1.0-test; }
  modprobe() { [[ $1 == -c ]] && printf '%s' "$RULES"; return 0; }
  modinfo() { [[ " $INSTALLED " == *" ${*: -1} "* ]]; }
}

@test "all loadable: recommendation with the command, no alert" {
  check_kmodules >"$BODY"
  run report
  [[ $output == *"Kernel modules of rarely used network protocols: sctp loadable, dccp loadable, tipc loadable, rds loadable"* ]]
  [[ $output == *"printf 'install %s /bin/false\\n' sctp dccp tipc rds >/etc/modprobe.d/rare-net-modules.conf"* ]]
  run alerts
  [ -z "$output" ]
}

@test "blocked, blacklisted, not installed, built in: no recommendation, no alert" {
  RULES='install sctp /bin/false
blacklist dccp
alias net-pf-30 tipc
'
  INSTALLED="sctp dccp tipc"
  echo "kernel/net/tipc/tipc.ko" >"$MODULES_DIR/6.1.0-test/modules.builtin"
  check_kmodules >"$BODY"
  run report
  [[ $output == *": sctp blocked, dccp blacklisted (not loaded automatically), tipc built into the kernel, rds not installed"* ]]
  [[ $output != *"Recommendation"* ]]
  run alerts
  [ -z "$output" ]
}

@test "a loaded module: warning, unload hint" {
  mkdir "$MODULES_SYS/sctp"
  RULES='install dccp /bin/true
install tipc /usr/bin/false
install rds /bin/false --ignore
'
  check_kmodules >"$BODY"
  run report
  [[ $output == *": sctp LOADED, dccp blocked, tipc blocked, rds blocked"* ]]
  [[ $output == *"printf 'install %s /bin/false\\n' sctp >"* ]]
  [[ $output == *"Loaded: sctp – no longer needed? After blocking: modprobe -r sctp, or reboot if it is in use"* ]]
  run alerts
  [[ $output == *"Kernel: rarely used network module(s) loaded: sctp – "* ]]
}

@test "loaded but already blocked (blocked after it was loaded): no recommendation, still the warning" {
  mkdir "$MODULES_SYS/sctp"
  RULES='install sctp /bin/false
'
  RARE_MODULES="sctp"
  check_kmodules >"$BODY"
  run report
  [[ $output == *": sctp LOADED (blocked from the next boot on)"* ]]
  [[ $output != *"Recommendation"* ]]
  run alerts
  [[ $output == *"Kernel: rarely used network module(s) loaded: sctp – "* ]]
}

@test "an install rule that runs something else is no block" {
  RULES='install sctp /sbin/modprobe --ignore-install sctp
'
  RARE_MODULES="sctp"
  check_kmodules >"$BODY"
  run report
  [[ $output == *": sctp loadable"* ]]
}

@test "RARE_MODULES empty: the check is off" {
  RARE_MODULES=" "
  ! check_enabled kmodules
}
