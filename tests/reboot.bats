#!/usr/bin/env bats
# dnf_reboot_check: needs-restarting -r as dnf plugin or command, its English answer counts;
# without an answer (plugin missing) the kernels are compared

load helper

setup() {
  load_script
  unset -f needs-restarting
  KCHECK=0
  kernel_reboot_check() { KCHECK=1; }
  PATH="$BATS_TEST_TMPDIR/bin:$PATH"; mkdir -p "$BATS_TEST_TMPDIR/bin"
}

@test "dnf plugin: reboot required" {
  dnf() { echo "Core libraries or services have been updated since boot-up:"; echo "  * glibc"; echo "Reboot is required to fully utilize these updates."; return 1; }
  run dnf_reboot_check
  [[ $output == *"Reboot required (needs-restarting"* ]]
  dnf_reboot_check >/dev/null
  run cat "$DALERTS"
  [[ $output == *"System: reboot required after updates"* ]]
}

@test "dnf plugin: no reboot needed, no kernel check" {
  dnf() { echo "No core libraries or services have been updated since boot-up."; echo "Reboot should not be necessary."; return 0; }
  dnf_reboot_check >/dev/null
  [ "$KCHECK" = 0 ]
  [ -z "$(cat "$DALERTS")" ]
}

@test "plugin missing (exit 1, other text): no alert, the kernels are compared" {
  dnf() { echo "No such command: needs-restarting. Please use /usr/bin/dnf --help"; return 1; }
  dnf_reboot_check >/dev/null
  [ "$KCHECK" = 1 ]
  [ -z "$(cat "$DALERTS")" ]
}

@test "needs-restarting command is used when installed" {
  printf '#!/bin/sh\necho "Reboot is required to fully utilize these updates."\nexit 1\n' >"$BATS_TEST_TMPDIR/bin/needs-restarting"
  chmod +x "$BATS_TEST_TMPDIR/bin/needs-restarting"
  dnf() { echo "should not be called"; return 1; }
  run dnf_reboot_check
  [[ $output == *"Reboot required"* ]]
}
