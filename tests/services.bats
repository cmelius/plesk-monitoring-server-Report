#!/usr/bin/env bats
# check_services: failed systemd units, IGNORE_FAILED_UNITS, the hint for rc-local.service (stubbed systemctl),
# crashes from the kernel log (stubbed journalctl) and the error logs of nginx, Apache and PHP-FPM

load helper

setup() {
  load_script
  FAILED_UNITS=""
  systemctl() { local u; for u in $FAILED_UNITS; do printf '%s loaded failed failed Dummy\n' "$u"; done; }
  KERNEL_LOG=""
  journalctl() { [[ " $* " == *" -o cat "* ]] && printf '%s' "$KERNEL_LOG"; return 0; }
  IGNORE_FAILED_UNITS=""; IGNORE_CRASHES=""
  SINCE=0
  CRASH_LOGS="$BATS_TEST_TMPDIR/nginx-error.log $BATS_TEST_TMPDIR/apache-error.log $BATS_TEST_TMPDIR/php*-fpm.log"
}

@test "no failed unit: none, no alert" {
  check_services || true
  run report
  [[ $output == *"Failed units: none"* ]]
  [[ $output != *"without an alert"* ]]
  run alerts
  [ -z "$output" ]
}

@test "a failed unit raises an alert" {
  FAILED_UNITS="postfix.service"
  check_services || true
  run alerts
  [ "$output" = "Service(s) failed: postfix.service" ]
}

@test "a failed rc-local.service: a line, no alert (the daily check rclocal judges rc.local)" {
  FAILED_UNITS="rc-local.service postfix.service"
  check_services || true
  run report
  [[ $output == *"Failed units: postfix.service"* ]]
  [[ $output == *"rc-local.service failed at boot – see rc.local in the daily checks (no alert of its own)"* ]]
  [[ $output != *"systemctl status rc-local"* ]]   # explained once, in the daily check
  run alerts
  [ "$output" = "Service(s) failed: postfix.service" ]
}

@test "IGNORE_FAILED_UNITS: still listed, no alert; names without .service and patterns" {
  FAILED_UNITS="sync-old.service backup-nightly.service postfix.service"
  IGNORE_FAILED_UNITS="sync-old backup-*"
  check_services || true
  run report
  [[ $output == *"Failed units: postfix.service"* ]]
  [[ $output == *"Failed units without an alert (IGNORE_FAILED_UNITS): sync-old.service backup-nightly.service"* ]]
  run alerts
  [ "$output" = "Service(s) failed: postfix.service" ]
}

@test "all failed units ignored: none, no alert" {
  FAILED_UNITS="backup-nightly.service"
  IGNORE_FAILED_UNITS="backup-nightly.service"
  check_services || true
  run report
  [[ $output == *"Failed units: none"* ]]
  [[ $output == *"(IGNORE_FAILED_UNITS): backup-nightly.service"* ]]
  run alerts
  [ -z "$output" ]
}

@test "no crash: none, no alert" {
  check_services || true
  run report
  [[ $output == *"Crashes: none"* ]]
  run alerts
  [ -z "$output" ]
}

@test "nginx worker crashes: kernel log and error log count once, critical alert" {
  KERNEL_LOG='nginx[2101]: segfault at 0 ip 000055d1c3a0b2f1 sp 00007ffd4c1e2a10 error 4 in nginx[55d1c39f0000+120000]
nginx[2102]: segfault at 8 ip 000055d1c3a0b2f1 sp 00007ffd4c1e2a10 error 4 in nginx[55d1c39f0000+120000]
'
  cat >"$BATS_TEST_TMPDIR/nginx-error.log" <<'L'
2026/11/18 10:01:02 [alert] 2000#2000: worker process 2101 exited on signal 11
2026/11/18 10:01:03 [alert] 2000#2000: worker process 2102 exited on signal 11 (core dumped)
2026/11/18 10:05:00 [alert] 2000#2000: worker process 2103 exited on signal 9
L
  check_services || true
  run report
  [[ $output == *"Crashes: nginx 2× (SIGSEGV)"* ]]
  [[ $output == *"an attack on a memory bug"* ]]
  run alerts
  [[ $output == "Crash: nginx 2× (SIGSEGV) – an attack on a memory bug, or a faulty module? Install updates, see the error log" ]]
  [ "$(alert_severity "${ALERTS[0]}")" = critical ]
}

@test "Apache and PHP-FPM crashes from their logs; a kill (signal 9) is not a crash" {
  cat >"$BATS_TEST_TMPDIR/apache-error.log" <<'L'
[Wed Nov 18 10:00:00.123456 2026] [core:notice] [pid 900] AH00052: child pid 1234 exit signal Segmentation fault (11)
[Wed Nov 18 10:00:01.123456 2026] [core:notice] [pid 900] AH00052: child pid 1235 exit signal Aborted (6)
L
  cat >"$BATS_TEST_TMPDIR/php8.3-fpm.log" <<'L'
[18-Nov-2026 10:00:00] WARNING: [pool example.com] child 4321 exited on signal 11 (SIGSEGV - core dumped) after 12.5 seconds from start
[18-Nov-2026 10:00:05] WARNING: [pool example.com] child 4322 exited on signal 9 (SIGKILL) after 30.0 seconds from start
L
  check_services || true
  run report
  [[ $output == *"Crashes: apache 2× (SIGSEGV SIGABRT), php-fpm 1× (SIGSEGV)"* ]]
  run alerts
  [[ $output == "Crash: apache 2× (SIGSEGV SIGABRT), php-fpm 1× (SIGSEGV) – "* ]]
}

@test "a crash only in the kernel log: name as the kernel writes it (php-fpm8.3 → php-fpm), warning" {
  KERNEL_LOG='traps: php-fpm8.3[777] general protection fault ip:7f00 sp:7ffd error:0 in libc.so.6
traps: someprog[778] trap invalid opcode ip:401000 sp:7ffd error:0 in someprog[400000+1000]
'
  check_services || true
  run report
  [[ $output == *"Crashes: php-fpm 1× (SIGSEGV), someprog 1× (SIGILL)"* ]]
  [ "$(alert_severity "${ALERTS[0]}")" = warning ]
}

@test "IGNORE_CRASHES: still listed, no alert" {
  KERNEL_LOG='php-fpm8.3[777]: segfault at 0 ip 0 sp 0 error 4 in opcache.so
'
  IGNORE_CRASHES="php-fpm"
  check_services || true
  run report
  [[ $output == *"Crashes: none"* ]]
  [[ $output == *"Crashes without an alert (IGNORE_CRASHES): php-fpm 1× (SIGSEGV)"* ]]
  run alerts
  [ -z "$output" ]
}
