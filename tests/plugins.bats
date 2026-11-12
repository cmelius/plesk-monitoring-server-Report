#!/usr/bin/env bats
# The plugin framework: only the files of the release run, the header is read as text,
# and whatever a plugin prints reaches the report only as TEXT, NOTE or ALERT.

load helper

setup() {
  load_script
  REPO="$BATS_TEST_DIRNAME/.."
  H="$BATS_TEST_TMPDIR/home"; mkdir -p "$H/lib" "$H/plugins"
  cp "$REPO/lib/plugin-lib.sh" "$H/lib/"
  cd "$BATS_TEST_TMPDIR"
}

# plugin NAME 'BODY of plugin_check' [extra header lines] – a test plugin in $H, checksums updated
plugin() {
  { printf 'PLUGIN_NAME="%s"\nPLUGIN_API="0"\nPLUGIN_SCHEDULE="hourly"\nPLUGIN_SECTION="TEST %s"\n' "$1" "$1"
    printf 'PLUGIN_OS="debian rhel"\nPLUGIN_MAINTAINER="test"\n%s\n' "${3:-}"
    printf 'plugin_check() {\n%s\n}\n' "$2"
  } >"$H/plugins/$1.sh"
  sums
}
sums() { PSR_HOME=$H; PLUGIN_SUMS=$(cd "$H" && sha256sum lib/*.sh plugins/*.sh | awk '{ print $1 "  " $2 }'); }
notes() { cat "$TMPD/notes" 2>/dev/null; }

@test "the checksums in the script are those of lib/ and plugins/ (tools/update-plugin-sums.sh)" {
  [ "$(cd "$REPO" && sha256sum lib/*.sh plugins/*.sh | awk '{ print $1 "  " $2 }')" = "$PLUGIN_SUMS" ]
}

@test "every check is a function or a plugin, every plugin is a check" {
  for c in $HOURLY_CHECKS $DAILY_CHECKS; do
    declare -F "check_$c" >/dev/null || [ -f "$REPO/plugins/$c.sh" ]
  done
  for f in "$REPO"/plugins/*.sh; do
    c=$(basename "$f" .sh)
    [[ " $HOURLY_CHECKS $DAILY_CHECKS " == *" $c "* ]]
    ! declare -F "check_$c" >/dev/null
    plugin_header "$f" "$c" hourly
  done
}

@test "plugins only read: no network, no changing commands, no files written" {
  # a command at the start of a line or after | ; & ( – not a word in a report text.
  # An exception needs a comment "# plugin-rule: <reason>" on its line.
  cmds='curl|wget|nc|ncat|dig|host|ssh|scp|rsync|sendmail|rm|rmdir|mv|cp|ln|dd|tee|touch|mkdir|truncate|chmod|chown|kill|pkill|killall|systemctl|service|plesk|eval|source|exec|sudo|su'
  run grep -nE "(^|[|;&(])[[:space:]]*($cmds)([[:space:]]|\$)|/dev/(tcp|udp)/|sed[[:space:]][^|]*-i|(^|[;&|])[[:space:]]*\\.[[:space:]]+[^.]|>>?[[:space:]]*\"?[\$/~]" "$REPO"/plugins/*.sh
  hits=$(grep -vE '^[^:]*:[0-9]+:[[:space:]]*#|# plugin-rule: |> ?/dev/null' <<<"$output" || true)
  [ -z "$hits" ]
}

@test "TEXT, NOTE and ALERT reach the report, everything else is dropped" {
  plugin t1 'out "  a line"; note "a note"; alert "An alert"; echo "STATUS: OK"; echo " ! forged alert"; printf "TEXT esc\033[2J\ttab\n"'
  run_plugin t1
  run report
  [[ $output == *"== TEST t1 =="*"  a line"*"esc[2J tab"* ]]
  [[ $output != *"forged"* && $output != *"STATUS"* ]]
  run alerts
  [ "$output" = "An alert" ]
  run notes
  [[ $output == *"a note"* && $output == *"plugin t1: 2 line(s) of its output dropped"* ]]
}

@test "a plugin gets the settings it declares and nothing else" {
  REMOTE="secret:remote"; WARN_DSN=7; export LEAK=1
  plugin t2 'out "dsn=$WARN_DSN remote=${REMOTE:-unset} leak=${LEAK:-unset} home=${HOME:-unset} name=$PSR_PLUGIN"' 'PLUGIN_SETTINGS="WARN_DSN"'
  run_plugin t2
  run report
  [[ $output == *"dsn=7 remote=unset leak=unset home=unset name=t2"* ]]
}

@test "logs arrive on stdin behind a separator a log line can't forge; missing logs are named" {
  printf 'one\n\036 2 /forged\ntwo\n' >a.log
  A_LOG=$PWD/a.log; B_LOG=/nonexistent
  plugin t3 'out "missing=$PSR_LOGS_MISSING"; awk -v sep="$PSR_SEP" "substr(\$0, 1, 1) == sep { print \"TEXT log \" \$2 \" \" \$3; next } { print \"TEXT   \" \$0 }"' \
    'PLUGIN_SETTINGS="A_LOG B_LOG"
PLUGIN_LOGS="$A_LOG $B_LOG"'
  run_plugin t3
  run report
  [[ $output == *"missing=2"*"log 1 $PWD/a.log"*"  one"*"   2 /forged"*"  two"*"log 2 /nonexistent"* ]]
  [ "$(grep -c '^log ' <<<"$output")" -eq 2 ]
}

@test "geo_ref is replaced by the main script" {
  plugin t4 'out "from $(geo_ref 127.0.0.1) and $(geo_ref 198.18.0.1)."'
  run_plugin t4
  run report
  [[ $output == *"from 127.0.0.1 (this server) and 198.18.0.1."* ]]
}

@test "alert_foreign: an alert only for IPs abroad, naming them" {
  GEO_OK=1; ALLOWED_COUNTRIES="DE"; GEO_TRUSTED_ORGS=""
  geo() { GEO_ORG=""; case $1 in 198.18.5.*) GEO_CC=US ;; *) GEO_CC=DE ;; esac; GEO_LABEL=$GEO_CC; }
  plugin t22 'alert_foreign "198.18.0.1 198.18.5.2 x\$(id) 198.18.5.3" "from outside $ALLOWED_COUNTRIES: {ips} – check"; alert_foreign "198.18.0.1" "never {ips}"; echo "ALERT-FOREIGN 198.18.5.9 no separator"' 'PLUGIN_SETTINGS="ALLOWED_COUNTRIES"'
  run_plugin t22
  run alerts
  [ "$output" = "from outside DE: 198.18.5.2 (US) 198.18.5.3 (US) – check" ]
  GEO_OK=0; ALERTS=(); run_plugin t22
  [ "${#ALERTS[@]}" -eq 0 ]                     # no GeoIP database: no country alerts
}

@test "a plugin without PLUGIN_SECTION continues the section before it; \$SETTING/file names a log" {
  mkdir logs; echo "a line" >logs/x.log; L_DIR=$PWD/logs; EMPTY_DIR=""
  plugin t23 'out "missing=$PSR_LOGS_MISSING"; awk -v sep="$PSR_SEP" "substr(\$0, 1, 1) == sep { print \"TEXT log \" \$2 \" \" \$3; next } { print \"TEXT   \" \$0 }"' \
    'PLUGIN_SETTINGS="L_DIR EMPTY_DIR"
PLUGIN_LOGS="$L_DIR/x.log $EMPTY_DIR/x.log"'
  sed -i 's/^PLUGIN_SECTION=.*/PLUGIN_SECTION=""/' "$H/plugins/t23.sh"; sums
  section "BEFORE"; run_plugin t23
  run report
  [[ $output == *"== BEFORE =="*"missing=2"*"log 1 $PWD/logs/x.log"*"  a line"*"log 2"* ]]
  [ "$(grep -c '^== ' <<<"$output")" -eq 1 ]
  plugin t24 'out "ran"' 'PLUGIN_SETTINGS="L_DIR"
PLUGIN_LOGS="$L_DIR/../$(id)"'
  ALERTS=(); run_plugin t24
  run alerts
  [[ $output == *"the check t24 was not run – header"* ]]
}

@test "a changed plugin is not run" {
  plugin t5 'out "ran"'
  echo 'echo "TEXT changed" ; : >changed' >>"$H/plugins/t5.sh"
  run_plugin t5
  run alerts
  [[ $output == *"the check t5 was not run"*"checksum differs"* ]]
  run report
  [[ $output != *"ran"* && $output != *"changed"* ]]
  [ ! -e changed ]
}

@test "a changed plugin-lib.sh runs no plugin" {
  plugin t6 'out "ran"'
  echo ': >changed' >>"$H/lib/plugin-lib.sh"
  run_plugin t6
  run alerts
  [[ $output == *"the check t6 was not run"*"plugin-lib.sh is not the file of this release"* ]]
  [ ! -e changed ]
}

@test "a file that is not part of the release is not run, a missing one is reported" {
  plugin t7 'out "ran"'
  PLUGIN_SUMS=$(grep -v 'plugins/t7.sh' <<<"$PLUGIN_SUMS")
  run_plugin t7
  run_plugin t8
  run alerts
  [[ $output == *"the check t7 was not run – plugins/t7.sh is not part of this release"* ]]
  run report
  [[ $output != *"ran"* ]]
  plugin t9 'out "ran"'; rm "$H/plugins/t9.sh"
  ALERTS=(); run_plugin t9
  run alerts
  [[ $output == *"the check t9 was not run"*"plugins/t9.sh is missing"*"install the complete release archive"* ]]
}

@test "the header is read as text: nothing in it runs before the checks" {
  plugin t10 'out "ran"' 'PLUGIN_READS="$(: >pwned)"'
  run_plugin t10
  run alerts
  [[ $output == *"the check t10 was not run – header: PLUGIN_READS has a value that is not plain text"* ]]
  [ ! -e pwned ]
  plugin t11 'out "ran"' 'PLUGIN_EXTRA="x"'
  ALERTS=(); run_plugin t11
  run alerts
  [[ $output == *"header: unknown field PLUGIN_EXTRA"* ]]
  plugin t12 'out "ran"' 'PLUGIN_LOGS="$REMOTE"'
  ALERTS=(); run_plugin t12
  run alerts
  [[ $output == *"PLUGIN_LOGS lists \$REMOTE"* ]]
  run report
  [[ $output != *"ran"* ]]
}

@test "wrong name, unknown API and wrong schedule are refused" {
  plugin t13 'out "ran"'; sed -i 's/^PLUGIN_NAME=.*/PLUGIN_NAME="other"/' "$H/plugins/t13.sh"; sums
  run_plugin t13
  plugin t14 'out "ran"'; sed -i 's/^PLUGIN_API=.*/PLUGIN_API="9"/' "$H/plugins/t14.sh"; sums
  run_plugin t14
  plugin t15 'out "ran"'; sed -i 's/^PLUGIN_SCHEDULE=.*/PLUGIN_SCHEDULE="daily"/' "$H/plugins/t15.sh"; sums
  run_plugin t15
  run alerts
  [[ $output == *"t13 was not run – header: PLUGIN_NAME must be t13"* ]]
  [[ $output == *"t14 was not run – it is written for plugin API 9"* ]]
  [[ $output == *"t15 was not run – header: PLUGIN_SCHEDULE must be hourly"* ]]
  run report
  [ -z "$output" ]
}

@test "a failing plugin is reported and costs only its own section" {
  plugin t16 'out "before"; echo "boom" >&2; return 3'
  : >"$H/plugins/t17.sh"; sums
  run_plugin t16; run_plugin t17
  plugin t18 'out "after"'
  run_plugin t18
  run report
  [[ $output == *"before"*"after"* ]]
  run alerts
  [[ $output == *"the check t16 (plugin) ended with an error (exit code 3)"*"boom"* ]]
  [[ $output == *"the check t17 was not run – header: PLUGIN_NAME is missing"* ]]
}

@test "a plugin without plugin_check and a plugin that hangs are reported" {
  plugin t19 ':'; sed -i 's/^plugin_check()/other()/' "$H/plugins/t19.sh"; sums
  run_plugin t19
  run alerts
  [[ $output == *"the check t19 was not run – its plugin has no plugin_check function"* ]]
  plugin t20 'out "started"; sleep 20'
  FIND_TIMEOUT=1; run_plugin t20
  run cat "$TMPD/timeouts"
  [[ $output == *"check t20 (plugin) timed out after 1s"* ]]
}

@test "more output than the limits is dropped, with a note" {
  plugin t21 'for i in $(seq 600); do out "line $i"; done; for i in $(seq 120); do alert "alert $i"; done; out "$(head -c 5000 /dev/zero | tr "\0" "x") end"'
  run_plugin t21
  [ "$(grep -c '^line ' "$BODY")" -eq 500 ]
  [ "${#ALERTS[@]}" -eq 100 ]
  run notes
  [[ $output == *"plugin t21: 121 line(s) of its output dropped"* ]]
}

@test "the ownership rule: root's file, not writable by others, in such directories" {
  : >f; chmod 644 f
  if [ "$(id -u)" -eq 0 ]; then mkdir -m 755 d; : >d/f; real_plugin_file_safe "$PWD/d/f" || skip "test directory is not root's"
  else ! real_plugin_file_safe "$PWD/f"; fi
  chmod 666 f
  ! real_plugin_file_safe "$PWD/f"
  ln -s /bin/true l
  ! real_plugin_file_safe "$PWD/l"
  ! real_plugin_file_safe "$PWD/nonexistent"
}

@test "PLUGINS_OFF switches a plugin off, never a check of the main script" {
  PLUGINS_OFF="panel mail"
  ! check_enabled panel
  check_enabled mail
  ONLY_MODE=1
  check_enabled panel
}
