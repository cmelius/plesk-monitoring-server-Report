#!/usr/bin/env bats
# check_firewall: databases and the Plesk installer reachable from outside – what listens where (ss)
# and what the Plesk Firewall allows (plesk ext firewall --list-json, rules from a real server)

load helper

setup() {
  load_script
  SS="$FIX/firewall/ss-local.txt"; RULES="$FIX/firewall/rules.json"; ENABLED=enabled
  ss() { cat "$SS"; }
  plesk() {
    case $* in
      "ext firewall --is-enabled") echo "$ENABLED" ;;
      "ext firewall --list-json") cat "$RULES" ;;
    esac
  }
}

# rules.json with the rule of CLASS set to ACTION and FROM ("" = key present but empty, - = no key)
rule() {
  RULES="$BATS_TEST_TMPDIR/rules.json"
  python3 - "$FIX/firewall/rules.json" "$RULES" "$@" <<'PY'
import json, sys
src, dst, cls, act, frm = sys.argv[1:6]
r = json.load(open(src))
for x in r:
    if x["class"] == cls:
        x["action"] = act
        if frm == "-": x.pop("from", None)
        else: x["from"] = frm
open(dst, "w").write(json.dumps(r, indent=4).replace("/", "\\/"))
PY
}
listen() {   # listen ADDRESS:PORT … – ss output with these listening sockets
  SS="$BATS_TEST_TMPDIR/ss.txt"
  echo "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process" >"$SS"
  for a in "$@"; do echo "LISTEN 0      80     $a        0.0.0.0:*    users:((\"x\",pid=1,fd=3))" >>"$SS"; done
}

@test "fw_rules: class, direction, action and sources of every rule" {
  run fw_rules <"$FIX/firewall/rules.json"
  [[ $output == *$'mysql\tinput\tdeny\t'* ]]
  [[ $output == *$'autoinstaller\tinput\tallow\t'* ]]
  [[ $output == *$'catchall\tinput\tdeny\t'* ]]
  [ "$(grep -c . <<<"$output")" -eq 8 ]
}

@test "fw_reach: no sources = everyone, sources = only them (or everyone but them)" {
  rule mysql allow "198.51.100.7, 203.0.113.0/24"
  FW_RULES=$(fw_rules <"$RULES")
  [ "$(fw_reach mysql)" = "only: 198.51.100.7, 203.0.113.0/24" ]
  [ "$(fw_reach postgresql)" = none ]
  [ "$(fw_reach autoinstaller)" = all ]
  [ "$(fw_reach smtp)" = none ]                      # no rule: the catch-all input rule
  rule mysql deny 198.51.100.7
  FW_RULES=$(fw_rules <"$RULES")
  [ "$(fw_reach mysql)" = "all except: 198.51.100.7" ]
}

@test "the real server: MariaDB only local, installer allowed from everywhere – recommendation, no alert" {
  check_firewall >"$BODY"
  run report
  [[ $output == *"Reachable from outside (databases, Plesk installer) – rules of the Plesk Firewall:"* ]]
  [[ $output == *"MySQL/MariaDB (3306): listens only locally (127.0.0.1) – not reachable from outside"* ]]
  [[ $output == *"PostgreSQL (5432): not listening"* ]]
  [[ $output == *"Plesk installer (8447, runs only while used): the firewall allows it from everywhere"* ]]
  [[ $output == *"Recommendation: allow it only from your own addresses"* ]]
  [[ $output == *"not visible from here"* ]]
  run alerts
  [ -z "$output" ]
}

@test "WARN_INSTALLER_OPEN=0: the line without recommendation" {
  WARN_INSTALLER_OPEN=0
  listen 0.0.0.0:8447
  check_firewall >"$BODY"
  run report
  [[ $output == *"Plesk installer (8447, runs only while used): the firewall allows it from everywhere"* ]]
  [[ $output != *"Recommendation"* ]]
}

@test "installer allowed only from own addresses, or blocked" {
  rule autoinstaller allow 198.51.100.7
  check_firewall >"$BODY"
  run report
  [[ $output == *"Plesk installer (8447, runs only while used): the firewall allows it only from 198.51.100.7"* ]]
  [[ $output != *"Recommendation"* ]]
  rule autoinstaller deny ""
  : >"$BODY"; check_firewall >"$BODY"
  run report
  [[ $output == *"the firewall blocks it (updates over SSH: plesk installer)"* ]]
}

@test "MySQL on all addresses, firewall open to everyone: warning with the Plesk setting" {
  listen '*:3306' '[::]:3306'
  rule mysql allow -
  check_firewall >"$BODY"
  run report
  [[ $output == *"MySQL/MariaDB (3306): listens on *, [::], the firewall allows it from everywhere – reachable from the internet"* ]]
  [[ $output == *'untick "Allow local MySQL server to accept external connections"'* ]]
  run alerts
  [[ $output == *"Database: MySQL/MariaDB listens on *, [::] and the firewall allows port 3306 from everywhere"* ]]
}

@test "MySQL on all addresses, firewall blocks it or allows a few: no alert" {
  listen 0.0.0.0:3306
  check_firewall >"$BODY"
  run report
  [[ $output == *"MySQL/MariaDB (3306): listens on 0.0.0.0, the firewall blocks it – Recommendation: let it listen only locally"* ]]
  rule mysql allow 198.51.100.7
  : >"$BODY"; check_firewall >"$BODY"
  run report
  [[ $output == *"listens on 0.0.0.0, the firewall allows it only from 198.51.100.7"* ]]
  run alerts
  [ -z "$output" ]
}

@test "firewall allows everyone except some: still a warning" {
  listen 0.0.0.0:3306
  rule mysql deny 198.51.100.7
  check_firewall >"$BODY"
  run report
  [[ $output == *"the firewall allows it from everywhere except 198.51.100.7"* ]]
  run alerts
  [[ $output == *"Database: MySQL/MariaDB"* ]]
}

@test "PostgreSQL open: warning without the MySQL setting" {
  listen 0.0.0.0:5432
  rule postgresql allow -
  check_firewall >"$BODY"
  run report
  [[ $output == *"PostgreSQL (5432): listens on 0.0.0.0, the firewall allows it from everywhere"* ]]
  [[ $output != *"Allow local MySQL"* ]]
  run alerts
  [[ $output == *"Database: PostgreSQL listens on 0.0.0.0 and the firewall allows port 5432"* ]]
}

@test "Plesk Firewall off: databases on all addresses not rated, no alert" {
  ENABLED=disabled
  listen 0.0.0.0:3306
  check_firewall >"$BODY"
  run report
  [[ $output == *"Reachable from outside (databases, Plesk installer):"* ]]
  [[ $output == *"listens on 0.0.0.0 – firewall not checked (no Plesk Firewall): make sure port 3306 is filtered"* ]]
  [[ $output == *"Plesk installer (8447, runs only while used): Plesk Firewall not enabled or not installed – not checked"* ]]
  run alerts
  [ -z "$output" ]
}

@test "no Plesk: databases only, no installer line" {
  unset -f plesk
  command() { if [[ $1 == -v && $2 == plesk ]]; then return 1; fi; builtin command "$@"; }
  listen 127.0.0.1:3306
  check_firewall >"$BODY"
  run report
  [[ $output == *"MySQL/MariaDB (3306): listens only locally (127.0.0.1)"* ]]
  [[ $output == *"Reachable from outside (databases):"* ]]
  [[ $output != *"Plesk installer (8447"* ]]
}

@test "IPv6 loopback and a public address" {
  listen '[::1]:3306' 203.0.113.10:3306
  run check_firewall
  [[ $output == *"MySQL/MariaDB (3306): listens on 203.0.113.10, the firewall blocks it"* ]]
}

@test "FIREWALL_CHECK=0 switches it off" {
  FIREWALL_CHECK=0
  ! check_enabled firewall
}
