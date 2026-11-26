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
  IPT=""; IPT6=""; SETS=""; V6=""; NFT=""     # no kernel rules unless a test sets them
  iptables-save() { [[ -n $IPT ]] && grep -v '^#' "$IPT"; return 0; }
  ip6tables-save() { [[ -n $IPT6 ]] && cat "$IPT6"; return 0; }
  ipset() { [[ -n $SETS ]] && printf '%s\n' "$SETS"; return 0; }
  nft() { [[ -n $NFT ]] && printf '%s\n' "$NFT"; return 0; }
  ip() { [[ -n $V6 ]] && echo "2: eth0    inet6 $V6/64 scope global"; return 0; }
}
# the real kernel rules with LINE inserted at the top of INPUT (or appended to chain CHAIN: "CHAIN LINE")
ipt() {
  IPT="$BATS_TEST_TMPDIR/iptables.txt"; cp "$FIX/firewall/iptables-save.txt" "$IPT"
  local l; for l in "$@"; do sed -i "0,/^-A INPUT /s||$l\n-A INPUT |" "$IPT"; done
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

@test "fw_reach: the rule covering the port – no sources = everyone, sources = only them (or everyone but them)" {
  rule mysql allow "198.51.100.7, 203.0.113.0/24"
  FW_RULES=$(fw_rules <"$RULES")
  [ "$(fw_reach 3306)" = "only: 198.51.100.7, 203.0.113.0/24" ]
  [ "$(fw_reach 5432)" = none ]
  [ "$(fw_reach 8447)" = all ]
  [ "$(fw_reach 50000)" = none ]                     # inside the passive FTP range 49152-65535
  [ "$(fw_reach 25)" = none ]                        # no rule: the catch-all input rule
  rule mysql deny 198.51.100.7
  FW_RULES=$(fw_rules <"$RULES")
  [ "$(fw_reach 3306)" = "all except: 198.51.100.7" ]
}

@test "the real server: MariaDB only local, installer allowed from everywhere – recommendation, no alert" {
  check_firewall >"$BODY"
  run report
  [[ $output == *"Reachable from outside (databases, Plesk installer) – rules of the Plesk Firewall:"* ]]
  [[ $output == *"MySQL/MariaDB (3306): listens only locally (127.0.0.1) – not reachable from outside"* ]]
  [[ $output == *"PostgreSQL (5432): not listening"* ]]
  [[ $output == *"Plesk installer (8447, runs only while used): the firewall allows it from everywhere"* ]]
  [[ $output == *"Recommendation: allow it only from your own addresses"* ]]
  [[ $output == *'rule'*'"Plesk installer": Sources, or Action "Deny"'* ]]
  [[ $output == *"update over SSH as root: plesk installer --select-release-latest --upgrade-installed-components"* ]]
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
  [[ $output == *"the firewall blocks it (updates over SSH: plesk installer --select-release-latest --upgrade-installed-components)"* ]]
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

@test "fw_procports: the ports a database process listens on, from ss -p" {
  run fw_procports 'mysqld|mariadbd' <"$FIX/firewall/ss-local.txt"
  [ "$output" = 3306 ]
  run fw_procports 'postgres|postmaster' <"$FIX/firewall/ss-local.txt"
  [ -z "$output" ]
}

@test "MariaDB on another port: checked on that port, with the firewall rule for it (none here: catch-all)" {
  SS="$BATS_TEST_TMPDIR/ss.txt"
  echo 'LISTEN 0      80           0.0.0.0:3307       0.0.0.0:*    users:(("mariadbd",pid=824,fd=127))' >"$SS"
  check_firewall >"$BODY"
  run report
  [[ $output == *"MySQL/MariaDB (3307): listens on 0.0.0.0, the firewall blocks it"* ]]
  [[ $output != *"(3306)"* ]]
  run alerts
  [ -z "$output" ]
}

@test "MariaDB on another port the firewall allows from everywhere: warning for that port" {
  SS="$BATS_TEST_TMPDIR/ss.txt"
  echo 'LISTEN 0      80           0.0.0.0:3307       0.0.0.0:*    users:(("mariadbd",pid=824,fd=127))' >"$SS"
  RULES="$BATS_TEST_TMPDIR/rules.json"
  python3 - "$FIX/firewall/rules.json" "$RULES" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
r.insert(0, {"type": "service", "class": "custom-db", "direction": "input", "ports": "3307/tcp", "action": "allow", "id": 1})
open(sys.argv[2], "w").write(json.dumps(r, indent=4).replace("/", "\\/"))
PY
  check_firewall >"$BODY"
  run report
  [[ $output == *"MySQL/MariaDB (3307): listens on 0.0.0.0, the firewall allows it from everywhere – reachable from the internet"* ]]
  run alerts
  [[ $output == *"Database: MySQL/MariaDB listens on 0.0.0.0 and the firewall allows port 3307 from everywhere"* ]]
}

@test "kfw_reach: the kernel's rules of a real server – catch-all DROP, ports allowed; fail2ban bans, loopback and state rules don't count" {
  KFW_SETS=""
  [ "$(kfw_reach 3306 <"$FIX/firewall/iptables-save.txt")" = none ]
  [ "$(kfw_reach 8447 <"$FIX/firewall/iptables-save.txt")" = all ]
  [ "$(kfw_reach 22 <"$FIX/firewall/iptables-save.txt")" = all ]       # through f2b-recidive and f2b-ssh, bans ignored
  [ "$(kfw_reach 993 <"$FIX/firewall/iptables-save.txt")" = all ]
  [ "$(kfw_reach 50000 <"$FIX/firewall/iptables-save.txt")" = none ]   # inside 49152:65535
  [ "$(kfw_reach 4000 <"$FIX/firewall/iptables-save.txt")" = none ]    # no rule: the last DROP
  # a ban outside fail2ban (a rule by hand) is a rule about the port
  [ "$(kfw_reach 22 <<<"$(sed 's/^-A INPUT -p tcp -j f2b-recidive$/&\n-A INPUT -s 203.0.113.5\/32 -j DROP/' "$FIX/firewall/iptables-save.txt")")" = "all except: 203.0.113.5" ]
}

@test "kfw_reach: sources and ipsets decide only for themselves, a range, policy ACCEPT without rules" {
  ipt "-A INPUT -s 198.51.100.7/32 -p tcp -m tcp --dport 3306 -j ACCEPT" \
      "-A INPUT -p tcp -m multiport --dports 5000:5500,3306 -m set --match-set trusted src -j ACCEPT"
  KFW_SETS="trusted 2"
  [ "$(kfw_reach 3306 <"$IPT")" = "only: ipset trusted (2 entries), 198.51.100.7" ]
  [ "$(kfw_reach 5432 <"$IPT")" = "only: ipset trusted (2 entries)" ]
  [ "$(kfw_reach 5432 <<<$'*filter\n:INPUT ACCEPT [0:0]\nCOMMIT')" = all ]
  # rate limits can't be judged: an ACCEPT counts, a DROP doesn't
  ipt "-A INPUT -p tcp --dport 3306 -m limit --limit 5/min -j ACCEPT"
  [ "$(kfw_reach 3306 <"$IPT")" = all ]
  ipt "-A INPUT -p tcp --dport 8447 -m recent --rcheck -j DROP"
  [ "$(kfw_reach 8447 <"$IPT")" = all ]
}

@test "kernel rules win: the Plesk Firewall blocks MySQL, but a rule added by hand lets everyone in – warning and a note" {
  listen 0.0.0.0:3306
  ipt "-A INPUT -p tcp -m tcp --dport 3306 -j ACCEPT"
  check_firewall >"$BODY"
  run report
  [[ $output == *"Reachable from outside (databases, Plesk installer) – firewall rules in the kernel (iptables):"* ]]
  [[ $output == *"MySQL/MariaDB (3306): listens on 0.0.0.0, the firewall allows it from everywhere – reachable from the internet"* ]]
  [[ $output == *"note: the Plesk Firewall's rule blocks port 3306, but the kernel's rules let everyone in"* ]]
  run alerts
  [[ $output == *"Database: MySQL/MariaDB listens on 0.0.0.0 and the firewall allows port 3306 from everywhere"* ]]
}

@test "kernel rules: the real server – same answers as the Plesk Firewall, no note" {
  ipt
  check_firewall >"$BODY"
  run report
  [[ $output == *"firewall rules in the kernel (iptables)"* ]]
  [[ $output == *"MySQL/MariaDB (3306): listens only locally (127.0.0.1)"* ]]
  [[ $output == *"Plesk installer (8447, runs only while used): the firewall allows it from everywhere"* ]]
  [[ $output != *"note:"* ]]
  run alerts
  [ -z "$output" ]
}

@test "kernel rules: the Plesk Firewall allows the installer, the kernel blocks it – a note" {
  ipt "-A INPUT -p tcp -m tcp --dport 8447 -j DROP"
  check_firewall >"$BODY"
  run report
  [[ $output == *"Plesk installer (8447, runs only while used): the firewall blocks it"* ]]
  [[ $output == *"note: the Plesk Firewall's rule allows port 8447 from everywhere, but the kernel's rules don't"* ]]
}

@test "kernel rules: listening on IPv6 without ip6tables rules, with a global IPv6 address – open over IPv6" {
  listen 0.0.0.0:3306 '[::]:3306'
  ipt; V6=2001:db8::10
  check_firewall >"$BODY"
  run report
  [[ $output == *"the firewall allows it over IPv4 for nobody, over IPv6 from everywhere: from everywhere – reachable from the internet"* ]]
  run alerts
  [[ $output == *"Database: MySQL/MariaDB listens on 0.0.0.0, [::]"* ]]
  # no global IPv6 address: IPv6 doesn't count
  V6=""; ALERTS=(); : >"$DALERTS"; : >"$BODY"
  check_firewall >"$BODY"
  run report
  [[ $output == *"listens on 0.0.0.0, [::], the firewall blocks it"* ]]
}

@test "kernel rules: other nftables tables (firewalld) are named, not read" {
  ipt; NFT=$'table ip filter\ntable inet firewalld\ntable ip6 filter'
  check_firewall >"$BODY"
  run report
  [[ $output == *"(nftables has more tables: inet firewalld – their rules are not read here; nft list ruleset shows them)"* ]]
}

@test "kernel rules without nft installed (Debian with iptables-nft): no error, no nftables line" {
  ipt; unset -f nft
  command() { if [[ $1 == -v && $2 == nft ]]; then return 1; fi; builtin command "$@"; }
  check_firewall >"$BODY"
  run report
  [[ $output == *"Plesk installer (8447, runs only while used): the firewall allows it from everywhere"* ]]
  [[ $output != *nftables* ]]
}
