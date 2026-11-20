#!/usr/bin/env bats
# mailauth_scan and check_domaindns: a DNS lookup without answer is "not rated", not "missing";
# domains are checked several at a time, with the same output as one after the other (stubbed dig)

load helper

# DNS data: lines "name type value"; names in DNS_FAIL never answer (timeout)
dns() { printf '%s %s %s\n' "$@" >>"$DNSDB"; }

setup() {
  load_script
  DNSDB="$BATS_TEST_TMPDIR/dns"; : >"$DNSDB"; DNS_FAIL=""
  MAILNAMES_DIR="$BATS_TEST_TMPDIR/mailnames"; DKIM_KEY_DIR="$BATS_TEST_TMPDIR/domainkeys"
  MAILAUTH_IGNORE_DOMAINS=""; MAILAUTH_SHOW_ALL=0; PUBIP6=""; PAR_JOBS=4
  unset -f plesk
  dig() {
    local a short=0 type=A name="" recs
    for a in "$@"; do
      case $a in
        +short) short=1 ;; +*|@*) ;; A|AAAA|MX|TXT|NS|CAA) type=$a ;; *) name=$a ;;
      esac
    done
    if [[ " $DNS_FAIL " == *" $name "* ]]; then
      (( short )) || echo ";; communications error to 1.1.1.1#53: timed out"
      return 9
    fi
    recs=$(awk -v n="$name" -v t="$type" '$1 == n && $2 == t { sub(/^[^ ]+ [^ ]+ /, ""); print }' "$DNSDB")
    if (( short )); then [[ -n $recs ]] && printf '%s\n' "$recs"; return 0; fi
    echo ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1"
    while IFS= read -r a; do [[ -n $a ]] && printf '%s.\t300\tIN\t%s\t%s\n' "$name" "$type" "$a"; done <<<"$recs"
    return 0
  }
  host_has_ip() { [[ $1 == mail.example.com && $2 == "$PUBIP" ]]; }
}

# a domain with a mailbox, MX here, SPF and DMARC; with a DKIM key here and its record in DNS
domain() {
  local d=$1 key
  mkdir -p "$MAILNAMES_DIR/$d/info" "$DKIM_KEY_DIR/$d"
  dns "$d" MX "10 mail.example.com."
  dns "$d" TXT '"v=spf1 ip4:203.0.113.10 -all"'
  dns "_dmarc.$d" TXT '"v=DMARC1; p=none"'
  dns "$d" NS "ns1.example.net."
  openssl genrsa -out "$DKIM_KEY_DIR/$d/default" 1024 2>/dev/null
  key=$(openssl rsa -in "$DKIM_KEY_DIR/$d/default" -pubout -outform DER 2>/dev/null | base64 -w0)
  dns "default._domainkey.$d" TXT "\"v=DKIM1; p=$key\""
}

@test "DKIM lookup without answer: DKIM ?, not rated, no finding" {
  domain d1.example
  DNS_FAIL="default._domainkey.d1.example"
  MAILAUTH_SHOW_ALL=0
  run mailauth_scan
  [[ $output == *"d1.example"*"SPF pass"*"DKIM ?"*"no DNS answer for DKIM – not rated"* ]]
  [[ $output != *MISSING* ]]
  [[ $output == *"1 domain(s) not rated: the name server gave no answer"* ]]
  [[ $output == *"0 domain(s) OK, 0 with findings"* ]]
}

@test "SPF without answer and DKIM missing for real: no alert (SPF not known to fail)" {
  domain d2.example
  sed -i '/^default._domainkey.d2.example /d' "$DNSDB"    # DKIM record really missing
  DNS_FAIL="d2.example"                                      # SPF (TXT of the domain) and MX/NS: no answer
  host_has_ip() { return 0; }
  run mailauth_scan
  [ -z "$(cat "$DALERTS")" ]
}

@test "DKIM record really missing (answer without record): still MISSING" {
  domain d3.example
  sed -i '/^default._domainkey.d3.example /d' "$DNSDB"
  run mailauth_scan
  [[ $output == *"d3.example"*"DKIM MISSING"* ]]
  [[ $output == *"0 domain(s) OK, 1 with findings"* ]]
}

@test "txt_get: a timeout is retried, then counts as no answer" {
  dns ok.example TXT '"v=spf1 -all"'
  txt_get ok.example
  [ "$TXT_FAIL" = 0 ]; [ "$TXT_RECS" = "v=spf1 -all" ]
  txt_get none.example
  [ "$TXT_FAIL" = 0 ]; [ -z "$TXT_RECS" ]
  DNS_FAIL="ok.example"
  txt_get ok.example
  [ "$TXT_FAIL" = 1 ]; [ -z "$TXT_RECS" ]
}

@test "several at a time: output and alerts in the same order as one after the other" {
  local d
  for d in a1.example b2.example c3.example d4.example e5.example f6.example; do domain "$d"; done
  sed -i '/^default._domainkey.c3.example /d; /^default._domainkey.f6.example /d' "$DNSDB"
  sed -i 's/^c3.example TXT .*/c3.example TXT "v=spf1 -all"/; s/^f6.example TXT .*/f6.example TXT "v=spf1 -all"/' "$DNSDB"
  MAILAUTH_SHOW_ALL=1
  PAR_JOBS=1; mailauth_scan >"$BATS_TEST_TMPDIR/seq"; mv "$DALERTS" "$BATS_TEST_TMPDIR/seq.a"; : >"$DALERTS"
  PAR_JOBS=4; mailauth_scan >"$BATS_TEST_TMPDIR/par"
  diff "$BATS_TEST_TMPDIR/seq" "$BATS_TEST_TMPDIR/par"
  diff "$BATS_TEST_TMPDIR/seq.a" "$DALERTS"
  [ "$(grep -c 'neither SPF nor DKIM passes' "$DALERTS")" -eq 2 ]
  grep -q 'c3.example' <(head -1 "$DALERTS")
  [[ $(cat "$BATS_TEST_TMPDIR/par") == *"4 domain(s) OK, 2 with findings"* ]]
}

@test "domaindns several at a time: findings in domain order, refused blocklists collected" {
  site_domains() { printf '%s\n' z1.example y2.example x3.example; }
  cert_scan() { LE_DOMAINS=""; }
  DOMAIN_BLOCKLISTS="dbl.example"
  bl_lookup() { [[ $1 == y2.example.dbl.example ]] && echo 127.0.1.2; [[ $1 == x3.example.dbl.example ]] && echo 127.255.255.254; return 0; }
  dns z1.example A 198.51.100.7
  dns y2.example A 203.0.113.10
  run check_domaindns
  [[ $output == *"  z1.example: website points elsewhere (198.51.100.7) – moved? CDN?"*"  y2.example: LISTED on dbl.example (127.0.1.2)"*"  x3.example: no A record"* ]]
  [[ $output == *"3 domain(s) checked"* ]]
  [[ $output == *"note: some blocklists refused queries from this resolver:  dbl.example"* ]]
  grep -q "domain y2.example is listed on dbl.example" "$DALERTS"
}
