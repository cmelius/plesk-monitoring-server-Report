#!/usr/bin/env bats
# check_php: PHP versions per domain, installed and in service plans, with the end of security
# support from PHP_EOL, php.net (states.php), the built-in table or php.net's schedule. Handlers from
# a real server (plus an OS vendor handler), domains and plans with invented names

load helper

setup() {
  load_script
  STATE_DIR="$BATS_TEST_TMPDIR/state"; mkdir -p "$STATE_DIR"
  P="$FIX/php"; DOMS="$P/domains.txt"; PLANS="$P/plans.txt"; HANDLERS="$P/handlers.txt"; STATES="$P/states.json"
  TODAY=2026-11-23; CURLS=0
  plesk() {
    case $* in
      "bin php_handler --list") cat "$HANDLERS" ;;
      db*Templates*)            cat "$PLANS" ;;
      db*hosting*)              cat "$DOMS" ;;
    esac
  }
  curl() { CURLS=$((CURLS + 1)); echo "$CURLS" >"$BATS_TEST_TMPDIR/curls"; cat "$STATES"; }
  date() { if [[ $* == +%F ]]; then echo "$TODAY"; else command date "$@"; fi; }
}

@test "php_states: version=date for every branch with a date, from php.net's JSON" {
  run php_states <"$P/states.json"
  [[ $output == *"8.1=2025-12-31"* && $output == *"8.6=2030-12-31"* && $output == *"7.4=2022-11-28"* ]]
  [[ $output != *"3.0"* ]]
}

@test "the real server: 8.4 and 8.5 supported, 8.3 only in reseller plans, old OS PHP installed and unused" {
  check_php >"$BODY"
  run report
  [[ $output == *"PHP versions (security support per https://www.php.net; domains with PHP: 3):"* ]]
  [[ $output == *"8.4 (8.4.28) – 2 domain(s), supported until 2028-12-31 (php.net)"* ]]
  [[ $output == *"8.5 (8.5.13) – 1 domain(s), supported until 2029-12-31 (php.net)"* ]]
  [[ $output == *"8.3 (8.3.37) – no domain, but the default of 2 service plan(s): Unlimited (reseller reseller1), Default Domain (reseller reseller2) – supported until 2027-12-31 (php.net)"* ]]
  [[ $output == *"7.4 (7.4.33) – installed, used by no domain and no service plan – WITHOUT security support since 2022-11-28 (php.net)"* ]]
  [[ $output == *"Recommendation: remove it"* ]]
  run alerts
  [[ $output != *"PHP:"* ]]
}

@test "first check: every domain without support named once, not again the next day" {
  printf 'a.example\tplesk-php84-fpm-dedicated\nold.example\tfpm\n' >"$BATS_TEST_TMPDIR/d.txt"; DOMS="$BATS_TEST_TMPDIR/d.txt"
  check_php >"$BODY"
  run report
  [[ $output == *"7.4 (7.4.33) – 1 domain(s), WITHOUT security support since 2022-11-28 (php.net): old.example"* ]]
  run alerts
  [[ $output == *"PHP: 1 domain(s) now use a PHP version without security support: old.example (7.4)"* ]]
  : >"$BODY"; rm -f "$DALERTS"
  check_php >"$BODY"
  run alerts
  [[ $output != *"PHP:"* ]]
}

@test "a version that loses its support: one alert on that day" {
  TODAY=2026-12-30
  check_php >/dev/null
  TODAY=2027-01-01
  printf '8.4=2026-12-31\n' >"$BATS_TEST_TMPDIR/x"; PHP_EOL="8.4=2026-12-31"
  rm -f "$DALERTS"; check_php >"$BODY"
  run alerts
  [[ $output == *"PHP: 2 domain(s) now use a PHP version without security support: a.example (8.4), b.example (8.4)"* ]]
}

@test "support ends within 90 days: named with the domains, no alert" {
  TODAY=2026-10-15
  printf 'x.example\tplesk-php82-fpm\n' >"$BATS_TEST_TMPDIR/d.txt"; DOMS="$BATS_TEST_TMPDIR/d.txt"
  check_php >"$BODY"
  run report
  [[ $output == *"8.2 – 1 domain(s), security support ends 2026-12-31 (php.net) – within 90 days: x.example"* ]]
  run alerts
  [[ $output != *"PHP:"* ]]
}

@test "PHP_EOL wins over php.net; an unknown 8.x is estimated, PHP 9 unknown" {
  PHP_EOL="8.5=2030-06-30"
  printf 'a.example\tplesk-php85-fpm\nb.example\tplesk-php87-fpm\nc.example\tplesk-php90-fpm\n' >"$BATS_TEST_TMPDIR/d.txt"; DOMS="$BATS_TEST_TMPDIR/d.txt"
  check_php >"$BODY"
  run report
  [[ $output == *"8.5 (8.5.13) – 1 domain(s), supported until 2030-06-30 (PHP_EOL)"* ]]
  [[ $output == *"8.7 – 1 domain(s), supported until 2031-12-31 (estimated)"* ]]
  [[ $output == *"9.0 – 1 domain(s), support end unknown"* ]]
  [[ $output == *'add it to PHP_EOL, e.g. PHP_EOL="9.0=YYYY-12-31"'* ]]
}

@test "php.net fetched at most once a day; kept when it can't be reached; PHP_EOL_ONLINE=0 never" {
  check_php >/dev/null; check_php >/dev/null
  [ "$(cat "$BATS_TEST_TMPDIR/curls")" = 1 ]
  [ -s "$STATE_DIR/php_eol" ]
  touch -d '2 days ago' "$STATE_DIR/php_eol"
  curl() { return 22; }
  run check_php
  [[ $output == *"(php.net)"* ]]
  rm -f "$STATE_DIR/php_eol"; PHP_EOL_ONLINE=0
  curl() { echo called >"$BATS_TEST_TMPDIR/called"; }
  run check_php
  [ ! -e "$BATS_TEST_TMPDIR/called" ]
  [[ $output == *"8.4 (8.4.28) – 2 domain(s), supported until 2028-12-31 (built-in)"* ]]
}

@test "a broken answer from php.net is not used" {
  STATES="$BATS_TEST_TMPDIR/bad.json"; echo '<html>maintenance</html>' >"$STATES"
  run check_php
  [ ! -s "$STATE_DIR/php_eol" ]
  [[ $output == *"(built-in)"* ]]
}

@test "without Plesk: the php command's version" {
  command() { if [[ $1 == -v && $2 == plesk ]]; then return 1; fi; builtin command "$@"; }
  php() { echo 8.1; }
  run check_php
  [[ $output == *"PHP (php command, no Plesk): 8.1 – WITHOUT security support since 2025-12-31 (php.net)"* ]]
}

@test "PHP_CHECK=0 switches it off" {
  PHP_CHECK=0
  ! check_enabled php
}
