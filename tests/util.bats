#!/usr/bin/env bats
# small helpers

load helper

setup() { load_script; }

@test "fmt_bytes in units of 1024, like Plesk" {
  [ "$(fmt_bytes 1677721600)" = "1.56 GB" ]
  [ "$(fmt_bytes 536870912)" = "512 MB" ]
  [ "$(fmt_bytes 0)" = "0 MB" ]
}

@test "maildir_used sums all lines after the header" {
  [ "$(maildir_used "$FIX/mailboxes/d1.example/info/Maildir/maildirsize")" = 1153430021 ]
  [ "$(maildir_used "$BATS_TEST_TMPDIR/missing")" = "" ] || [ "$(maildir_used "$BATS_TEST_TMPDIR/missing")" = 0 ]
}

@test "the script can be sourced without running" {
  run bash -c "source '$BATS_TEST_DIRNAME/../plesk-server-report.sh'; echo sourced"
  [ "$status" -eq 0 ]
  [ "$output" = sourced ]
}

@test "tests use the awk chosen by AWK_DIR" {
  [ -z "$AWK_DIR" ] || [ "$(command -v awk)" = "$AWK_DIR/awk" ]
}

@test "UPLOADS_PHP_IGNORE no longer skips the whole borlabs-cookie folder" {
  run grep -qE "$UPLOADS_PHP_IGNORE" <<<"/var/www/vhosts/d1.example/httpdocs/wp-content/uploads/borlabs-cookie/x.php"
  [ "$status" -ne 0 ]
  grep -qE "$UPLOADS_PHP_IGNORE" <<<"/var/www/vhosts/d1.example/httpdocs/wp-content/uploads/mailchimp-for-wp/debug-log.php"
}
