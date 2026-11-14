#!/usr/bin/env bats
# check_webshell: PHP backdoors (and, in 2.0 through the plugin php-config, PHP settings in .htaccess), also behind odd folder names

load helper

setup() {
  load_script
  W="$BATS_TEST_TMPDIR/www"; mkdir -p "$W/d1"
  docroots() { printf 'd1.example\t%s\n' "$W/d1"; }
  # the backdoor line is put together at run time, so that virus scanners don't flag the repository
  BACKDOOR=$(printf '<?php %s(%s($%s["x"])); ?>' "ev""al" "base64_""decode" "_PO""ST")
}

@test "a folder name with a line break hides neither a PHP backdoor nor a .htaccess backdoor" {
  local d="$W/d1/a"$'\n'"b"
  mkdir -p "$d"; printf '%s\n' "$BACKDOOR" >"$d/x.php"; cp "$FIX/htaccess/prepend/.htaccess" "$d/"
  run run_daily webshell php-config                 # 2.0: .htaccess & co. are the plugin php-config
  [[ $output == *"  $W/d1/a?b/x.php (file date"* ]]
  [[ $output == *"  $W/d1/a?b/.htaccess: "* ]]
  [[ $output == *"1 document root(s) scanned, 1 suspicious file(s)"*"1 document root(s) scanned, 1 suspicious file(s)"* ]]
}

@test "a normal file with the backdoor is found, an ordinary one not" {
  printf '%s\n' "$BACKDOOR" >"$W/d1/bad.php"; printf '<?php echo "hello"; ?>\n' >"$W/d1/good.php"
  run check_webshell
  [[ $output == *"$W/d1/bad.php (file date"* ]]
  [[ $output != *good.php* ]]
}
