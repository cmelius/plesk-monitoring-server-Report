#!/usr/bin/env bats
# the plugin php-config (plugins/php-config.sh): PHP settings in .htaccess / .user.ini

load helper

setup() {
  load_script
  docroots() { printf 'd1.example\t%s\n' "$FIX/htaccess"; }
}

@test "backdoor patterns are found, security plugins and normal files are not" {
  output=$(run_plugin php-config daily)
  for d in prepend image-handler addtype campaign; do
    [[ $output == *"/htaccess/$d/"* ]]
  done
  for d in wordfence normal none; do
    [[ $output != *"/htaccess/$d/"* ]]
  done
  [ "$(grep -c "^  $FIX/htaccess/" <<<"$output")" -eq 4 ]
}
