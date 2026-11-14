#!/usr/bin/env bats
# php_config_backdoors: PHP settings in .htaccess / .user.ini

load helper

setup() { load_script; }

@test "backdoor patterns are found, security plugins and normal files are not" {
  run php_config_backdoors < <(find "$FIX/htaccess" -type f -print0 | sort -z)
  for d in prepend image-handler addtype campaign; do
    [[ $output == *"/htaccess/$d/"* ]]
  done
  for d in wordfence normal none; do
    [[ $output != *"/htaccess/$d/"* ]]
  done
  [ "$(wc -l <<<"$output")" -eq 4 ]
}
