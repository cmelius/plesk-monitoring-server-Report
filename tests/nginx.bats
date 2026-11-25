#!/usr/bin/env bats
# check_nginx_versions: the nginx that runs (websites, Plesk panel) with version, package and
# modules; plesk_pending: Plesk's own packages with an update (not counted as security updates)

load helper

setup() {
  load_script
  PROC_DIR="$BATS_TEST_TMPDIR/proc"; mkdir -p "$PROC_DIR/900" "$PROC_DIR/800"
  printf '#!/bin/sh\necho "nginx version: nginx/1.30.7" >&2\n' >"$PROC_DIR/900/exe"
  printf '#!/bin/sh\necho "nginx version: nginx/1.30.7" >&2\n' >"$PROC_DIR/800/exe"
  chmod +x "$PROC_DIR"/*/exe
  EXE_NGINX=/usr/sbin/nginx; EXE_PANEL=/usr/sbin/sw-cp-serverd
  pgrep() { case $3 in nginx) echo 900 ;; sw-cp-serverd) echo 800 ;; esac; }
  readlink() { case $1 in */900/exe) echo "$EXE_NGINX" ;; */800/exe) echo "$EXE_PANEL" ;; esac; }
  dpkg-query() {
    case "$1 $2" in
      "-S /usr/sbin/nginx") echo "sw-nginx: /usr/sbin/nginx" ;;
      "-S /usr/sbin/sw-cp-serverd") echo "sw-cp-server: /usr/sbin/sw-cp-serverd" ;;
      "-S /usr/lib/nginx/modules/ngx_http_geoip2_module.so") echo "libnginx-mod-http-geoip2: /usr/lib/nginx/modules/ngx_http_geoip2_module.so" ;;
      "-S "*) echo "dpkg-query: no path found matching pattern $2" >&2; return 1 ;;
      "-W -f") case $4 in sw-nginx) echo -n "1.30.7-v.debian.13+p18.0.75.0+t261119.1200" ;; sw-cp-server) echo -n "2:1.30.7-v.debian.13+p18.0.75.0" ;; *) echo -n "1:3.4-1" ;; esac ;;
    esac
  }
  NGINX_MODULE_CONFS="$BATS_TEST_TMPDIR/mod-*.conf"
}

@test "websites and panel: version of the running program and its Plesk package" {
  check_nginx_versions >"$BODY"
  run report
  [[ $output == *"nginx running (version, package):"* ]]
  [[ $output == *"websites: nginx/1.30.7 – /usr/sbin/nginx, package sw-nginx 1.30.7-v.debian.13+p18.0.75.0+t261119.1200 (Plesk)"* ]]
  [[ $output == *"the Plesk panel (sw-cp-server): nginx/1.30.7 – /usr/sbin/sw-cp-serverd, package sw-cp-server 2:1.30.7-v.debian.13+p18.0.75.0 (Plesk)"* ]]
  run alerts
  [ -z "$output" ]
}

@test "replaced on disk but not restarted: warning" {
  EXE_NGINX="/usr/sbin/nginx (deleted)"
  check_nginx_versions >"$BODY"
  run report
  [[ $output == *"websites: nginx/1.30.7 – /usr/sbin/nginx, package sw-nginx"* ]]
  [[ $output == *"replaced on disk by an update, but not restarted"* ]]
  run alerts
  [[ $output == *"Updates: nginx of websites still runs the program from before an update"*"systemctl restart nginx"* ]]
}

@test "nginx compiled by hand, a module from a package and one without" {
  EXE_NGINX=/usr/local/nginx/sbin/nginx
  echo 'load_module /usr/lib/nginx/modules/ngx_http_geoip2_module.so;' >"$BATS_TEST_TMPDIR/mod-a.conf"
  echo 'load_module "modules/ngx_custom.so";' >"$BATS_TEST_TMPDIR/mod-b.conf"
  check_nginx_versions >"$BODY"
  run report
  [[ $output == *"websites: nginx/1.30.7 – /usr/local/nginx/sbin/nginx, not from a package (compiled by hand?)"* ]]
  [[ $output == *"module ngx_http_geoip2_module.so: package libnginx-mod-http-geoip2 1:3.4-1"* ]]
  [[ $output == *"module ngx_custom.so: not from a package – its updates are up to you"* ]]
}

@test "no nginx running: nothing" {
  pgrep() { return 1; }
  run check_nginx_versions
  [ -z "$output" ]
}

@test "plesk_pending: Plesk packages listed, a pending update of Plesk's nginx is a warning" {
  upg='Inst sw-nginx [1.30.6-v.debian.13+p18.0.74.0] (1.30.7-v.debian.13+p18.0.75.0 Plesk:18.0/bookworm [amd64])
Inst psa-php84-configurator [1.0.1] (1.0.2 Plesk:18.0 [amd64])
Inst curl [8.14.1-2] (8.14.1-2+deb13u1 Debian-Security:13/stable-security [amd64])'
  plesk_pending "$(apt_plesk <<<"$upg")" >"$BODY"
  run report
  [[ $output == *"Plesk packages with an update (not counted as security updates above):"* ]]
  [[ $output == *"  sw-nginx 1.30.6-v.debian.13+p18.0.74.0 → 1.30.7-v.debian.13+p18.0.75.0"* ]]
  [[ $output == *"  psa-php84-configurator 1.0.1 → 1.0.2"* ]]
  [[ $output != *curl* ]]
  run alerts
  [[ $output == *"Updates: Plesk's nginx has an update (sw-nginx 1.30.7-v.debian.13+p18.0.75.0)"* ]]
}

@test "plesk_pending: nothing pending – no lines, no alert" {
  run plesk_pending ""
  [ -z "$output" ]
}
