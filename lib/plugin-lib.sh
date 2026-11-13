#!/bin/bash
# =============================================================================
# plugin-lib.sh – runs one plugin of plesk-server-report in a process of its own.
#
# Started by the main script, never by hand:
#   bash --noprofile --norc plugin-lib.sh PLUGINFILE  <new log lines  >protocol lines
#
# The plugin gets the new lines of its logs on stdin and answers on stdout, one line each:
#   TEXT <line>    a line of its section in the report
#   NOTE <text>    a note below the STATUS line (missing data source)
#   ALERT <text>   an alert
#   ALERT-FOREIGN <ip> <ip> … :: <text>   an alert only if one of the IPs is outside
#                  ALLOWED_COUNTRIES; {ips} in the text becomes these IPs
#   STATE <line>   a line of its new state; the main script stores it (only in a normal run)
#                  and gives it back next time as the file $PSR_STATE
#
# A daily plugin's TEXT lines go into the daily checks; it prints its own heading.
# Context files from the main script: $PSR_DOMAINS ("domain<TAB>document root", if the
# plugin lists domains in PLUGIN_INPUTS).
#
# out, note, alert and state below print these lines, so a check reads the same inside the main
# script and as a plugin. Everything else on stdout is dropped by the main script.
#
# A plugin only reads: it writes no files and makes no network connections.
# =============================================================================

set -uo pipefail
export LC_ALL=C
umask 077

# one protocol line each: a line break inside the text (a file name can hold one) becomes a
# space, so nothing a plugin prints can start a line of its own
_line() { local t="$*"; t=${t//$'\n'/ }; printf '%s\n' "${t//$'\r'/ }"; }
out()   { _line "TEXT $*"; }
note()  { _line "NOTE $*"; }
alert() { _line "ALERT $*"; }
state() { _line "STATE $*"; }

# geo_ref IP – stands for "IP (country, operator)": the main script, which has the GeoIP
# database, replaces it. \037 never comes from a log line (log_clean removes it).
geo_ref() { printf '\037G%s\037' "$1"; }

# alert_foreign "IP IP …" TEXT – an alert only if one of the IPs is outside ALLOWED_COUNTRIES
# (the main script decides); {ips} in TEXT becomes those IPs with country and operator
alert_foreign() { local ips=$1; shift; _line "ALERT-FOREIGN $ips :: $*"; }

ignored_domain() { [[ " ${WEB_IGNORE_DOMAINS:-} " == *" $1 "* ]]; }

# Each log on stdin starts with a line "\036 NUMBER PATH"; logs that could not be read are
# listed by number in PSR_LOGS_MISSING. PSR_SEP is that first character, for awk -v sep=…
PSR_SEP=$(printf '\036')
: "${PSR_LOGS_MISSING:=}" "${PSR_STATE:=/dev/null}" "${PSR_DOMAINS:=/dev/null}"
# shellcheck disable=SC2034  # for the plugins
readonly PSR_SEP PSR_LOGS_MISSING PSR_STATE PSR_DOMAINS

[[ -r ${1:-} ]] || exit 96
# shellcheck source=/dev/null  # the plugin file is given by the main script
. "$1"
declare -F plugin_check >/dev/null || exit 97
plugin_check
