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
# out, note and alert below print these lines, so a check reads the same inside the main
# script and as a plugin. Everything else on stdout is dropped by the main script.
#
# A plugin only reads: it writes no files and makes no network connections.
# =============================================================================

set -uo pipefail
export LC_ALL=C
umask 077

out()   { printf 'TEXT %s\n' "$*"; }
note()  { printf 'NOTE %s\n' "$*"; }
alert() { printf 'ALERT %s\n' "$*"; }

# geo_ref IP – stands for "IP (country, operator)": the main script, which has the GeoIP
# database, replaces it. \037 never comes from a log line (log_clean removes it).
geo_ref() { printf '\037G%s\037' "$1"; }

ignored_domain() { [[ " ${WEB_IGNORE_DOMAINS:-} " == *" $1 "* ]]; }

# Each log on stdin starts with a line "\036 NUMBER PATH"; logs that could not be read are
# listed by number in PSR_LOGS_MISSING. PSR_SEP is that first character, for awk -v sep=…
PSR_SEP=$(printf '\036')
: "${PSR_LOGS_MISSING:=}"
# shellcheck disable=SC2034  # for the plugins
readonly PSR_SEP PSR_LOGS_MISSING

[[ -r ${1:-} ]] || exit 96
# shellcheck source=/dev/null  # the plugin file is given by the main script
. "$1"
declare -F plugin_check >/dev/null || exit 97
plugin_check
