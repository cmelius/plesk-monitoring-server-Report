#!/bin/bash
# Writes the checksums of lib/*.sh and plugins/*.sh into plesk-server-report.sh (PLUGIN_SUMS).
# Run it after every change of one of these files; tests/plugins.bats fails if it was forgotten.
# For developing only – never needed on a server.
set -euo pipefail
cd "$(dirname "$0")/.."
sums=$(LC_ALL=C sha256sum lib/*.sh plugins/*.sh | awk '{ print $1 "  " $2 }')
awk -v sums="$sums" '
  /^# >>> plugin sums/ { print; print "PLUGIN_SUMS=\047" sums "\047"; skip = 1; next }
  /^# <<< plugin sums/ { skip = 0 }
  !skip' plesk-server-report.sh >plesk-server-report.sh.new
cat plesk-server-report.sh.new >plesk-server-report.sh    # keeps the file mode
rm -f plesk-server-report.sh.new
echo "$sums"
