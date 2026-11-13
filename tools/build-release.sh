#!/bin/bash
# Builds the release files for GitHub from the committed state (HEAD) – for the maintainer only:
#   tools/build-release.sh [OUTDIR]          default OUTDIR: dist/
# writes OUTDIR/plesk-server-report.tar.gz and OUTDIR/SHA256SUMS. Then sign SHA256SUMS on your
# own computer (the private key never goes anywhere else) and upload all three files:
#   ssh-keygen -Y sign -f ~/.ssh/<your key> -n plesk-server-report OUTDIR/SHA256SUMS
# --self-update checks the signature with the public key in RELEASE_KEY of the script.
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:-dist}
version=$(sed -n 's/^VERSION=//p' plesk-server-report.sh)
[[ -z $(git status --porcelain -- plesk-server-report.sh lib plugins) ]] ||
  { echo "uncommitted changes in the script, lib/ or plugins/ – commit them first" >&2; exit 1; }
bash plesk-server-report.sh --verify || { echo "the checksums in the script don't match – run tools/update-plugin-sums.sh" >&2; exit 1; }
mkdir -p "$out"
# tar.umask: no file and no folder writable by group or others (the script refuses such plugins)
git -c tar.umask=022 archive --format=tar HEAD \
  plesk-server-report.sh lib plugins README.md CHANGELOG.md STATE-FILES.md LICENSE |
  gzip -n9 >"$out/plesk-server-report.tar.gz"
(cd "$out" && sha256sum plesk-server-report.tar.gz >SHA256SUMS)
echo "version $version: $out/plesk-server-report.tar.gz, $out/SHA256SUMS"
echo "next: ssh-keygen -Y sign -f ~/.ssh/<your key> -n plesk-server-report $out/SHA256SUMS"
