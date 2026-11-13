#!/usr/bin/env bats
# --self-update and --verify: a release is downloaded (here: from a folder, file://), its
# signature and checksum checked, the new version tests itself, then the folders are swapped.

load helper

setup() {
  load_script
  R="$BATS_TEST_TMPDIR/rel"; I="$BATS_TEST_TMPDIR/inst/plesk-server-report"
  mkdir -p "$R/v9.9.9" "$I"
  REPO="$BATS_TEST_DIRNAME/.."
  cp -r "$REPO/plesk-server-report.sh" "$REPO/lib" "$REPO/plugins" "$REPO/CHANGELOG.md" "$I/"
  PSR_HOME=$I; RELEASE_URL="file://$R"; SU_YES=0; SU_ROLLBACK=0
  is_root() { return 0; }
  latest_release() { echo 9.9.9; }
}

# release [VERSION] – builds the release 9.9.9 (the files of this checkout, with that version) in $R
release() {
  local s="$BATS_TEST_TMPDIR/stage"
  rm -rf "$s"; mkdir -p "$s"
  cp -r "$REPO/plesk-server-report.sh" "$REPO/lib" "$REPO/plugins" "$s/"
  sed -i "s/^VERSION=.*/VERSION=${1:-9.9.9}/" "$s/plesk-server-report.sh"
  printf '# Changelog\n\n## [9.9.9] – test\n\n- a change for the test\n\n## [%s] – old\n\n- older\n' "$VERSION" >"$s/CHANGELOG.md"
  chmod -R go-w "$s"
  (cd "$s" && tar -czf "$R/v9.9.9/plesk-server-report.tar.gz" .)
  (cd "$R/v9.9.9" && sha256sum plesk-server-report.tar.gz >SHA256SUMS)
}
# sign – a key pair for the test, its public key as RELEASE_KEY, SHA256SUMS signed with it
sign() {
  command -v ssh-keygen >/dev/null || skip "no ssh-keygen here (the workflow has it)"
  [[ -f $BATS_TEST_TMPDIR/key ]] || ssh-keygen -q -t ed25519 -N "" -C test -f "$BATS_TEST_TMPDIR/key"
  RELEASE_KEY=$(cut -d' ' -f1,2 "$BATS_TEST_TMPDIR/key.pub")
  rm -f "$R/v9.9.9/SHA256SUMS.sig"
  ssh-keygen -q -Y sign -f "$BATS_TEST_TMPDIR/key" -n plesk-server-report "$R/v9.9.9/SHA256SUMS" 2>/dev/null
}
# the new version tests itself with --verify, which as root also checks the ownership of all
# parent folders – under /tmp (mode 1777) that fails, rightly
safe_place() { [[ $EUID -ne 0 ]] || real_plugin_file_safe "$I/plesk-server-report.sh" || skip "as root, the test folder fails the ownership rule (/tmp)"; }
untouched() { [ ! -e "$I.old" ] && [ ! -e "$I.new" ] && grep -q "^VERSION=$VERSION\$" "$I/plesk-server-report.sh"; }

@test "--verify: the files of this checkout are those of this release" {
  run bash "$REPO/plesk-server-report.sh" --verify
  [ "$status" -eq 0 ] || [[ $EUID -eq 0 && $output == *"not root's"* ]]
  echo '# changed' >>"$I/plugins/panel.sh"; : >"$I/plugins/extra.sh"; rm "$I/lib/plugin-lib.sh"
  run verify_install
  [ "$status" -eq 1 ]
  [[ $output == *"missing: lib/plugin-lib.sh"* ]]
  [[ $output == *"differs from this release: plugins/panel.sh"* ]]
  [[ $output == *"not part of this release (never run): plugins/extra.sh"* ]]
}

@test "refused: no release key, not an installation from the archive, a git checkout, not root" {
  release
  RELEASE_KEY=""
  run self_update
  [ "$status" -eq 1 ]; [[ $output == *"no release key built in"* ]]
  untouched
  PSR_HOME="$BATS_TEST_TMPDIR/inst"
  run self_update
  [[ $output == *"is not an installation from the release archive"* ]]
  PSR_HOME=$I; mkdir "$I/.git"
  run self_update
  [[ $output == *"is a git checkout – update it with git pull"* ]]
  rmdir "$I/.git"; is_root() { return 1; }
  run self_update
  [[ $output == *"run it as root"* ]]
}

@test "up to date: nothing downloaded" {
  latest_release() { echo "$VERSION"; }
  run self_update
  [ "$status" -eq 0 ]; [[ $output == *"is up to date"* ]]
  latest_release() { echo ""; }
  run self_update
  [ "$status" -eq 1 ]; [[ $output == *"no answer from GitHub"* ]]
}

@test "a good release is installed, the old one kept; --rollback swaps back and forth" {
  safe_place; release; sign
  SU_YES=1 run self_update
  [ "$status" -eq 0 ]
  [[ $output == *"signature: good"*"checksum: good"*"test of the new version: good"*"a change for the test"*"installed version 9.9.9"* ]]
  [[ $output != *"older"* ]]                    # the changes since the installed version only
  grep -q '^VERSION=9.9.9$' "$I/plesk-server-report.sh"
  grep -q "^VERSION=$VERSION\$" "$I.old/plesk-server-report.sh"
  [ -x "$I/plesk-server-report.sh" ] && [ ! -e "$I.new" ]
  [ -z "$(ls "$STATE_DIR" | grep self-update)" ]  # the downloads are gone
  SU_ROLLBACK=1 SU_YES=1 run self_update
  [ "$status" -eq 0 ]
  grep -q "^VERSION=$VERSION\$" "$I/plesk-server-report.sh"
  grep -q '^VERSION=9.9.9$' "$I.old/plesk-server-report.sh"
}

@test "a changed archive, a forged signature, a wrong key: nothing installed" {
  release; sign
  echo garbage >>"$R/v9.9.9/plesk-server-report.tar.gz"           # archive changed, SHA256SUMS signed
  SU_YES=1 run self_update
  [ "$status" -eq 1 ]; [[ $output == *"checksum of plesk-server-report.tar.gz does not match"* ]]
  untouched
  release; sign
  (cd "$R/v9.9.9" && sha256sum plesk-server-report.tar.gz | sed 's/^./0/' >SHA256SUMS)   # SHA256SUMS changed after signing
  SU_YES=1 run self_update
  [ "$status" -eq 1 ]; [[ $output == *"signature of the release is NOT valid"* ]]
  untouched
  release; sign
  ssh-keygen -q -t ed25519 -N "" -C other -f "$BATS_TEST_TMPDIR/other"
  RELEASE_KEY=$(cut -d' ' -f1,2 "$BATS_TEST_TMPDIR/other.pub")      # signed with another key
  SU_YES=1 run self_update
  [ "$status" -eq 1 ]; [[ $output == *"NOT valid"* ]]
  untouched
}

@test "an archive with a link or ../ is refused; a new version that fails its test too" {
  release
  local s="$BATS_TEST_TMPDIR/stage"
  ln -s /etc/passwd "$s/plugins/link.sh"
  (cd "$s" && tar -czf "$R/v9.9.9/plesk-server-report.tar.gz" .)
  (cd "$R/v9.9.9" && sha256sum plesk-server-report.tar.gz >SHA256SUMS); sign
  SU_YES=1 run self_update
  [ "$status" -eq 1 ]; [[ $output == *"holds something other than plain files and folders"* ]]
  untouched
  release
  (cd "$BATS_TEST_TMPDIR" && mkdir -p up && echo x >up/evil && tar -czf "$R/v9.9.9/plesk-server-report.tar.gz" -C stage . ../up/evil 2>/dev/null) || true
  (cd "$R/v9.9.9" && sha256sum plesk-server-report.tar.gz >SHA256SUMS); sign
  SU_YES=1 run self_update
  [ "$status" -eq 1 ]
  untouched
  release 9.9.8; sign                           # the archive says 9.9.8, the release 9.9.9
  SU_YES=1 run self_update
  [ "$status" -eq 1 ]; [[ $output == *"the new version failed its test"* ]]
  untouched
}

@test "OpenSSH without signatures (RHEL 8): only after asking, never with --yes" {
  safe_place; release; RELEASE_KEY="ssh-ed25519 AAAAtest"
  : >"$R/v9.9.9/SHA256SUMS.sig"
  mkdir "$BATS_TEST_TMPDIR/bin"
  printf '#!/bin/sh\necho "unknown option -- Y" >&2\nexit 1\n' >"$BATS_TEST_TMPDIR/bin/ssh-keygen"; chmod +x "$BATS_TEST_TMPDIR/bin/ssh-keygen"
  PATH="$BATS_TEST_TMPDIR/bin:$PATH"
  SU_YES=1 run self_update
  [ "$status" -eq 1 ]; [[ $output == *"--yes needs a checked signature"* ]]
  untouched
  run self_update <<<"n"
  [[ $output == *"not installed"* ]]; untouched
  run self_update < <(printf 'y\ny\n')
  [ "$status" -eq 0 ]; [[ $output == *"signature: can't be checked"*"checksum: good"*"installed version 9.9.9"* ]]
}

@test "tools/build-release.sh: the archive has the files of the release, nothing writable by others" {
  command -v git >/dev/null && git -C "$REPO" rev-parse HEAD >/dev/null 2>&1 || skip "not a git checkout"
  [[ -z $(git -C "$REPO" status --porcelain -- plesk-server-report.sh lib plugins) ]] || skip "uncommitted changes"
  run bash "$REPO/tools/build-release.sh" "$BATS_TEST_TMPDIR/dist"
  [ "$status" -eq 0 ] || [[ $EUID -eq 0 ]]      # as root, --verify may refuse a checkout under /tmp
  [ "$status" -eq 0 ] || skip "$output"
  run tar -tvzf "$BATS_TEST_TMPDIR/dist/plesk-server-report.tar.gz"
  [[ $output == *"plesk-server-report.sh"* && $output == *"lib/plugin-lib.sh"* && $output == *"plugins/panel.sh"* ]]
  [[ $output != *"tests/"* && $output != *"tools/"* ]]
  ! grep -E '^.....w|^........w' <<<"$output"
  grep -E '^-rwxr-xr-x .* plesk-server-report.sh$' <<<"$output"
  (cd "$BATS_TEST_TMPDIR/dist" && sha256sum -c SHA256SUMS)
}
