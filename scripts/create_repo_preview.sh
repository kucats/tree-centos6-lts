#!/usr/bin/env bash
# Construct a deliberately UNSIGNED, PRIVATE yum metadata preview.
# Never publish this directory to a web server or a public yum repository.
set -euo pipefail
source_dir="${1:-/candidate}"
dest="${2:-/preview}"
mkdir -p "$dest/6/x86_64"
main=$(find "$source_dir" -maxdepth 1 -type f -name 'sudo-[0-9]*.x86_64.rpm' -print -quit)
test -s "$main"
if ! rpm -qp --qf '%{NAME}' "$main" | grep -qx sudo; then
    echo "FAIL: candidate is not the main sudo RPM" >&2
    exit 1
fi
cp "$main" "$dest/6/x86_64/"
createrepo --quiet --checksum sha256 "$dest/6/x86_64"
test -s "$dest/6/x86_64/repodata/repomd.xml"
echo 'Preview only: unsigned sudo RPM and yum repodata; NOT ready for distribution.'
