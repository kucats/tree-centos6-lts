#!/usr/bin/env bash
# Compares dynamic API exports and DT_NEEDED of the baseline installed sudo
# with the newly built candidate. Not a substitute for full ABI regression.
set -euo pipefail
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
candidate=$(find /out -maxdepth 1 -type f -name 'sudo-*.x86_64.rpm' -print -quit)
test -n "$candidate"
(
  cd "$tmp"
  rpm2cpio "$candidate" | cpio -idm --quiet
)
symbols() {
  nm -D --defined-only "$1" | awk 'NF>=2 {print $(NF-1), $NF}' | sort
}
needed() {
  readelf -d "$1" | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' | sort
}
for path in /usr/bin/sudo /usr/libexec/sudoers.so; do
  test -f "$path" && test -f "$tmp$path"
  symbols "$path" > "$tmp/baseline.syms"
  symbols "$tmp$path" > "$tmp/candidate.syms"
  diff -u "$tmp/baseline.syms" "$tmp/candidate.syms"
  needed "$path" > "$tmp/baseline.needed"
  needed "$tmp$path" > "$tmp/candidate.needed"
  diff -u "$tmp/baseline.needed" "$tmp/candidate.needed"
  echo "PASS: exported dynamic symbols and DT_NEEDED unchanged for $path"
done
