#!/usr/bin/env bash
# Offline historical CentOS RPM %prep inspection. Never run ssh-agent/sshd.
set -euo pipefail
top=/tmp/tree-openssh-prep
mkdir -p "$top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
rpm -i --define "_topdir $top" /sources/openssh-5.3p1-124.el6_10.src.rpm
spec="$top/SPECS/openssh.spec"
test -s "$spec"
echo "--- CentOS 6 SRPM PKCS11 patch declaration/application ---"
grep -E '^Patch103:.*pkcs11' "$spec"
grep -Ei '^%patch103([[:space:]]|$)' "$spec"
rpmbuild -bp --define "_topdir $top" --define "dist .el6_10" "$spec" >/tmp/prep-stdout.log 2>&1 || {
    tail -100 /tmp/prep-stdout.log >&2
    exit 1
}
src=$(find "$top/BUILD" -name ssh-agent.c -type f -print -quit)
makefile=$(find "$top/BUILD" -name Makefile.in -type f -print -quit)
test -n "$src" && test -n "$makefile"
echo "--- Actually prepared ssh-agent code and link targets ---"
grep -n 'process_add_smartcard_key(' "$src"
grep -n 'pkcs11_add_provider(' "$src"
grep -n 'ssh-pkcs11-client.o' "$makefile"
echo 'PASS: signed CentOS source RPM applies PKCS11 support in prepared ssh-agent implementation'
echo 'LIMIT: compilation/runtime exposure and exploitability still require independent tests.'
