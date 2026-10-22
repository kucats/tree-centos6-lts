#!/usr/bin/env bash
# Offline source inspection only. Does not run vulnerable ssh-agent/sshd.
set -euo pipefail
src=/sources/openssh-5.3p1-124.el6_10.src.rpm
test -s "$src"
rpm -qp --qf 'Source package: %{NAME} %{VERSION}-%{RELEASE}\n' "$src"
mkdir -p /tmp/openssh-inspection
cd /tmp/openssh-inspection
rpm2cpio "$src" | cpio -idm --quiet
echo '--- Package source files ---'
find . -maxdepth 1 -type f -printf '%f\n' | sort
echo '--- Relevant RPM spec source/options ---'
find . -maxdepth 1 -type f -name '*.spec' -exec grep -Ein 'pkcs11|agent|openssh|^Patch[0-9]+:' {} \; | head -120 || true
echo '--- PKCS11-related downstream patches ---'
find . -maxdepth 1 -type f -name '*.patch' -exec grep -Ein 'pkcs11|ssh-pkcs11|process_add_smartcard_key' {} \; | head -120 || true
echo '--- Historical upstream agent code signatures (read only) ---'
for tarball in openssh-5.3p1.tar.gz openssh-5.3p1.tar.bz2; do
    if test -f "$tarball"; then
        tar -tf "$tarball" | grep -E '/(ssh-agent|ssh-pkcs11)\.c$' || true
    fi
done
echo 'NOTE: grep hits do not establish effective build reachability; manual review required.'
