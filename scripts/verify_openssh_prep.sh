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
# Only run %prep, not compilation: historical BuildRequires are not needed.
rpmbuild -bp --nodeps --define "_topdir $top" --define "dist .el6_10" "$spec" >/tmp/prep-stdout.log 2>&1 || {
    tail -100 /tmp/prep-stdout.log >&2
    exit 1
}
src=$(find "$top/BUILD" -name ssh-agent.c -type f -print -quit)
makefile="$(dirname "$src")/Makefile.in"
test -n "$src" && test -n "$makefile"
echo "--- Actually prepared ssh-agent code and link targets ---"
grep -n 'process_add_smartcard_key(' "$src"
grep -n 'pkcs11_add_provider(' "$src"
grep -n 'ssh-pkcs11-client.o' "$makefile"
echo '--- Historical feature-presence report (source tokens only; not exploitability) ---'
features() {
  local label="$1" expr="$2"
  shift 2
  if grep -Eql "$expr" "$@"; then
    echo "FEATURE ${label}: PRESENT in prepared source"
  else
    echo "FEATURE ${label}: NOT FOUND in prepared source"
  fi
}
features ssh_agent_session_bind 'session-bind@openssh\.com' "$src"
features sshd_DisableForwarding 'DisableForwarding' "$(dirname "$src")/servconf.c"
features ssh_client_ControlPersist 'ControlPersist|controlpersist' "$(dirname "$src")/readconf.c"
features sshd_GSSAPIAuthentication 'GSSAPIAuthentication|gssapiauthentication' "$(dirname "$src")/servconf.c"
features sshd_PermitTunnel 'PermitTunnel|permittunnel' "$(dirname "$src")/servconf.c"
features ssh_packet_zlib '(uncompress|deflate|inflate)' "$(dirname "$src")/packet.c"
echo 'PASS: signed CentOS source RPM applies PKCS11 support in prepared ssh-agent implementation'
echo 'LIMIT: compilation/runtime exposure and exploitability still require independent tests.'
