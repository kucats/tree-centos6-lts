#!/usr/bin/env bash
# Research-only: build a conservative legacy ssh-agent PKCS11 disablement.
# Container must be disposable and output must remain unsigned and unpublished.
set -euo pipefail
top=/tmp/tree-openssh-build
source_rpm=/out/openssh-5.3p1-124.el6_10.src.rpm
patch_file=/work/packages/openssh/CVE-2023-38408-deny-pkcs11.patch
test -s "$source_rpm" && test -s "$patch_file"
mkdir -p "$top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
rpm -i --define "_topdir $top" "$source_rpm"
spec="$top/SPECS/openssh.spec"
test -s "$spec"
cp "$patch_file" "$top/SOURCES/tree-CVE-2023-38408-deny-pkcs11.patch"
python - "$spec" <<'PY'
import re, sys
path = sys.argv[1]
with open(path) as f:
    content = f.read()
content, n = re.subn(r'(?m)^(Release:\s*[^\n]+)$', r'\1.tree1', content, count=1)
assert n == 1, 'Release field not found'
assert 'Patch7999:' not in content and '%patch7999' not in content, 'Patch ID conflict'
match = re.search(r'(?m)^%description(?:\s|$)', content)
assert match, 'missing %description'
content = (content[:match.start()] +
           'Patch7999: tree-CVE-2023-38408-deny-pkcs11.patch\n\n' +
           content[match.start():])
prep = re.search(r'(?m)^%prep(?:\s|$)', content)
assert prep, 'missing %prep'
next_section = re.search(
    r'(?m)^%(build|install|check|clean|files|changelog)(?:\s|$)',
    content[prep.end():])
assert next_section, 'cannot locate %prep end'
pos = prep.end() + next_section.start()
content = content[:pos] + '%patch7999 -p1\n\n' + content[pos:]
with open(path, 'w') as f:
    f.write(content)
print('Research-only candidate: appended .tree1 release and PKCS11 deny patch')
PY

# CentOS Vault is archival; fixed source hash and GPG signature checked by caller.
yum-builddep -y "$spec"
rpmbuild -bp --define "_topdir $top" --define "dist .el6_10" "$spec"
agent_source=$(find "$top/BUILD" -maxdepth 3 -name ssh-agent.c -type f -print -quit)
test -s "$agent_source"
grep -F "legacy agent cannot identify forwarded peers" "$agent_source"
# Reject if any surviving request-dispatch call can still load provider.
if grep -Eq '^[[:space:]]+process_(add|remove)_smartcard_key\(e\);' "$agent_source"; then
  echo 'FAIL: smartcard dispatch still reachable' >&2
  exit 1
fi
rpmbuild -ba --define "_topdir $top" --define "dist .el6_10" "$spec"
find "$top/RPMS" -name '*.rpm' -type f -exec cp -v {} /out/ \;
find "$top/SRPMS" -name '*.src.rpm' -type f -exec cp -v {} /out/ \;
rpm -qp --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' /out/openssh-clients-[0-9]*.x86_64.rpm
python - <<'PY'
import rpm
assert rpm.labelCompare(("0", "5.3p1", "124.el6_10.tree1"),
                        ("0", "5.3p1", "124.el6_10")) > 0
print("PASS: candidate RPM release orders after CentOS 6 baseline")
PY
(cd /out && sha256sum *tree1*.rpm > OPENSSH-RESEARCH-CANDIDATE.sha256)
