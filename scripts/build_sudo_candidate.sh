#!/usr/bin/env bash
# Must run INSIDE a disposable CentOS 6.10 container; never release unsigned candidates.
set -euo pipefail
TOP=/tmp/tree-rpmbuild
SRPM=/out/sudo-1.8.6p3-29.el6_10.3.src.rpm
PATCH=/work/packages/sudo/CVE-2023-22809.patch
mkdir -p "$TOP"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
test -f "$SRPM" && test -s "$PATCH"
rpm -i --define "_topdir $TOP" "$SRPM"
cp "$PATCH" "$TOP/SOURCES/tree-CVE-2023-22809.patch"
SPEC="$TOP/SPECS/sudo.spec"
test -f "$SPEC"
python - "$SPEC" <<'PY'
import re, sys
spec = sys.argv[1]
with open(spec, 'r') as f:
    s = f.read()
s, n = re.subn(r'(?m)^(Release:\s*[^\n]+)$', r'\1.tree1', s, count=1)
assert n == 1, 'Release field not found'
assert 'Patch7999:' not in s and '%patch7999' not in s, 'Patch ID conflict'
match = re.search(r'(?m)^%description(?:\s|$)', s)
assert match, 'missing %description'
s = s[:match.start()] + 'Patch7999: tree-CVE-2023-22809.patch\n\n' + s[match.start():]
prep = re.search(r'(?m)^%prep(?:\s|$)', s)
assert prep, 'missing %prep'
next_section = re.search(r'(?m)^%(build|install|check|clean|files|changelog)(?:\s|$)', s[prep.end():])
assert next_section, 'cannot find end of %prep'
pos = prep.end() + next_section.start()
s = s[:pos] + '%patch7999 -p1\n\n' + s[pos:]
with open(spec, 'w') as f:
    f.write(s)
print('Added Patch7999, appended .tree1 release; RPM candidate only')
PY
yum-builddep -y "$SPEC"
rpmbuild -bp --define "_topdir $TOP" --define "dist .el6_10" "$SPEC"
# Fail closed unless the actual post-%prep source contains the backport guard.
SOURCE=$(find "$TOP/BUILD" -path '*/plugins/sudoers/sudoers.c' -type f -print -quit)
test -n "$SOURCE"
grep -F 'editor arguments may not contain' "$SOURCE"
rpmbuild -ba --define "_topdir $TOP" --define "dist .el6_10" "$SPEC"
find "$TOP/RPMS" -type f -name '*.rpm' -exec cp -v {} /out/ \;
find "$TOP/SRPMS" -type f -name '*.src.rpm' -exec cp -v {} /out/ \;
rpm -qp --queryformat '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' /out/sudo-*.x86_64.rpm
# Preserve upgrade ordering over 29.el6_10.3, and record all candidate checksums.
python - <<'PY'
import rpm
old = ('0', '1.8.6p3', '29.el6_10.3')
new = ('0', '1.8.6p3', '29.el6_10.3.tree1')
assert rpm.labelCompare(new, old) > 0, 'Candidate is not an RPM upgrade'
print('PASS: candidate RPM release is newer than CentOS 6.10 baseline')
PY
sha256sum /out/*tree1*.rpm > /out/CANDIDATE.sha256
