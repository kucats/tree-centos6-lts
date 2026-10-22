#!/usr/bin/env bash
# Usage (inside build/Dockerfile.candidate): build_candidate.sh PACKAGE
# Builds PACKAGE from its pinned, CentOS-signed SRPM in /out with the patches listed in
# config/candidates.json, as release <vendor>.tree1. Never run with signing keys present.
set -euo pipefail
pkg="$1"
TOP=/tmp/tree-rpmbuild-$pkg
cfg=/work/config/candidates.json
get() { python -c 'import json,sys; c=json.load(open(sys.argv[1]))["packages"][sys.argv[2]]; v=c[sys.argv[3]]; print("\n".join(v) if isinstance(v, list) else v)' "$cfg" "$pkg" "$1"; }
srpm=/out/$(get srpm)
dist=$(get dist)
test -s "$srpm"
# The SRPM must carry a valid signature from the official CentOS 6 key.
rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6
rpm -K "$srpm"
rpm -K "$srpm" | grep -q 'pgp.*OK$'
mkdir -p "$TOP"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
rpm -i --define "_topdir $TOP" "$srpm"
spec=$(ls "$TOP"/SPECS/*.spec)
cves=$(get patches)
for cve in $cves; do
  test -s "/work/packages/$pkg/$cve.patch"
  cp "/work/packages/$pkg/$cve.patch" "$TOP/SOURCES/tree-$cve.patch"
done
python - "$spec" $cves <<'PY'
import re, sys
spec, cves = sys.argv[1], sys.argv[2:]
s = open(spec).read()
s, n = re.subn(r'(?m)^(Release:\s*[^\n]+?)\s*$', r'\1.tree1', s, count=1)
assert n == 1, 'Release field not found'
ids = range(9900, 9900 + len(cves))
for i in ids:
    assert 'Patch%d:' % i not in s and '%%patch%d' % i not in s, 'patch id conflict'
decl = ''.join('Patch%d: tree-%s.patch\n' % (i, c) for i, c in zip(ids, cves))
m = re.search(r'(?m)^%description(?:\s|$)', s)
s = s[:m.start()] + decl + '\n' + s[m.start():]
prep = re.search(r'(?m)^%prep(?:\s|$)', s)
end = prep.end() + re.search(r'(?m)^%(build|install|check|clean|files|changelog)(?:\s|$)', s[prep.end():]).start()
body = s[prep.end():end]
last = None
for last in re.finditer(r'(?m)^%patch\d*\b[^\n]*\n', body):
    pass
apply = ''.join('%%patch%d -p1 -b .tree-%s\n' % (i, c) for i, c in zip(ids, cves))
pos = prep.end() + (last.end() if last else len(body))
s = s[:pos] + apply + s[pos:]
# rpm 4.8 has no --nocheck; vendor test suites run in a separate, bounded job.
s, _ = re.subn(r'(?m)^(%check[ \t]*\n)', r'\1exit 0 # tree candidate build: vendor suite deferred\n', s, count=1)
open(spec, 'w').write(s)
print('applied after last vendor %%patch: %s' % ', '.join(cves))
PY
yum-builddep -y "$spec"
rpmbuild -bp --define "_topdir $TOP" --define "dist $dist" "$spec"
for cve in $cves; do
  guard=$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["packages"][sys.argv[2]]["guards"][sys.argv[3]])' "$cfg" "$pkg" "$cve")
  grep -rqF -- "$guard" "$TOP/BUILD" || { echo "FAIL: guard for $cve not found after %prep: $guard" >&2; exit 1; }
  echo "guard present: $cve"
done
rpmbuild -ba --define "_topdir $TOP" --define "dist $dist" --define '_smp_mflags -j4' "$spec"
find "$TOP/RPMS" -type f -name '*.rpm' -exec cp {} /out/ \;
find "$TOP/SRPMS" -type f -name '*.src.rpm' -exec cp {} /out/ \;
(cd /out && ls -1 *.tree1.*.rpm && sha256sum *.tree1.*.rpm > CANDIDATE.sha256)
