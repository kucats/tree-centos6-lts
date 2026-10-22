#!/usr/bin/env bash
# Run only in a disposable CentOS 6 build container, with no signing keys.
set -euo pipefail
TOP=/tmp/tree-curl-rpmbuild
SRPM=/out/curl-7.19.7-54.el6_10.src.rpm
PATCH=/work/packages/curl/CVE-2023-28321.patch
mkdir -p "$TOP"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
test -s "$SRPM" && test -s "$PATCH"
rpm -i --define "_topdir $TOP" "$SRPM"
SPEC="$TOP/SPECS/curl.spec"
test -s "$SPEC"
yum-builddep -y "$SPEC"

# First prove the old source function accepts both unsafe wildcard classes.
rpmbuild -bp --define "_topdir $TOP" --define "dist .el6_10" "$SPEC"
SRC=$(find "$TOP/BUILD" -type f -path '*/lib/ssluse.c' -print -quit)
test -n "$SRC"
echo '---- CentOS 6.10 post-vendor-patch hostname verifier ----'
sed -n '/cert_hostcheck(const char \*match_pattern/,/\/\* Quote from RFC2818/p' "$SRC" | head -90
echo '---- end verifier ----'
bash /work/tests/integration/curl_wildcard_smoke.sh "$SRC" before

# Attach one reviewable patch, never replacing the original vendor patch set.
cp "$PATCH" "$TOP/SOURCES/tree-CVE-2023-28321.patch"
python - "$SPEC" <<'PY'
import re, sys
path = sys.argv[1]
with open(path) as f:
    text = f.read()
text, count = re.subn(r'(?m)^(Release:\s*[^\n]+)$', r'\1.tree1', text, count=1)
assert count == 1 and 'Patch7998:' not in text and '%patch7998' not in text
description = re.search(r'(?m)^%description(?:\s|$)', text)
assert description, 'missing %description'
text = text[:description.start()] + 'Patch7998: tree-CVE-2023-28321.patch\n\n' + text[description.start():]
prep = re.search(r'(?m)^%prep(?:\s|$)', text)
assert prep, 'missing %prep'
section = re.search(r'(?m)^%(build|install|check|clean|files|changelog)(?:\s|$)', text[prep.end():])
assert section, 'missing end of %prep'
end = prep.end() + section.start()
text = text[:end] + '%patch7998 -p1\n\n' + text[end:]
with open(path, 'w') as f:
    f.write(text)
PY
# This re-preps the exact source, applies vendor patches and our candidate.
rpmbuild -bp --define "_topdir $TOP" --define "dist .el6_10" "$SPEC"
SRC=$(find "$TOP/BUILD" -type f -path '*/lib/ssluse.c' -print -quit)
test -n "$SRC"
grep -F 'only allow a full leftmost-label wildcard' "$SRC"
bash /work/tests/integration/curl_wildcard_smoke.sh "$SRC" after

# If the two-sided source tests pass, attempt the full RPM + SRPM build.
rpmbuild -ba --define "_topdir $TOP" --define "dist .el6_10" "$SPEC"
find "$TOP/RPMS" -type f -name '*.rpm' -exec cp -v {} /out/ \;
find "$TOP/SRPMS" -type f -name '*.src.rpm' -exec cp -v {} /out/ \;
rpm -qp --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' /out/curl-*.x86_64.rpm
(cd /out && sha256sum *tree1*.rpm > CURL-CANDIDATE.sha256)
