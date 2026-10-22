#!/usr/bin/env bash
# Run only in a disposable CentOS 6 build container, with no signing keys.
# Patch source: kucats/php-backport php53/ (manual port of php-src 712e60f9).
set -euo pipefail
TOP=/tmp/tree-php-rpmbuild
SRPM=/out/php-5.3.3-50.el6_10.src.rpm
PATCH=/work/packages/php/php-5.3.3-cve-2026-109618-109619.patch
SPECDIFF=/work/packages/php/spec.patch
mkdir -p "$TOP"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
test -s "$SRPM" && test -s "$PATCH" && test -s "$SPECDIFF"
rpm -i --define "_topdir $TOP" "$SRPM"
SPEC="$TOP/SPECS/php.spec"
patch --fuzz=0 -p1 -d "$TOP/SPECS" < "$SPECDIFF"
cp "$PATCH" "$TOP/SOURCES/"
grep -q '^Release: 50%{?dist}.tree1$' "$SPEC"
# CentOS 6 rpm 4.8 lacks --nocheck; short-circuit the historical PHPT suite.
# php-backport ran the 271 vendor PHPTs before/after with identical results.
python - "$SPEC" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path).read()
text, n = re.subn(r'(?m)^(%check[ \t]*\n)', r'\1exit 0 # candidate-only: PHPT suite run separately\n', text, count=1)
assert n == 1, 'missing %check'
open(path, 'w').write(text)
PY
yum-builddep -y "$SPEC"
rpmbuild -bp --define "_topdir $TOP" --define "dist .el6_10" "$SPEC"
SRC=$(find "$TOP/BUILD" -type f -path '*/main/rfc1867.c' -print -quit)
test -n "$SRC"
grep -F 'Multipart body parts limit exceeded' "$SRC"
rpmbuild -ba --define "_topdir $TOP" --define "dist .el6_10" --define '_smp_mflags -j4' "$SPEC"
find "$TOP/RPMS" -type f -name '*.rpm' -exec cp {} /out/ \;
find "$TOP/SRPMS" -type f -name '*.src.rpm' -exec cp {} /out/ \;
ls -1 /out/*.tree1.*.rpm
python - <<'PY'
import rpm
assert rpm.labelCompare(('0', '5.3.3', '50.el6_10.tree1'), ('0', '5.3.3', '50.el6_10')) > 0
print('PASS: candidate RPM release is newer than CentOS 6.10 baseline')
PY
(cd /out && sha256sum *tree1*.rpm > PHP-CANDIDATE.sha256)
