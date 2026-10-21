#!/usr/bin/env bash
# Exercise only a trivial noarch RPM; no CVE fix or release is asserted.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist/smoke
docker build --pull --file build/Dockerfile --tag tree-centos6-lts-builder:6.10 .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 128 --memory 2g \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m \
  --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD/tests/fixtures:/fixtures:ro" \
  -v "$PWD/dist/smoke:/out" \
  tree-centos6-lts-builder:6.10 /bin/bash -ec '
    mkdir -p /tmp/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
    cp /fixtures/smoke.spec /tmp/rpmbuild/SPECS/
    cp /fixtures/hello.sh /tmp/rpmbuild/SOURCES/
    rpmbuild -bb --define "_topdir /tmp/rpmbuild" /tmp/rpmbuild/SPECS/smoke.spec
    find /tmp/rpmbuild/RPMS -type f -name "*.rpm" -exec cp {} /out/ \;
    test -n "$(find /out -type f -name "*.rpm" -print -quit)"
    rpm -qp --queryformat "%{NAME} %{VERSION}-%{RELEASE}\n" /out/*.rpm
  '
