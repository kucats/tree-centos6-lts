#!/usr/bin/env bash
# Research-only offline yum upgrade of an UNSIGNED candidate in a throwaway
# CentOS 6 container. No signing keys, network, host rootfs or public yum repo.
set -euo pipefail
repo=/tmp/tree-openssh-yum-research
mkdir -p "$repo"
for pattern in openssh-[0-9]*.x86_64.rpm openssh-clients-[0-9]*.x86_64.rpm; do
  set -- /out/$pattern
  test "$#" -eq 1 && test -s "$1"
  cp "$1" "$repo/"
done
rpm -qp --qf '%{NAME} %{VERSION}-%{RELEASE}\n' "$repo"/*.rpm
createrepo --quiet --checksum sha256 "$repo"
test -s "$repo/repodata/repomd.xml"
for pkg in openssh openssh-clients; do
  old=$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$pkg")
  test "$old" = "5.3p1-124.el6_10" || {
    echo "Unexpected CentOS 6 baseline package $pkg: $old" >&2
    exit 1
  }
done
cat > /etc/yum.repos.d/tree-local-UNSIGNED-test.repo <<'EOF'
[tree-local]
name=UNSIGNED OFFLINE RESEARCH TEST ONLY
baseurl=file:///tmp/tree-openssh-yum-research/
enabled=0
gpgcheck=0
repo_gpgcheck=0
EOF
yum --noplugins --disablerepo='*' --enablerepo=tree-local \
  --setopt=obsoletes=0 -y update openssh openssh-clients
for pkg in openssh openssh-clients; do
  current=$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$pkg")
  test "$current" = "5.3p1-124.el6_10.tree1" || {
    echo "FAIL: $pkg did not upgrade; actual=$current" >&2
    exit 1
  }
done
ssh -V 2>&1 | grep 'OpenSSH_5.3p1'
echo 'PASS: offline yum RPM dependency transaction upgraded openssh + openssh-clients to tree1'
