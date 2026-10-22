#!/usr/bin/env bash
# Runs inside a disposable CentOS 6 builder container with --network none.
# This is an UNSIGNED local file:// yum transaction smoke test, not a safe
# installation recipe. Never use gpgcheck=0 on a production host.
set -euo pipefail
repo="/preview/6/x86_64"
test -s "$repo/repodata/repomd.xml"
rpm -q sudo
before=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' sudo)
if [[ "$before" != "1.8.6p3-29.el6_10.3" ]]; then
    echo "FAIL: unexpected installed baseline sudo: $before" >&2
    exit 1
fi
cat > /etc/yum.repos.d/tree-candidate-local.repo <<'EOF'
[tree-candidate-local]
name=UNSIGNED TEMPORARY OFFLINE CENTOS 6 TEST ONLY
baseurl=file:///preview/6/x86_64/
enabled=0
gpgcheck=0
repo_gpgcheck=0
EOF
# No network access, no other repos, no plugin-based extra repos, single update.
yum --noplugins --disablerepo='*' --enablerepo=tree-candidate-local \
    --setopt=obsoletes=0 -y update sudo
after=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' sudo)
if [[ "$after" != "1.8.6p3-29.el6_10.3.tree1" ]]; then
    echo "FAIL: yum failed to upgrade to the exact candidate: $after" >&2
    exit 1
fi
sudo -V > /tmp/tree-sudo-version.txt
head -1 /tmp/tree-sudo-version.txt
echo "PASS: offline CentOS 6 yum transaction upgraded $before -> $after"
