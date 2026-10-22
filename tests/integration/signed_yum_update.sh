#!/usr/bin/env bash
# Runs inside a disposable CentOS 6 container (build/Dockerfile.repo) with --network none.
# /repo: signed repository output, /candidate: the unsigned build. No secret key is present here.
set -euo pipefail
repo=/repo/6/x86_64
key=/repo/RPM-GPG-KEY-tree-centos6-lts
test -s "$repo/repodata/repomd.xml.asc" && test -s "$key"
before=$(rpm -q --qf '%{VERSION}-%{RELEASE}' sudo)
[[ "$before" == "1.8.6p3-29.el6_10.3" ]]

write_repo() {  # id baseurl repo_gpgcheck
  cat > "/etc/yum.repos.d/$1.repo" <<REPO
[$1]
name=$1
baseurl=file://$2/
enabled=0
gpgcheck=1
repo_gpgcheck=$3
gpgkey=file://$key
REPO
}
yum_only() { local id=$1; shift; yum -q --disablerepo='*' --enablerepo="$id" -y "$@"; }
expect_fail() {
  local what=$1; shift
  if "$@" >/tmp/neg.out 2>&1; then
    echo "FAIL: $what was accepted" >&2; cat /tmp/neg.out >&2; exit 1
  fi
  [[ "$(rpm -q --qf '%{VERSION}-%{RELEASE}' sudo)" == "$before" ]]
  echo "PASS: rejected $what"; tail -2 /tmp/neg.out
}

# 1. Metadata altered after signing must be refused by repo_gpgcheck.
cp -a "$repo" /tmp/tampered-md
sed -i 's#</repomd>#<!-- tampered --></repomd>#' /tmp/tampered-md/repodata/repomd.xml
write_repo tree-tampered-md /tmp/tampered-md 1
expect_fail 'tampered repomd.xml' yum_only tree-tampered-md --noplugins update sudo

# 2. Unsigned RPMs must be refused by gpgcheck even with otherwise valid metadata.
mkdir -p /tmp/unsigned
cp /candidate/sudo-1.8.6p3-29.el6_10.3.tree1.x86_64.rpm /tmp/unsigned/
createrepo --quiet --checksum sha256 /tmp/unsigned
write_repo tree-unsigned /tmp/unsigned 0
expect_fail 'unsigned sudo RPM' yum_only tree-unsigned --noplugins update sudo

# 3. The signed repository: security errata are visible and yum updates sudo.
write_repo tree-centos6-lts "$repo" 1
yum_only tree-centos6-lts updateinfo list security > /tmp/updateinfo.out 2>&1 || true
cat /tmp/updateinfo.out
grep -q 'TREE-2026:0001' /tmp/updateinfo.out
yum_only tree-centos6-lts --security check-update > /tmp/security.out 2>&1 || true
grep -q 'sudo' /tmp/security.out
yum_only tree-centos6-lts --noplugins update sudo
after=$(rpm -q --qf '%{VERSION}-%{RELEASE}' sudo)
[[ "$after" == "1.8.6p3-29.el6_10.3.tree1" ]]
rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE} %{RSAHEADER:pgpsig}\n' sudo
sudo -V > /tmp/sudo-version.txt 2>&1; head -1 /tmp/sudo-version.txt
echo "PASS: signed yum update $before -> $after with gpgcheck=1 repo_gpgcheck=1"
