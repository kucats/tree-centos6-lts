#!/usr/bin/env bash
# Executes only inside an ephemeral CentOS 6 container, after RPM candidate build.
set -euo pipefail
useradd -m -s /bin/sh centos6check
printf '%s\\n' 'centos6check ALL=(root) NOPASSWD: sudoedit /tmp/tree-allowed' >>/etc/sudoers
printf '%s\\n' 'baseline allowed' >/tmp/tree-allowed
printf '%s\\n' 'baseline protected' >/tmp/tree-protected
chmod 0644 /tmp/tree-allowed
chmod 0600 /tmp/tree-protected
run_case() {
  su -s /bin/sh centos6check -c "EDITOR='/bin/true -- /tmp/tree-protected' /usr/bin/sudoedit -n /tmp/tree-allowed"
}
# Vulnerable control must accept the malformed editor args, otherwise the test setup is invalid.
if ! run_case > /tmp/before.out 2>&1; then
  echo 'Baseline did not accept editor injection; this environment cannot validate the fix.' >&2
  cat /tmp/before.out >&2
  exit 1
fi
CANDIDATE=$(find /out -maxdepth 1 -type f -name 'sudo-*.x86_64.rpm' -print -quit)
test -n "$CANDIDATE"
rpm -Uvh --force --nodeps "$CANDIDATE"
# The patched candidate must reject the same inputs, not silently fall back.
if run_case > /tmp/after.out 2>&1; then
  echo 'FAIL: candidate accepted dangerous editor arguments' >&2
  exit 1
fi
grep -F 'editor arguments may not contain' /tmp/after.out
# And ordinary sudoedit behavior must still work.
su -s /bin/sh centos6check -c 'EDITOR=/bin/true /usr/bin/sudoedit -n /tmp/tree-allowed'
test "$(cat /tmp/tree-protected)" = 'baseline protected'
echo 'PASS: baseline accepted; candidate rejected; regular editor accepted'
