#!/usr/bin/env bash
# Executes only inside an ephemeral, network-less CentOS 6 container, after RPM candidate build.
# CVE-2021-3156 ("Baron Samedit"): sudoedit -s/-i with a trailing backslash overflows user_args.
set -euo pipefail
useradd -m -s /bin/sh samedit        # no sudoers rights at all: the bug is pre-authentication
useradd -m -s /bin/sh shellcheck
printf '%s\n' 'shellcheck ALL=(root) NOPASSWD: ALL' >>/etc/sudoers
cat >/tmp/probe.sh <<'EOF'
#!/bin/sh
exec /usr/bin/sudoedit -n -s /
EOF
cat >/tmp/probe_login.sh <<'EOF'
#!/bin/sh
exec /usr/bin/sudoedit -n -i /
EOF
cat >/tmp/overflow.sh <<'EOF'
#!/bin/sh
exec /usr/bin/sudoedit -n -s '\' "$(head -c 65536 /dev/zero | tr '\0' A)"
EOF
cat >/tmp/shell_mode.sh <<'EOF'
#!/bin/sh
/usr/bin/sudo -n -s /bin/echo 'trail\' 'a b' && /usr/bin/sudo -n -i /bin/echo login-ok
EOF
chmod 0755 /tmp/probe.sh /tmp/probe_login.sh /tmp/overflow.sh /tmp/shell_mode.sh
as_user() { local user=$1; shift; su -s /bin/sh "$user" -c "$*"; }

# Baseline control: CentOS 6.10 sudo must still be vulnerable, otherwise this test proves nothing.
rc=0; as_user samedit /tmp/probe.sh >/tmp/before.out 2>&1 || rc=$?
if grep -q '^usage:' /tmp/before.out; then
  echo 'Baseline already rejects sudoedit -s; this environment cannot validate the fix.' >&2
  cat /tmp/before.out >&2
  exit 1
fi
echo "baseline sudoedit -s probe: rc=$rc (no usage error, i.e. vulnerable signature)"
rc=0; as_user samedit /tmp/overflow.sh >/tmp/before-overflow.out 2>&1 || rc=$?
echo "baseline overflow input: rc=$rc (informational; >=128 means the heap overflow crashed sudo)"
as_user shellcheck /tmp/shell_mode.sh >/tmp/before-shell.out 2>&1
CANDIDATE=$(find /out -maxdepth 1 -type f -name 'sudo-[0-9]*.x86_64.rpm' -print -quit)
test -n "$CANDIDATE"
rpm -Uvh --force --nodeps "$CANDIDATE"

# Patched candidate: every shell-mode sudoedit form must stop at the argument parser.
for probe in /tmp/probe.sh /tmp/probe_login.sh /tmp/overflow.sh; do
  rc=0; as_user samedit "$probe" >/tmp/after.out 2>&1 || rc=$?
  if [[ $rc -ne 1 ]] || ! grep -q '^usage:' /tmp/after.out; then
    echo "FAIL: candidate did not reject $probe with a usage error (rc=$rc)" >&2
    head -c 2000 /tmp/after.out >&2
    exit 1
  fi
done
# And sudo -s / -i must keep unescaping and running commands exactly as before.
as_user shellcheck /tmp/shell_mode.sh >/tmp/after-shell.out 2>&1
diff -u /tmp/before-shell.out /tmp/after-shell.out
printf '%s\n' 'trail\ a b' login-ok | diff -u - /tmp/after-shell.out
echo 'PASS: baseline vulnerable signature; candidate rejects sudoedit -s/-i; sudo -s/-i unchanged'
