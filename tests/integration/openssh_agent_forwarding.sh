#!/usr/bin/env bash
# Entire test runs in a disposable --network none CentOS 6 container.
# The only listener is loopback sshd. No production secrets or external hosts.
set -euo pipefail
tmp=$(mktemp -d)
cleanup() {
  if test -f "$tmp/sshd.pid"; then kill "$(cat "$tmp/sshd.pid")" 2>/dev/null || true; fi
  if test -f "$tmp/agent.pid"; then kill "$(cat "$tmp/agent.pid")" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
chmod 0700 "$tmp"
candidate=$(find /out -maxdepth 1 -name 'openssh-clients-[0-9]*.x86_64.rpm' -print -quit)
test -s "$candidate"
mkdir "$tmp/payload"
(cd "$tmp/payload" && rpm2cpio "$candidate" | cpio -idmu --quiet)
export PATH="$tmp/payload/usr/bin:$PATH"
test -x "$tmp/payload/usr/bin/ssh-agent"
test -x "$tmp/payload/usr/bin/ssh"
ssh-keygen -q -t rsa -b 2048 -N '' -f "$tmp/key"
ssh-keygen -q -t rsa -b 2048 -N '' -f "$tmp/hostkey"
cp "$tmp/key.pub" "$tmp/authorized_keys"
chmod 0600 "$tmp/authorized_keys"
cat > "$tmp/sshd_config" <<EOF
Port 22220
ListenAddress 127.0.0.1
HostKey $tmp/hostkey
PidFile $tmp/sshd_pid
AuthorizedKeysFile $tmp/authorized_keys
PermitRootLogin yes
StrictModes no
PasswordAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
UsePAM no
UsePrivilegeSeparation no
AllowAgentForwarding yes
AllowTcpForwarding no
X11Forwarding no
LogLevel VERBOSE
EOF
gcc -shared -fPIC -o "$tmp/probe.so" /tests/ssh_agent_provider_probe.c
export TREE_AGENT_PROBE_MARKER="$tmp/module-was-loaded"
test ! -e "$TREE_AGENT_PROBE_MARKER"
/usr/sbin/sshd -t -f "$tmp/sshd_config"
/usr/sbin/sshd -D -e -f "$tmp/sshd_config" > "$tmp/sshd.log" 2>&1 &
echo "$!" > "$tmp/sshd.pid"
eval "$(ssh-agent -s -a "$tmp/agent.sock")"
echo "$SSH_AGENT_PID" > "$tmp/agent.pid"
export SSH_AUTH_SOCK
ssh-add "$tmp/key" >/dev/null 2>&1
connection() {
  ssh -A -T -p 22220 -i "$tmp/key" \
    -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 \
    -o PreferredAuthentications=publickey root@127.0.0.1 "$@"
}
connected=0
for i in $(seq 1 12); do
  if connection 'echo local-connected' > "$tmp/login.log" 2>&1; then
    connected=1
    break
  fi
  sleep 1
done
if test "$connected" -ne 1; then
  echo 'FAIL: loopback sshd login could not be established' >&2
  cat "$tmp/sshd.log" "$tmp/login.log" >&2
  exit 1
fi
echo 'PASS: candidate SSH client authenticated to isolated loopback sshd'

connection python - "$tmp/probe.so" <<'PY'
import os, socket, struct, sys
path = os.environ.get('SSH_AUTH_SOCK')
assert path and os.path.exists(path), 'no forwarded agent socket'
def string(value):
    return struct.pack('>I', len(value)) + value
def recv_exact(sock, count):
    result = ''
    while len(result) < count:
        part = sock.recv(count - len(result))
        assert part
        result += part
    return result
for typ in (20, 21, 26):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(5)
    conn.connect(path)
    payload = chr(typ) + string(sys.argv[1]) + string('')
    conn.sendall(struct.pack('>I', len(payload)) + payload)
    length = struct.unpack('>I', recv_exact(conn, 4))[0]
    assert length == 1, (typ, length)
    assert ord(recv_exact(conn, 1)) == 5, typ
    conn.close()
    print('PASS: forwarded well-formed PKCS11 request %d denied' % typ)
PY
test ! -e "$TREE_AGENT_PROBE_MARKER" || {
  echo 'FAIL: forwarded request loaded a module' >&2
  exit 1
}
connection ssh-add -l | grep -Ei 'rsa'
echo 'PASS: forwarded agent still lists ordinary RSA key'
echo 'PASS: no provider module loaded over real forwarded-agent socket'
