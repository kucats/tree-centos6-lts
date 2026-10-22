#!/usr/bin/env bash
# No network, no malicious libraries and no remote agent forwarding.
# Validate regular signing while PKCS11 agent protocol requests are denied.
set -euo pipefail
candidate=$(find /out -maxdepth 1 -name 'openssh-clients-[0-9]*.x86_64.rpm' -type f -print -quit)
test -s "$candidate"
rpm -qp --qf '%{NAME}\n' "$candidate" | grep -qx openssh-clients
rpm -Uvh --force --nodeps "$candidate"
test -x /usr/bin/ssh-agent && test -x /usr/bin/ssh-add
temp=$(mktemp -d)
trap 'if test -f "$temp/agentpid"; then kill "$(cat "$temp/agentpid")" 2>/dev/null || true; fi; rm -rf "$temp"' EXIT
chmod 0700 "$temp"
# Use explicit test key and isolated Unix socket, never a production key.
ssh-keygen -q -t rsa -b 2048 -N '' -f "$temp/id_rsa"
eval "$(ssh-agent -s -a "$temp/agent.sock")"
printf '%s\n' "$SSH_AGENT_PID" > "$temp/agentpid"
export SSH_AUTH_SOCK
ssh-add "$temp/id_rsa" >/tmp/tree-ssh-add.out 2>&1
ssh-add -l | grep -E 'RSA|rsa' 
echo 'PASS: ordinary RSA key add/list works'

# Observe protocol 20 and 26/21 directly without an executable provider library.
# These messages should fail before parsing strings or loading any modules.
python - "$SSH_AUTH_SOCK" <<'PY'
import socket, struct, sys
sockpath = sys.argv[1]
for typ in (20, 21, 26):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    client.connect(sockpath)
    # Type-only request intentionally carries no library path or PIN.
    payload = chr(typ)
    client.sendall(struct.pack(">I", len(payload)) + payload)
    def read_exact(count):
        buf = ''
        while len(buf) < count:
            chunk = client.recv(count - len(buf))
            if not chunk:
                raise AssertionError("agent closed early")
            buf += chunk
        return buf
    length = struct.unpack(">I", read_exact(4))[0]
    assert length == 1, (typ, length)
    status = ord(read_exact(1))
    assert status == 5, (typ, status)  # SSH_AGENT_FAILURE
    client.close()
    print("PASS: PKCS11 agent request type %d denied safely" % typ)
PY
