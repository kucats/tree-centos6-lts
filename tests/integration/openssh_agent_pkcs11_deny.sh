#!/usr/bin/env bash
# No network, no malicious libraries and no remote agent forwarding.
# Validate regular signing while PKCS11 agent protocol requests are denied.
set -euo pipefail
candidate=$(find /out -maxdepth 1 -name 'openssh-clients-[0-9]*.x86_64.rpm' -type f -print -quit)
test -s "$candidate"
rpm -qp --qf '%{NAME}\n' "$candidate" | grep -qx openssh-clients
# Extract, do not install RPM inside the runtime sandbox: rpm file conflicts
# and immutable-hmac attributes are unrelated to the agent protocol regression.
temp=$(mktemp -d)
trap 'if test -f "$temp/agentpid"; then kill "$(cat "$temp/agentpid")" 2>/dev/null || true; fi; rm -rf "$temp"' EXIT
chmod 0700 "$temp"
mkdir -p "$temp/package"
(cd "$temp/package" && rpm2cpio "$candidate" | cpio -idmu --quiet)
test -x "$temp/package/usr/bin/ssh-agent" && test -x "$temp/package/usr/bin/ssh-add"
export PATH="$temp/package/usr/bin:$PATH"
echo 'PASS: running exact candidate RPM payload binaries in isolated filesystem'
# Full ELF ABI review is separate. The dependency list must not regress.
readelf -d /usr/bin/ssh-agent | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' | sort > "$temp/baseline-libs"
readelf -d "$temp/package/usr/bin/ssh-agent" | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' | sort > "$temp/candidate-libs"
test -s "$temp/baseline-libs" && test -s "$temp/candidate-libs"
comm -13 "$temp/baseline-libs" "$temp/candidate-libs" > "$temp/new-needed"
comm -23 "$temp/baseline-libs" "$temp/candidate-libs" > "$temp/removed-needed"
if test -s "$temp/new-needed"; then
  echo 'FAIL: new ssh-agent ELF dependencies were introduced' >&2
  cat "$temp/new-needed" >&2
  exit 1
fi
if test -s "$temp/removed-needed"; then
  grep -qx 'libplc4.so' "$temp/removed-needed"
  test "$(wc -l < "$temp/removed-needed")" -eq 1
  echo 'PASS: only audited NSS-token-related libplc4.so dependency was removed'
else
  echo 'PASS: ssh-agent ELF DT_NEEDED dependency set unchanged'
fi
echo 'PASS: ssh-agent ELF DT_NEEDED introduces no new libraries'
# Benign dynamic library contains only a constructor marker, no PKCS11 API.
# If even a failed provider load occurs, the constructor must not execute.
gcc -shared -fPIC -o "$temp/probe.so" /tests/ssh_agent_provider_probe.c
export TREE_AGENT_PROBE_MARKER="$temp/provider-loaded"
test ! -e "$TREE_AGENT_PROBE_MARKER"
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
python - "$SSH_AUTH_SOCK" "$temp/probe.so" <<'PY'
import socket, struct, sys
sockpath = sys.argv[1]
provider_path = sys.argv[2]
# Confirm the agent still performs an actual SSH2 signature using the test key.
# No server, network or privileged target is involved.
import base64, subprocess
p = subprocess.Popen(["ssh-add", "-L"], stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
output, errors = p.communicate()
assert p.returncode == 0, errors
line = output.strip().splitlines()[0].split()
assert line[0] == "ssh-rsa", line[0]
public_blob = base64.b64decode(line[1])
def string(value):
    return struct.pack(">I", len(value)) + value
probe = "centos6-ssh-agent-benign-test"
sign_payload = chr(13) + string(public_blob) + string(probe) + struct.pack(">I", 0)
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(5)
client.connect(sockpath)
client.sendall(struct.pack(">I", len(sign_payload)) + sign_payload)
def read_exact(sock, count):
    result = ''
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise AssertionError("unexpected socket EOF")
        result += chunk
    return result
size = struct.unpack(">I", read_exact(client, 4))[0]
assert 1 < size < 8192, size
reply = read_exact(client, size)
assert ord(reply[0]) == 14, ord(reply[0])  # SSH2_AGENT_SIGN_RESPONSE
siglen = struct.unpack(">I", reply[1:5])[0]
assert siglen >= 16 and siglen == len(reply) - 5, siglen
client.close()
print("PASS: normal SSH2 agent RSA signature response retained")

for typ in (20, 21, 26, 30, 31, 32):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    client.connect(sockpath)
    # Syntactically well-formed request: provider path plus empty PIN.
    # Without this, even a vulnerable unpatched agent may return FAILURE.
    if typ in (30, 31, 32):
        # Red Hat NSS agent extension: token, key label and PIN.
        payload = chr(typ) + string("ProbeToken") + string("ProbeKey") + string("")
    else:
        payload = chr(typ) + string(provider_path) + string("")
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
    print("PASS: valid PKCS11 agent request type %d denied" % typ)
PY
test ! -e "$TREE_AGENT_PROBE_MARKER" || {
  echo 'FAIL: agent executed benign provider constructor' >&2
  exit 1
}
echo 'PASS: syntactically valid requests did not load a benign shared object'
