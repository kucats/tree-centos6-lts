#!/usr/bin/env bash
# Runs INSIDE the disposable CentOS 6 repo container (build/Dockerfile.repo).
# Inputs:  /candidate (built RPMs), /keys/secret.asc, /meta/updateinfo.xml, /meta/release.json
# Env:     KEY_FPR (pinned fingerprint), OUT_UID/OUT_GID, optional TREE_SIGNING_PASSPHRASE
# Output:  /repo/6/x86_64 with signed RPMs, signed repomd.xml, updateinfo; public key and .repo file
set -euo pipefail
: "${KEY_FPR:?pinned signing key fingerprint required}"
pass="${TREE_SIGNING_PASSPHRASE:-}"
out=/repo/6/x86_64
mkdir -p "$out"
export GNUPGHOME=$(mktemp -d)
chmod 0700 "$GNUPGHOME"
gpg2 --batch --quiet --import /keys/secret.asc
if ! gpg2 --batch --with-colons --fingerprint --list-secret-keys "$KEY_FPR" | grep -q "^fpr:*$KEY_FPR:"; then
  echo "FAIL: imported secret key does not match pinned fingerprint $KEY_FPR" >&2
  exit 1
fi

# Copy exactly the RPMs named in the release manifest; nothing else is published.
python - /meta/release.json /candidate "$out" <<'PY'
import json, os, shutil, sys
manifest, src, dst = sys.argv[1:]
for u in json.load(open(manifest))['updates']:
    for name in u['rpms']:
        fn = '%s-%s-%s.%s.rpm' % (name, u['version'], u['release'], u['arch'])
        path = os.path.join(src, fn)
        assert os.path.isfile(path), 'missing built RPM ' + fn
        shutil.copy2(path, os.path.join(dst, fn))
        print('include ' + fn)
PY

cat > "$HOME/.rpmmacros" <<MACROS
%_signature gpg
%_gpg_name $KEY_FPR
%_gpg_path $GNUPGHOME
%__gpg /usr/bin/gpg2
%__gpg_sign_cmd %{__gpg} gpg2 --batch --no-verbose --no-armor --digest-algo sha256 --passphrase-fd 3 --no-secmem-warning -u "%{_gpg_name}" -sbo %{__signature_filename} %{__plaintext_filename}
MACROS
expect /work/scripts/rpm_addsign.exp "$out"/*.rpm

pub=/repo/RPM-GPG-KEY-tree-centos6-lts
gpg2 --batch --armor --export "$KEY_FPR" > "$pub"
rpm --import "$pub"
for f in "$out"/*.rpm; do
  rpm -K "$f"
  rpm -K "$f" | grep -q 'pgp.*OK$'
done

createrepo --quiet --checksum sha256 "$out"
modifyrepo /meta/updateinfo.xml "$out/repodata"
printf '%s' "$pass" | gpg2 --batch --yes --armor --digest-algo sha256 --passphrase-fd 0 \
  -u "$KEY_FPR" --detach-sign "$out/repodata/repomd.xml"
gpg2 --batch --verify "$out/repodata/repomd.xml.asc" "$out/repodata/repomd.xml"

python - /meta/release.json /repo/tree-centos6-lts.repo <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
open(sys.argv[2], 'w').write(
    '[tree-centos6-lts]\n'
    'name=tree CentOS 6 LTS security updates\n'
    'baseurl=%s\n'
    'enabled=1\n'
    'gpgcheck=1\n'
    'repo_gpgcheck=1\n'
    'gpgkey=%s\n' % (m['base_url'], m['key_url']))
PY
rm -rf "$GNUPGHOME"
chown -R "${OUT_UID:-0}:${OUT_GID:-0}" /repo
echo "PASS: signed RPMs and repomd.xml with $KEY_FPR"
