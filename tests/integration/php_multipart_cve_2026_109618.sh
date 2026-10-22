#!/usr/bin/env bash
# Runs inside the disposable CentOS 6 php image with --network none, after the candidate build.
# CVE-2026-109618/109619: unbounded multipart part count and per-part header retention.
set -euo pipefail
cat > /tmp/form.php <<'PHP'
<?php
echo "post=", count($_POST), "\n";
if (isset($_FILES['f'])) { echo "file=", $_FILES['f']['size'], " ", md5_file($_FILES['f']['tmp_name']), "\n"; }
PHP
python - <<'PY'
def body(fields, junk_headers=0, with_file=False):
    out = []
    for i in range(fields):
        out.append('--B\r\nContent-Disposition: form-data; name="v%d"\r\n' % i)
        out.extend('X-Junk: %d\r\n' % j for j in range(junk_headers))
        out.append('\r\nx%d\r\n' % i)
    if with_file:
        out.append('--B\r\nContent-Disposition: form-data; name="f"; filename="a.bin"\r\n'
                   'Content-Type: application/octet-stream\r\n\r\n' + 'A' * 4096 + '\r\n')
    out.append('--B--\r\n')
    return ''.join(out)
open('/tmp/small.body', 'w').write(body(3, with_file=True))
open('/tmp/many.body', 'w').write(body(5000))
PY
run() {  # body-file
  REDIRECT_STATUS=1 REQUEST_METHOD=POST SCRIPT_FILENAME=/tmp/form.php \
  CONTENT_TYPE='multipart/form-data; boundary=B' CONTENT_LENGTH=$(stat -c %s "$1") \
  php-cgi -n -d max_input_vars=1000 -d max_file_uploads=20 -d display_errors=1 \
    -d error_reporting=-1 -d log_errors=0 -d upload_tmp_dir=/tmp < "$1" 2>&1
}
php -v > /tmp/before-version.txt 2>&1; head -1 /tmp/before-version.txt
run /tmp/small.body > /tmp/before-small.out
run /tmp/many.body > /tmp/before-many.out
if grep -q 'Multipart body parts limit exceeded' /tmp/before-many.out; then
  echo 'Baseline already limits multipart parts; cannot validate the fix.' >&2; exit 1
fi
echo "baseline 5000-part body: $(grep -o 'post=[0-9]*' /tmp/before-many.out)"

rpm -Uvh --force --nodeps $(ls /out/php-common-5.3.3-*.tree1.x86_64.rpm /out/php-cli-5.3.3-*.tree1.x86_64.rpm)
rc=0; php -v > /tmp/after-version.txt 2>&1 || rc=$?
cat /tmp/after-version.txt
[[ $rc -eq 0 ]] && grep -q '^PHP 5.3.3' /tmp/after-version.txt
rpm -q php-cli php-common > /tmp/after-rpm.txt; cat /tmp/after-rpm.txt
[[ $(grep -c tree1 /tmp/after-rpm.txt) -eq 2 ]]
run /tmp/small.body > /tmp/after-small.out
run /tmp/many.body > /tmp/after-many.out
if ! grep -q 'Multipart body parts limit exceeded' /tmp/after-many.out; then
  echo 'FAIL: candidate did not enforce the multipart part limit' >&2; head -c 2000 /tmp/after-many.out >&2; exit 1
fi
grep -m1 'Multipart body parts limit exceeded' /tmp/after-many.out
# Ordinary forms and uploads are unchanged.
diff -u <(grep -E '^(post|file)=' /tmp/before-small.out) <(grep -E '^(post|file)=' /tmp/after-small.out)
grep -q '^post=3$' /tmp/after-small.out
grep -q "^file=4096 $(head -c 4096 /dev/zero | tr '\0' A | md5sum | cut -d' ' -f1)$" /tmp/after-small.out
echo 'PASS: baseline parses unbounded parts; candidate enforces the part limit; ordinary form and upload unchanged'
