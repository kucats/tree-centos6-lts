#!/usr/bin/env bash
# Runs in a network-less CentOS 6 container: baseline krb5-libs + krb5-devel installed, candidate RPMs in /out.
# CVE-2022-42898: PAC buffer count and offset/size arithmetic overflows in krb5_pac_parse().
set -euo pipefail
cat > /tmp/pac.c <<'C'
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <krb5.h>
static void le32(unsigned char *p, unsigned long v) { int i; for (i = 0; i < 4; i++) p[i] = (v >> (8 * i)) & 0xff; }
static void le64(unsigned char *p, unsigned long long v) { int i; for (i = 0; i < 8; i++) p[i] = (v >> (8 * i)) & 0xff; }
int main(void) {
  krb5_context ctx; krb5_pac pac; krb5_data d; unsigned char b[64]; int r;
  krb5_init_context(&ctx);
  /* 1. buffer count that wraps the 32-bit header length */
  memset(b, 0, sizeof b); le32(b, 0x10000001UL);
  r = krb5_pac_parse(ctx, b, 64, &pac); printf("count=%s ", r == ERANGE ? "ERANGE" : r ? "other" : "accepted");
  /* 2. one buffer whose 64-bit Offset + size wraps around */
  memset(b, 0, sizeof b); le32(b, 1); le32(b + 8, 1); le32(b + 12, 16); le64(b + 16, 0xFFFFFFFFFFFFFFF8ULL);
  r = krb5_pac_parse(ctx, b, 64, &pac); printf("offset=%s ", r == ERANGE ? "ERANGE" : r ? "other" : "accepted");
  /* 3. ordinary well-formed PAC with one 8-byte buffer */
  memset(b, 0, sizeof b); le32(b, 1); le32(b + 8, 1); le32(b + 12, 8); le64(b + 16, 24); memcpy(b + 24, "ABCDEFGH", 8);
  r = krb5_pac_parse(ctx, b, 32, &pac);
  if (!r) r = krb5_pac_get_buffer(ctx, pac, 1, &d);
  printf("ordinary=%s\n", !r && d.length == 8 && !memcmp(d.data, "ABCDEFGH", 8) ? "ok" : "bad");
  return 0;
}
C
gcc -o /tmp/pac /tmp/pac.c -lkrb5
rc=0; /tmp/pac > /tmp/before.out 2>&1 || rc=$?
echo "baseline rc=$rc $(cat /tmp/before.out)"
if [[ $rc -eq 0 ]] && ! grep -q 'offset=accepted' /tmp/before.out && grep -q 'count=ERANGE' /tmp/before.out; then
  echo 'Baseline already rejects both malformed PACs; cannot validate CVE-2022-42898.' >&2; exit 1
fi
rpm -Uvh --force --nodeps $(ls /out/krb5-libs-1.10.3-*.tree1.x86_64.rpm /out/krb5-devel-1.10.3-*.tree1.x86_64.rpm)
rpm -q krb5-libs | grep -q tree1
gcc -o /tmp/pac /tmp/pac.c -lkrb5
/tmp/pac | tee /tmp/after.out
grep -q 'count=ERANGE offset=ERANGE ordinary=ok' /tmp/after.out
echo 'PASS: malformed PAC counts and offsets rejected; well-formed PAC parsed as before'
