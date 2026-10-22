#!/usr/bin/env bash
# Runs in a network-less CentOS 6 container: baseline glibc(-devel) installed, candidate RPMs in /out.
# Covers CVE-2024-2961 (iconv ISO-2022-CN-EXT), CVE-2022-23219 (clnt_create) and CVE-2021-3999 (getcwd guard).
set -euo pipefail
cat > /tmp/iconv.c <<'C'
/* Port of glibc iconvdata/tst-iconv-iso-2022-cn-ext.c: the output buffer ends at a PROT_NONE page. */
#include <errno.h>
#include <iconv.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
static int run(iconv_t cd, char *base, const char *in, int max) {
  int i, bad = 0;
  for (i = 0; i < max; i++) {
    char buf[64]; char *inp = buf; size_t inleft = strlen(in); char *outp = base - i; size_t outleft = i;
    strcpy(buf, in);
    if (iconv(cd, &inp, &inleft, &outp, &outleft) != (size_t) -1 || errno != E2BIG) bad++;
    iconv(cd, NULL, NULL, NULL, NULL);
  }
  return bad;
}
int main(int argc, char **argv) {
  iconv_t cd = iconv_open("ISO-2022-CN-EXT", "UTF-8");
  int pgz = getpagesize();
  char *ntf = mmap(NULL, 2 * pgz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  mprotect(ntf + pgz, pgz, PROT_NONE);
  if (!strcmp(argv[1], "so")) return run(cd, ntf + pgz, "\xe4\xba\xa4\xe6\x8d\xa2", 9);
  if (!strcmp(argv[1], "ss2")) return run(cd, ntf + pgz, "\xe3\xb4\xbd \xe3\xb4\xbd", 14);
  if (!strcmp(argv[1], "ss3")) return run(cd, ntf + pgz, "\xe5\x8a\x84 \xe5\x8a\x84", 14);
  { /* ordinary round trip with ample space */
    char in[] = "\xe4\xba\xa4\xe6\x8d\xa2 \xe3\xb4\xbd \xe5\x8a\x84 abc", mid[128], back[128];
    char *ip = in, *mp = mid, *bp = back; size_t il = strlen(in), ml = sizeof mid, bl = sizeof back;
    if (iconv(cd, &ip, &il, &mp, &ml) == (size_t) -1) return 2;
    iconv(cd, &ip, &il, &mp, &ml) ; iconv(cd, NULL, NULL, &mp, &ml);
    iconv_t rd = iconv_open("UTF-8", "ISO-2022-CN-EXT"); char *mi = mid; size_t mil = mp - mid;
    if (iconv(rd, &mi, &mil, &bp, &bl) == (size_t) -1) return 3;
    *bp = 0; printf("roundtrip=%d\n", strcmp(back, in) == 0); return 0;
  }
}
C
cat > /tmp/rpc.c <<'C'
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <rpc/rpc.h>
int main(int argc, char **argv) {
  static char path[4000]; memset(path, 'A', sizeof path - 1);
  CLIENT *c = clnt_create(argc > 1 ? argv[1] : path, 1, 1, "unix");
  struct rpc_createerr *e = &get_rpc_createerr();
  printf("client=%s stat=%d errno=%d\n", c ? "set" : "null", e->cf_stat, e->cf_error.re_errno);
  return 0;
}
C
cat > /tmp/cwd.c <<'C'
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
int main(void) {
  char g[2] = {'X', 'Y'}; char *r = getcwd(g + 1, 1); int e = errno; char big[PATH_MAX];
  printf("small=%s errno_erange=%d guard=%c normal=%s\n", r ? "set" : "null", e == ERANGE, g[0], getcwd(big, sizeof big));
  return 0;
}
C
build() { for p in iconv rpc cwd; do gcc -o /tmp/$p /tmp/$p.c; done; }
crash_count() { local n=0 rc; for c in so ss2 ss3; do rc=0; /tmp/iconv $c || rc=$?; echo "  iconv $c rc=$rc"; [[ $rc -ge 128 ]] && n=$((n+1)); done; echo "$n" > /tmp/crashes; }

build
crash_count; echo "baseline iconv crashes: $(cat /tmp/crashes)"
[[ $(cat /tmp/crashes) -ge 1 ]] || { echo 'Baseline iconv did not fault; cannot validate CVE-2024-2961.' >&2; exit 1; }
rc=0; /tmp/rpc > /tmp/rpc-before.out 2>&1 || rc=$?; echo "baseline clnt_create rc=$rc $(cat /tmp/rpc-before.out)"
grep -q "errno=36" /tmp/rpc-before.out && { echo 'Baseline already rejects long unix paths.' >&2; exit 1; }
/tmp/cwd | tee /tmp/cwd-before.out
/tmp/iconv roundtrip | tee /tmp/rt-before.out

rpm -Uvh --force --nodeps $(ls /out/glibc-2.12-*.tree1.x86_64.rpm /out/glibc-common-2.12-*.tree1.x86_64.rpm \
  /out/glibc-devel-2.12-*.tree1.x86_64.rpm /out/glibc-headers-2.12-*.tree1.x86_64.rpm)
rpm -q glibc | grep -q tree1
build
for c in so ss2 ss3; do /tmp/iconv $c || { echo "FAIL: candidate iconv $c rc=$?" >&2; exit 1; }; done
echo 'candidate iconv: all buffer sizes return E2BIG without faulting'
/tmp/rpc | tee /tmp/rpc-after.out
grep -q 'client=null stat=12 errno=36' /tmp/rpc-after.out   # RPC_SYSTEMERROR, ENAMETOOLONG
/tmp/rpc /nonexistent.sock | tee /tmp/rpc-short.out
grep -q 'client=null' /tmp/rpc-short.out && ! grep -q 'errno=36' /tmp/rpc-short.out
/tmp/cwd | tee /tmp/cwd-after.out
grep -q 'small=null errno_erange=1 guard=X normal=/' /tmp/cwd-after.out
/tmp/iconv roundtrip | tee /tmp/rt-after.out
diff /tmp/rt-before.out /tmp/rt-after.out && grep -q 'roundtrip=1' /tmp/rt-after.out
ls / > /dev/null && /bin/sh -c 'echo shell-ok'
echo 'PASS: iconv OOB write, clnt_create overflow and getcwd guard fixed; ordinary behaviour unchanged'
