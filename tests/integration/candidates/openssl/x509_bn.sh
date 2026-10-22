#!/usr/bin/env bash
# Runs in a network-less CentOS 6 container: baseline openssl + openssl-devel installed,
# candidate RPMs in /out. Covers CVE-2020-1971, CVE-2023-0286 and CVE-2022-0778.
set -euo pipefail
cat > /tmp/gn.c <<'C'
#include <stdio.h>
#include <string.h>
#include <openssl/x509v3.h>
static GENERAL_NAME *der(const unsigned char *p, long n) {
    const unsigned char *q = p; GENERAL_NAME *g = d2i_GENERAL_NAME(NULL, &q, n);
    if (!g) { fprintf(stderr, "d2i failed\n"); _exit(3); } return g;
}
int main(int argc, char **argv) {
    if (!strcmp(argv[1], "edi")) {           /* EDIPARTYNAME without partyName */
        static const unsigned char e[] = {0xa5, 0x00};
        printf("edi_cmp=%d\n", GENERAL_NAME_cmp(der(e, 2), der(e, 2)));
    } else if (!strcmp(argv[1], "x400")) {   /* two different 5-byte X.400 addresses */
        static const unsigned char a[] = {0xa3, 0x05, 0x02, 0x03, 0x01, 0x02, 0x03};
        static const unsigned char b[] = {0xa3, 0x05, 0x02, 0x03, 0x04, 0x05, 0x06};
        printf("x400_same=%d x400_diff=%d\n",
               GENERAL_NAME_cmp(der(a, 7), der(a, 7)), GENERAL_NAME_cmp(der(a, 7), der(b, 7)));
    } else {                                 /* ordinary: equal and different DNS names */
        static const unsigned char d1[] = {0x82, 0x03, 'a', '.', 'b'};
        static const unsigned char d2[] = {0x82, 0x03, 'a', '.', 'c'};
        printf("dns_same=%d dns_diff=%d\n",
               GENERAL_NAME_cmp(der(d1, 5), der(d1, 5)) == 0, GENERAL_NAME_cmp(der(d1, 5), der(d2, 5)) != 0);
    }
    return 0;
}
C
cat > /tmp/sqrt.c <<'C'
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <openssl/bn.h>
/* Count BN_mod_sqrt calls that do not return within 2s for composite moduli. */
int main(int argc, char **argv) {
    static const unsigned long ps[] = {697, 1105, 2465, 4369, 10585};
    int hangs = 0, i; unsigned long a;
    for (i = 0; i < 5; i++) for (a = 2; a < 300; a++) {
        pid_t pid = fork();
        if (pid == 0) {
            BN_CTX *ctx = BN_CTX_new(); BIGNUM *A = BN_new(), *P = BN_new();
            alarm(2); BN_set_word(A, a); BN_set_word(P, ps[i]);
            BN_mod_sqrt(NULL, A, P, ctx); _exit(0);
        }
        int st; waitpid(pid, &st, 0);
        if (WIFSIGNALED(st) && WTERMSIG(st) == SIGALRM) { hangs++; if (hangs == 1) printf("first hang: a=%lu p=%lu\n", a, ps[i]); }
    }
    BN_CTX *ctx = BN_CTX_new(); BIGNUM *r = BN_new(), *A = BN_new(), *P = BN_new();
    BN_set_word(A, 4); BN_set_word(P, 7);
    int ok = BN_mod_sqrt(r, A, P, ctx) && (BN_get_word(r) == 2 || BN_get_word(r) == 5);
    printf("hangs=%d sqrt_4_mod_7_ok=%d\n", hangs, ok);
    return 0;
}
C
build() { gcc -o /tmp/gn /tmp/gn.c -lcrypto && gcc -o /tmp/sqrt /tmp/sqrt.c -lcrypto; }
run_edi() { local rc=0; /tmp/gn edi > /tmp/edi.out 2>&1 || rc=$?; echo "$rc"; }

build
rc=$(run_edi); echo "baseline edi rc=$rc $(cat /tmp/edi.out)"
[[ $rc -ge 128 ]] || { echo 'Baseline EDIPARTYNAME compare did not crash; cannot validate CVE-2020-1971.' >&2; exit 1; }
/tmp/gn x400 | tee /tmp/x400-before.out
grep -q 'x400_diff=0' /tmp/x400-before.out || { echo 'Baseline did not show the X.400 type confusion.' >&2; exit 1; }
/tmp/sqrt | tee /tmp/sqrt-before.out
grep -q 'hangs=0 ' /tmp/sqrt-before.out && { echo 'Baseline BN_mod_sqrt never hung; cannot validate CVE-2022-0778.' >&2; exit 1; }
/tmp/gn dns > /tmp/dns-before.out

rpm -Uvh --force --nodeps $(ls /out/openssl-1.0.1e-*.tree1.x86_64.rpm /out/openssl-devel-1.0.1e-*.tree1.x86_64.rpm)
rpm -q openssl | grep -q tree1
build
rc=$(run_edi); echo "candidate edi rc=$rc $(cat /tmp/edi.out)"
[[ $rc -eq 0 ]] && grep -q 'edi_cmp=-1' /tmp/edi.out
/tmp/gn x400 | tee /tmp/x400-after.out
grep -q 'x400_same=0 ' /tmp/x400-after.out && ! grep -q 'x400_diff=0' /tmp/x400-after.out
/tmp/sqrt | tee /tmp/sqrt-after.out
grep -q 'hangs=0 sqrt_4_mod_7_ok=1' /tmp/sqrt-after.out
/tmp/gn dns | tee /tmp/dns-after.out
diff /tmp/dns-before.out /tmp/dns-after.out && grep -q 'dns_same=1 dns_diff=1' /tmp/dns-after.out
openssl version
echo 'PASS: EDIPARTYNAME, X.400 and BN_mod_sqrt fixed; ordinary GENERAL_NAME compare and sqrt unchanged'
