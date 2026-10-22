#!/usr/bin/env bash
# Compiles the real historical SSL hostname-checker function in isolation.
# This does not prove every TLS backend or connection integration case.
set -euo pipefail
source_c="$1"
mode="$2"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
test -f "$source_c"
cat >"$tmp/check.c" <<'C'
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
static int Curl_raw_toupper(int ch) { return toupper((unsigned char)ch); }
static int Curl_raw_equal(const char *a, const char *b)
{
  return strcasecmp(a, b) == 0;
}
C
awk '/^#define HOST_NOMATCH/ {on=1} /^\/\* Quote from RFC2818/ {on=0} on {print}' "$source_c" >> "$tmp/check.c"
cat >>"$tmp/check.c" <<'C'
int main(int argc, char **argv)
{
  int normal = cert_hostcheck("*.example.com", "www.example.com");
  int exact = cert_hostcheck("WwW.Example.Com", "www.example.com");
  int partial = cert_hostcheck("x*.example.com", "xn--id.example.com");
  int deep = cert_hostcheck("*.example.com", "a.b.example.com");
  if(argc != 2 || !normal || !exact) {
    fprintf(stderr, "FAIL: legitimate certificate cases changed\n");
    return 2;
  }
  if(!strcmp(argv[1], "before")) {
    if(!partial || !deep) {
      fprintf(stderr, "FAIL: expected vulnerable baseline behavior was absent\n");
      return 3;
    }
  }
  else if(!strcmp(argv[1], "after")) {
    if(partial || deep) {
      fprintf(stderr, "FAIL: partial/deep wildcard still accepted\n");
      return 4;
    }
  }
  else return 5;
  printf("PASS: %s wildcard behavior: normal=%d exact=%d partial=%d deep=%d\n",
         argv[1], normal, exact, partial, deep);
  return 0;
}
C
if ! grep -q 'static int.*hostmatch' "$tmp/check.c"; then
  # historical source puts the declaration on its own line, so look for call
  grep -q 'hostmatch(' "$tmp/check.c"
fi
gcc -Wall -O0 -o "$tmp/check" "$tmp/check.c"
"$tmp/check" "$mode"
