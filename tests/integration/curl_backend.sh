#!/usr/bin/env bash
# Runs only in an isolated, disposable CentOS 6 container after a candidate build.
# Inspect the *actual packaged curl* TLS backend. Source presence != reachable code.
set -euo pipefail

main_rpm=$(find /out -maxdepth 1 -type f -name 'curl-[0-9]*.x86_64.rpm' -print -quit)
lib_rpm=$(find /out -maxdepth 1 -type f -name 'libcurl-[0-9]*.x86_64.rpm' -print -quit)
test -s "$main_rpm" && test -s "$lib_rpm"

rpm -qp --requires "$lib_rpm" > /out/CURL-LIBCURL-REQUIRES.txt
# Installing packages is confined to this throwaway container, with no network.
rpm -Uvh --force --nodeps "$lib_rpm" "$main_rpm"
curl --version | tee /out/CURL-TLS-BACKEND.txt
if grep -Eiq '(^|[[:space:]])NSS/' /out/CURL-TLS-BACKEND.txt; then
  echo 'RESULT: NSS backend; curl upstream states CVE-2023-28321 wildcard code is not used with NSS.'
  echo 'Do not claim this runtime was vulnerable or that the patch fixed its TLS behavior.'
elif grep -Eiq '(^|[[:space:]])OpenSSL/' /out/CURL-TLS-BACKEND.txt; then
  echo 'RESULT: OpenSSL backend; vulnerable certificate checker could be reachable.'
  echo 'Isolated source-function tests alone are NOT full TLS integration tests.'
else
  echo 'RESULT: unknown or alternate TLS backend; manual reachability review required.'
fi
