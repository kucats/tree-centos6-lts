#!/usr/bin/env bash
# Runs in a network-less CentOS 6 container: baseline bind + bind-utils installed, candidate RPMs in /out.
# CVE-2021-25215: named aborts (INSIST) when a DNAME being chased is also the final answer.
set -euo pipefail
mkdir -p /tmp/ns && chmod 755 /tmp/ns
cat > /tmp/ns/named.conf <<'CONF'
options {
  directory "/tmp/ns"; pid-file "/tmp/ns/named.pid";
  listen-on port 5300 { 127.0.0.1; }; listen-on-v6 { none; };
  recursion no;
};
zone "example" { type master; file "example.db"; };
CONF
cat > /tmp/ns/example.db <<'ZONE'
$TTL 300
@     IN SOA ns.example. hostmaster.example. 1 3600 600 86400 300
@     IN NS  ns.example.
ns    IN A   127.0.0.1
www   IN A   192.0.2.1
self  IN DNAME example.
ZONE
chown -R named:named /tmp/ns
start() { named -u named -c /tmp/ns/named.conf -g > /tmp/ns/log 2>&1 & echo $! > /tmp/ns/pid.txt
  for i in $(seq 1 30); do dig +short +time=1 +tries=1 -p 5300 @127.0.0.1 example SOA > /dev/null 2>&1 && return 0; sleep 1; done
  cat /tmp/ns/log; return 1; }
alive() { kill -0 "$(cat /tmp/ns/pid.txt)" 2>/dev/null; }
stop() { kill "$(cat /tmp/ns/pid.txt)" 2>/dev/null || true; sleep 1; }
ask() { dig +time=2 +tries=1 -p 5300 @127.0.0.1 "$@" > /tmp/ns/dig.out 2>&1 || true; }
ordinary() { ask www.example A; grep -E '^www\.example\.' /tmp/ns/dig.out; ask x.self.example A; grep -E 'CNAME|DNAME' /tmp/ns/dig.out | awk '{print $1, $4, $5}' | sort; }

start
ordinary > /tmp/ordinary-before.out
ask self.self.example DNAME; sleep 1
if alive; then
  echo 'Baseline named survived the DNAME self-answer query; cannot validate CVE-2021-25215.' >&2
  tail -5 /tmp/ns/log >&2; stop; exit 1
fi
echo "baseline named died: $(grep -m1 -E 'INSIST|assertion|exiting' /tmp/ns/log || tail -1 /tmp/ns/log)"

rpm -Uvh --force --nodeps $(ls /out/bind-9.8.2-*.tree1.x86_64.rpm /out/bind-libs-9.8.2-*.tree1.x86_64.rpm \
  /out/bind-utils-9.8.2-*.tree1.x86_64.rpm)
rpm -q bind | grep -q tree1
start
ask self.self.example DNAME; sleep 1
alive || { echo 'FAIL: candidate named died' >&2; tail -5 /tmp/ns/log >&2; exit 1; }
grep -q 'status: NOERROR' /tmp/ns/dig.out && grep -E '^self\.example\..*DNAME' /tmp/ns/dig.out
ordinary > /tmp/ordinary-after.out
diff /tmp/ordinary-before.out /tmp/ordinary-after.out && cat /tmp/ordinary-after.out
stop
echo 'PASS: DNAME self-answer handled; ordinary A and DNAME-synthesized answers unchanged'
