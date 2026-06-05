#!/usr/bin/env bash
# Drive HTTP/2 traffic to observe the [L4]/[L7] logs in the Envoy terminal.
# Needs h2load:  brew install nghttp2
set -euo pipefail

if ! command -v h2load >/dev/null 2>&1; then
  echo "h2load not found. Install with: brew install nghttp2"
  echo "Fallback (one request):  curl --http2-prior-knowledge -s http://localhost:10000/stream"
  exit 1
fi

echo "== A) 10 streams over ONE connection on :10000 =="
echo "   expect in Envoy log: ONE [L4] write, TEN [L7] ...attested=attested-marker-v1"
h2load -n10 -c1 http://localhost:10000/stream-A

echo
echo "== B) 2 connections x (10 total) on :10000 =="
echo "   expect: TWO [L4] writes; all [L7] reads PRESENT"
h2load -n10 -c2 http://localhost:10000/stream-B

echo
echo "== C) :10001 has NO network write filter =="
echo "   expect: NO [L4] writes; all [L7] reads attested=ABSENT"
h2load -n5 -c1 http://localhost:10001/stream-C
