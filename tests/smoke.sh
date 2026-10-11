#!/bin/sh
# Headless smoke test for the Audit Row Reader.
#   sh tests/smoke.sh            python tests, then the page self-check (core and page checks)
#   sh tests/smoke.sh --bench    also time a 100,000-row load with a seal
# Exits non-zero if anything fails. Needs Google Chrome; node 22+ gives real timings over the
# DevTools protocol on 127.0.0.1, otherwise it falls back to --dump-dom with a virtual clock.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
URL="file://$HERE/index.html?selfcheck"
fail=0

echo "== python tests (-W error)"
(cd "$HERE" && python3 -W error -m unittest discover -s tests) || fail=1

echo "== page self-check"
if command -v node >/dev/null 2>&1 && node -e 'process.exit(typeof WebSocket === "function" ? 0 : 1)' 2>/dev/null; then
  out=$(node "$HERE/tests/cdp.mjs" "$URL" 120); code=$?
  echo "$out"
  [ $code -eq 0 ] || fail=1
  if [ "${1:-}" = "--bench" ]; then
    echo "== bench: 100,000 rows with a seal"
    node "$HERE/tests/cdp.mjs" "file://$HERE/index.html?bench=100000&benchseal" 240 || fail=1
  fi
else
  body=$("$CHROME" --headless=new --disable-gpu --virtual-time-budget=60000 --dump-dom "$URL" 2>/dev/null | grep -o '<body[^>]*>' | head -1)
  echo "$body"
  echo "$body" | grep -q 'data-selfcheck="pass"' || fail=1
fi

if [ $fail -eq 0 ]; then echo "SMOKE PASS"; else echo "SMOKE FAIL"; fi
exit $fail
