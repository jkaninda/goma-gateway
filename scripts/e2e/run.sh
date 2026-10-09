#!/usr/bin/env bash
#
# End-to-end test: builds the gateway, runs it as a real process against mock
# backends on free loopback ports, and checks behaviour over HTTP and signals.
#
#   scripts/e2e/run.sh            run every check
#   KEEP=1 scripts/e2e/run.sh     keep the work directory (config, logs)
#
# Needs: go, curl. Exits non-zero if any check fails.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/goma-e2e.XXXXXX")"
PIDS=()
FAILED=0
GW=""

cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [[ "${KEEP:-}" == "1" || "$FAILED" != "0" ]]; then
    echo "work directory kept: $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILED=$((FAILED + 1)); }

# expect NAME WANT GOT
expect() {
  if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (want $2, got $3)"; fi
}

# code METHOD URL [curl args...] -> HTTP status, 000 when unreachable
code() {
  local method=$1 url=$2; shift 2
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X "$method" "$@" "$url" || true
}

body() { curl -s --max-time 5 "$1" || true; }

# wait_for URL WANT_CODE SECONDS -> 0 when URL answers WANT_CODE in time
wait_for() {
  local url=$1 want=$2 tries=$(($3 * 20))
  for ((i = 0; i < tries; i++)); do
    [[ "$(code GET "$url")" == "$want" ]] && return 0
    sleep 0.05
  done
  return 1
}

# wait_exit PID SECONDS -> sets EXIT_CODE to the process's exit code, or 124
# if it was still running and had to be killed. Not called through $(...):
# only this shell can wait on its own child.
wait_exit() {
  local pid=$1 tries=$(($2 * 10))
  EXIT_CODE=124
  for ((i = 0; i < tries; i++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      EXIT_CODE=0
      wait "$pid" || EXIT_CODE=$?
      return
    fi
    sleep 0.1
  done
  kill -9 "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

start_gateway() {
  GOMA_PPROF_ADDR="127.0.0.1:$PPROF" "$WORK/goma" server -c "$WORK/goma.yml" >"$WORK/gateway.log" 2>&1 &
  GW=$!
  PIDS+=("$GW")
  if ! wait_for "$GATEWAY/readyz" 200 20; then
    fail "gateway did not become ready (log: $WORK/gateway.log)"
    exit 1
  fi
}

echo "==> Building"
go build -o "$WORK/goma" "$ROOT"
go build -o "$WORK/backend" "$ROOT/scripts/e2e/backend"

read -r WEB WEB_SECURE PORT_A PORT_B PORT_DEAD PPROF <<<"$("$WORK/backend" -free-ports 6)"
GATEWAY="http://127.0.0.1:$WEB"
BACKEND_A="http://127.0.0.1:$PORT_A"
BACKEND_B="http://127.0.0.1:$PORT_B"
BACKEND_DEAD="http://127.0.0.1:$PORT_DEAD" # nothing listens here

"$WORK/backend" -addr "127.0.0.1:$PORT_A" -name a &
PIDS+=($!)
"$WORK/backend" -addr "127.0.0.1:$PORT_B" -name b &
PIDS+=($!)

mkdir -p "$WORK/providers"
cat >"$WORK/goma.yml" <<EOF
version: "2"
gateway:
  log:
    level: info
  entryPoints:
    web:
      address: "127.0.0.1:$WEB"
    webSecure:
      address: "127.0.0.1:$WEB_SECURE"
  monitoring:
    enableMetrics: true
  providers:
    file:
      enabled: true
      directory: $WORK/providers
      watch: true
      debounce: 50ms
  routes:
    - name: single
      path: /single
      methods: [GET]
      target: $BACKEND_A
    - name: private
      path: /private
      target: $BACKEND_A
      middlewares: [basic-auth]
    - name: failover
      path: /failover
      backends:
        - endpoint: $BACKEND_DEAD
        - endpoint: $BACKEND_A
middlewares:
  - name: basic-auth
    type: basicAuth
    paths: ["/.*"]
    rule:
      realm: e2e
      users:
        - username: admin
          password: \$2y\$05\$TIx7l8sJWvMFXw4n0GbkQuOhemPQOormacQC4W1p28TOVzJtx.XpO # admin
EOF

for port in "$PORT_A" "$PORT_B"; do
  wait_for "http://127.0.0.1:$port/" 200 10 || { fail "mock backend on $port did not start"; exit 1; }
done

echo "==> Starting gateway on $GATEWAY"
start_gateway

echo "==> Routing"
expect "readyz" 200 "$(code GET "$GATEWAY/readyz")"
expect "GET /single reaches backend a" a "$(body "$GATEWAY/single")"
expect "POST /single is 405" 405 "$(code POST "$GATEWAY/single")"
expect "unknown path is 404" 404 "$(code GET "$GATEWAY/nope")"

echo "==> Basic auth"
expect "no credentials is 401" 401 "$(code GET "$GATEWAY/private")"
expect "wrong password is 401" 401 "$(code GET "$GATEWAY/private" -u admin:wrong)"
expect "valid credentials is 200" 200 "$(code GET "$GATEWAY/private" -u admin:admin)"

echo "==> Passive health: one dead backend of two"
failed=0
for ((i = 0; i < 40; i++)); do
  [[ "$(code GET "$GATEWAY/failover")" == 200 ]] || failed=$((failed + 1))
done
if ((failed >= 1 && failed <= 2)); then
  pass "dead backend ejected after $failed failed request(s) of 40"
else
  fail "want 1-2 failed requests of 40 before ejection, got $failed"
fi
metric="gateway_backend_ejections_total{backend=\"$BACKEND_DEAD\"} 1"
if body "$GATEWAY/metrics" | grep -qF "$metric"; then
  pass "ejection counted in /metrics"
else
  fail "ejection metric missing: $metric"
fi

echo "==> File provider: a new route goes live without a restart"
cat >"$WORK/providers/dynamic.yaml" <<EOF
routes:
  - name: dynamic
    path: /dynamic
    target: $BACKEND_B
EOF
if wait_for "$GATEWAY/dynamic" 200 5; then
  expect "provider route reaches backend b" b "$(body "$GATEWAY/dynamic")"
else
  fail "route from the file provider not live within 5s"
fi

echo "==> pprof (GOMA_PPROF_ADDR)"
expect "pprof index on its own listener" 200 "$(code GET "http://127.0.0.1:$PPROF/debug/pprof/")"
expect "pprof not served on the gateway port" 404 "$(code GET "$GATEWAY/debug/pprof/")"

echo "==> Graceful shutdown"
kill -TERM "$GW"
wait_exit "$GW" 15
expect "SIGTERM exits with 0" 0 "$EXIT_CODE"
if grep -q "gracefully stopped" "$WORK/gateway.log"; then pass "shutdown logged"; else fail "no graceful-stop log line"; fi
expect "pprof listener closed" 000 "$(code GET "http://127.0.0.1:$PPROF/debug/pprof/")"

echo "==> SIGTERM right after start"
start_gateway
kill -TERM "$GW"
wait_exit "$GW" 15
expect "early SIGTERM exits with 0" 0 "$EXIT_CODE"

echo
if ((FAILED > 0)); then
  echo "e2e: $FAILED check(s) failed"
  exit 1
fi
echo "e2e: all checks passed"
