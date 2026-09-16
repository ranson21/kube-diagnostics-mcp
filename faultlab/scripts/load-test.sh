#!/usr/bin/env bash
# Drives traffic at the fault lab so every injected fault produces its symptom.
#   BASE_URL=http://localhost:30080 DURATION=120 ./scripts/load-test.sh
# Per iteration (~1 s): product list, 3 product details (PII log lines), 3 review lookups (N+1),
# the slow endpoint (504), a burst of 3 concurrent checkouts (pool exhaustion + 504),
# an admin report (memory leak), and every ~50th iteration the deadlock endpoint.
set -u
BASE_URL="${BASE_URL:-http://localhost:30080}"
DURATION="${DURATION:-120}"
CONCURRENT_CHECKOUTS="${CONCURRENT_CHECKOUTS:-3}"
UA="faultlab-load-test/1.0"

hit() { # method path [data]
  local m="$1" p="$2" d="${3:-}"
  if [ -n "$d" ]; then
    curl -s -o /dev/null --max-time 15 -A "$UA" -X "$m" -H 'Content-Type: application/json' -d "$d" -w "%{http_code} %{time_total}s $m $p\n" "$BASE_URL$p"
  else
    curl -s -o /dev/null --max-time 15 -A "$UA" -X "$m" -w "%{http_code} %{time_total}s $m $p\n" "$BASE_URL$p"
  fi
}

echo "load-test: $BASE_URL for ${DURATION}s"
end=$(( $(date +%s) + DURATION ))
i=0
declare -A codes
while [ "$(date +%s)" -lt "$end" ]; do
  i=$((i+1))
  out=""
  out+=$(hit GET /api/catalog/products)$'\n'
  for id in $(( (i*7) % 50 + 1 )) $(( (i*13) % 50 + 1 )) $(( (i*17) % 50 + 1 )); do
    out+=$(hit GET "/api/catalog/products/$id")$'\n'
    out+=$(hit GET "/api/catalog/reviews?productId=$id")$'\n'
  done
  out+=$(hit GET /api/catalog/products/slow)$'\n'
  out+=$(hit GET /api/cart)$'\n'
  # concurrent checkouts: with hikari max-pool-size=2 the third one fails
  for _ in $(seq 1 "$CONCURRENT_CHECKOUTS"); do
    hit POST /api/checkout '{"items":[],"totalCents":25749}' &
  done
  wait
  out+=$(hit GET /api/admin/report)$'\n'
  if [ $((i % 50)) -eq 1 ]; then out+=$(hit GET /api/orders/deadlock)$'\n'; fi
  # SPA + static assets (hero image, unhashed-cache faults)
  out+=$(hit GET /)$'\n'
  out+=$(hit GET /assets/hero-large.png)$'\n'
  while read -r code _rest; do [ -n "$code" ] && codes[$code]=$(( ${codes[$code]:-0} + 1 )); done <<< "$out"
  if [ $((i % 10)) -eq 0 ]; then
    printf 'iter %d  status counts:' "$i"; for c in "${!codes[@]}"; do printf ' %s=%s' "$c" "${codes[$c]}"; done; echo
  fi
  sleep 1
done
printf 'done after %d iterations. status counts:' "$i"; for c in "${!codes[@]}"; do printf ' %s=%s' "$c" "${codes[$c]}"; done; echo
