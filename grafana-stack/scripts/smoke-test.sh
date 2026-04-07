#!/bin/bash

# Smoke Test for Observability Stack
# Sends a test trace, metric, and log via OTEL Collector,
# then verifies they arrive in Tempo, Prometheus, and Loki.
#
# Usage:
#   ./scripts/smoke-test.sh [otel-http-endpoint]
#   Default endpoint: http://localhost:4318

set -euo pipefail

OTEL_ENDPOINT="${1:-http://localhost:4318}"
LOKI_ENDPOINT="http://localhost:3100"
PROMETHEUS_ENDPOINT="http://localhost:9090"
TEMPO_ENDPOINT="http://localhost:3200"
TEST_SERVICE="smoke-test"
TRACE_ID=$(printf '%032x' $RANDOM$RANDOM$RANDOM$RANDOM)
SPAN_ID=$(printf '%016x' $RANDOM$RANDOM)
TIMESTAMP_NS=$(date +%s)000000000

echo "========================================"
echo " Observability Stack Smoke Test"
echo "========================================"
echo ""
echo "OTEL Endpoint: $OTEL_ENDPOINT"
echo "Trace ID:      $TRACE_ID"
echo ""

PASS=0
FAIL=0

# --- Send test trace ---
echo "[1/6] Sending test trace..."
TRACE_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "${OTEL_ENDPOINT}/v1/traces" \
  -H "Content-Type: application/json" \
  -d "{
    \"resourceSpans\": [{
      \"resource\": {
        \"attributes\": [{
          \"key\": \"service.name\",
          \"value\": {\"stringValue\": \"${TEST_SERVICE}\"}
        }]
      },
      \"scopeSpans\": [{
        \"scope\": {\"name\": \"smoke-test\"},
        \"spans\": [{
          \"traceId\": \"${TRACE_ID}\",
          \"spanId\": \"${SPAN_ID}\",
          \"name\": \"smoke-test-span\",
          \"kind\": 1,
          \"startTimeUnixNano\": \"${TIMESTAMP_NS}\",
          \"endTimeUnixNano\": \"$((TIMESTAMP_NS + 1000000000))\",
          \"status\": {\"code\": 1}
        }]
      }]
    }]
  }")

if [ "$TRACE_RESPONSE" = "200" ]; then
  echo "  -> Trace sent (HTTP $TRACE_RESPONSE)"
  PASS=$((PASS + 1))
else
  echo "  -> FAILED to send trace (HTTP $TRACE_RESPONSE)"
  FAIL=$((FAIL + 1))
fi

# --- Send test log ---
echo "[2/6] Sending test log..."
LOG_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "${OTEL_ENDPOINT}/v1/logs" \
  -H "Content-Type: application/json" \
  -d "{
    \"resourceLogs\": [{
      \"resource\": {
        \"attributes\": [{
          \"key\": \"service.name\",
          \"value\": {\"stringValue\": \"${TEST_SERVICE}\"}
        }]
      },
      \"scopeLogs\": [{
        \"scope\": {\"name\": \"smoke-test\"},
        \"logRecords\": [{
          \"timeUnixNano\": \"${TIMESTAMP_NS}\",
          \"severityNumber\": 9,
          \"severityText\": \"INFO\",
          \"body\": {\"stringValue\": \"Smoke test log entry - trace_id=${TRACE_ID}\"},
          \"traceId\": \"${TRACE_ID}\",
          \"spanId\": \"${SPAN_ID}\"
        }]
      }]
    }]
  }")

if [ "$LOG_RESPONSE" = "200" ]; then
  echo "  -> Log sent (HTTP $LOG_RESPONSE)"
  PASS=$((PASS + 1))
else
  echo "  -> FAILED to send log (HTTP $LOG_RESPONSE)"
  FAIL=$((FAIL + 1))
fi

# --- Send test metric ---
echo "[3/6] Sending test metric..."
METRIC_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "${OTEL_ENDPOINT}/v1/metrics" \
  -H "Content-Type: application/json" \
  -d "{
    \"resourceMetrics\": [{
      \"resource\": {
        \"attributes\": [{
          \"key\": \"service.name\",
          \"value\": {\"stringValue\": \"${TEST_SERVICE}\"}
        }]
      },
      \"scopeMetrics\": [{
        \"scope\": {\"name\": \"smoke-test\"},
        \"metrics\": [{
          \"name\": \"smoke_test_counter\",
          \"sum\": {
            \"dataPoints\": [{
              \"asInt\": \"1\",
              \"startTimeUnixNano\": \"${TIMESTAMP_NS}\",
              \"timeUnixNano\": \"${TIMESTAMP_NS}\"
            }],
            \"aggregationTemporality\": 2,
            \"isMonotonic\": true
          }
        }]
      }]
    }]
  }")

if [ "$METRIC_RESPONSE" = "200" ]; then
  echo "  -> Metric sent (HTTP $METRIC_RESPONSE)"
  PASS=$((PASS + 1))
else
  echo "  -> FAILED to send metric (HTTP $METRIC_RESPONSE)"
  FAIL=$((FAIL + 1))
fi

# Wait for data to propagate
echo ""
echo "Waiting 10 seconds for data to propagate..."
sleep 10

# --- Verify trace in Tempo ---
echo "[4/6] Checking Tempo for trace..."
TEMPO_CHECK=$(curl -s -o /dev/null -w "%{http_code}" \
  "${TEMPO_ENDPOINT}/api/traces/${TRACE_ID}" 2>/dev/null || echo "000")

if [ "$TEMPO_CHECK" = "200" ]; then
  echo "  -> Trace found in Tempo"
  PASS=$((PASS + 1))
else
  echo "  -> Trace NOT found in Tempo (HTTP $TEMPO_CHECK) - may need more time"
  FAIL=$((FAIL + 1))
fi

# --- Verify log in Loki ---
echo "[5/6] Checking Loki for log..."
LOKI_CHECK=$(curl -s \
  "${LOKI_ENDPOINT}/loki/api/v1/query" \
  --data-urlencode "query={service_name=\"${TEST_SERVICE}\"}" \
  --data-urlencode "limit=1" 2>/dev/null || echo "")

if echo "$LOKI_CHECK" | grep -q "smoke-test" 2>/dev/null; then
  echo "  -> Log found in Loki"
  PASS=$((PASS + 1))
else
  echo "  -> Log NOT found in Loki - may need more time or check config"
  FAIL=$((FAIL + 1))
fi

# --- Verify metric in Prometheus ---
echo "[6/6] Checking Prometheus for metric..."
PROM_CHECK=$(curl -s \
  "${PROMETHEUS_ENDPOINT}/api/v1/query" \
  --data-urlencode "query=smoke_test_counter{service_name=\"${TEST_SERVICE}\"}" 2>/dev/null || echo "")

if echo "$PROM_CHECK" | grep -q "smoke_test_counter" 2>/dev/null; then
  echo "  -> Metric found in Prometheus"
  PASS=$((PASS + 1))
else
  echo "  -> Metric NOT found in Prometheus - may need more time"
  FAIL=$((FAIL + 1))
fi

# --- Summary ---
echo ""
echo "========================================"
echo " Results: ${PASS} passed, ${FAIL} failed"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "Some checks failed. This may be due to propagation delay."
  echo "Retry verification manually:"
  echo "  curl ${TEMPO_ENDPOINT}/api/traces/${TRACE_ID}"
  echo "  curl '${LOKI_ENDPOINT}/loki/api/v1/query?query={service_name=\"${TEST_SERVICE}\"}'"
  echo "  curl '${PROMETHEUS_ENDPOINT}/api/v1/query?query=smoke_test_counter'"
  exit 1
fi

echo ""
echo "All checks passed! The observability stack is working correctly."
exit 0
