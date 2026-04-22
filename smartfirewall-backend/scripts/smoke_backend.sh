#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:5000}"
KEY="${KEY:-c285413f142c8a4d205bf52818ecc381d31d90846189356b9351f91ab4a93cef}"
EMAIL="${EMAIL:-hebaa.sakkal@gmail.com}"
FRONTEND_SECRET="${FRONTEND_SECRET:-52a25726928a251158a18020bb9753513a848644c9777d051b3d26f82d83c5ef}"
TEST_MAC="${TEST_MAC:-0e:1c:52:d3:c1:06}"

pass() {
  echo "[PASS] $1"
}

fail() {
  echo "[FAIL] $1"
  exit 1
}

contains() {
  local haystack="$1"
  local needle="$2"
  [[ "$haystack" == *"$needle"* ]]
}

echo "=== smart-envo backend smoke test ==="
echo "BASE=$BASE"

resp=$(curl -s "$BASE/api/health")
contains "$resp" '"ok":true' && pass "health" || fail "health"

resp=$(curl -s "$BASE/api/me" \
  -H "X-User-Email: $EMAIL" \
  -H "X-Frontend-Secret: $FRONTEND_SECRET")
contains "$resp" '"ok":true' && contains "$resp" "$EMAIL" && pass "trusted frontend auth" || fail "trusted frontend auth"

resp=$(curl -s "$BASE/api/users" -H "X-API-Key: $KEY")
contains "$resp" '"ok":true' && contains "$resp" '"users"' && pass "users list" || fail "users list"

resp=$(curl -s "$BASE/api/devices" -H "X-API-Key: $KEY")
contains "$resp" '"mac"' && pass "devices list" || fail "devices list"

resp=$(curl -s "$BASE/api/groups" -H "X-API-Key: $KEY")
contains "$resp" '"name"' && pass "groups list" || fail "groups list"

resp=$(curl -s "$BASE/api/groups/1/members" -H "X-API-Key: $KEY")
contains "$resp" '"members"' && pass "group members" || fail "group members"

resp=$(curl -s "$BASE/api/groups/1/domains" -H "X-API-Key: $KEY")
contains "$resp" '"domains"' && pass "group domains" || fail "group domains"

resp=$(curl -s "$BASE/api/schedules" -H "X-API-Key: $KEY")
contains "$resp" '"group_id"' && pass "schedules list" || fail "schedules list"

resp=$(curl -s "$BASE/api/dashboard/summary" -H "X-API-Key: $KEY")
contains "$resp" '"summary"' && contains "$resp" '"recent_alerts"' && pass "dashboard summary" || fail "dashboard summary"

resp=$(curl -s "$BASE/api/alerts" -H "X-API-Key: $KEY")
contains "$resp" '"alerts"' && pass "alerts list" || fail "alerts list"

resp=$(curl -s "$BASE/api/monitor/feed" -H "X-API-Key: $KEY")
contains "$resp" '"items"' && pass "monitor feed" || fail "monitor feed"

resp=$(curl -s "$BASE/api/devices/effective" -H "X-API-Key: $KEY")
contains "$resp" '"devices"' && pass "devices effective" || fail "devices effective"

resp=$(curl -s "$BASE/api/devices/$TEST_MAC/groups" -H "X-API-Key: $KEY")
contains "$resp" '"groups"' && pass "device groups" || fail "device groups"

echo "=== smoke test finished successfully ==="
