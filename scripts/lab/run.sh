#!/usr/bin/env bash
# Local realism lab: real nginx auth_request -> real microguard check server ->
# real scorer/model/features/labeler, driven by real attack tools and realistic
# human sessions. Ends with two reports: `microguard evaluate` (the field view)
# and scorecard.py (exact ground truth). Nothing here ever blocks; it observes.
set -euo pipefail
cd "$(dirname "$0")/../.."
LAB="scripts/lab"; PFX="$LAB/.run"
REDIS_URL="${REDIS_URL:-redis://localhost:6379/15}"
HUMANS="${HUMANS:-40}"; SCRAPERS="${SCRAPERS:-20}"; CRED="${CRED:-12}"

cleanup() {
  [ -f "$PFX/nginx.pid" ] && nginx -p "$PWD/$PFX/" -c "$PWD/$PFX/nginx.conf" -s stop 2>/dev/null || true
  [ -n "${SERVE_PID:-}" ] && kill "$SERVE_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> reset workspace ($PFX)"
rm -rf "$PFX"; mkdir -p "$PFX"; cp -r "$LAB/site" "$PFX/site"
sed "s#__PREFIX__#$PWD/$PFX#g" "$LAB/nginx.conf" > "$PFX/nginx.conf"
redis-cli -u "$REDIS_URL" flushdb >/dev/null
ARCHIVE="$PFX/collected.jsonl"

echo "==> start check server (observe-only, real scorer) on :8400"
python -m microguard.cli serve --host 127.0.0.1 --port 8400 \
  --redis-url "$REDIS_URL" --block-threshold 1.0 \
  --collect-to "$ARCHIVE" --deployment-id lab >"$PFX/serve.log" 2>&1 &
SERVE_PID=$!
sleep 3
curl -sf -o /dev/null -H "X-Real-IP: 9.9.9.9" -H "X-Original-URI: /" \
  http://127.0.0.1:8400/check || { echo "check server did not come up"; cat "$PFX/serve.log"; exit 1; }

echo "==> start nginx on :8080"
nginx -p "$PWD/$PFX/" -c "$PWD/$PFX/nginx.conf" >"$PFX/nginx.boot.log" 2>&1 &
sleep 2
curl -sf -o /dev/null -H "X-Forwarded-For: 203.0.113.1" http://127.0.0.1:8080/ \
  || { echo "nginx did not serve"; cat "$PFX/nginx.boot.log" "$PFX/error.log" 2>/dev/null; exit 1; }

echo "==> generate traffic"
python "$LAB/generate_traffic.py" "$HUMANS" "$SCRAPERS" "$CRED" "$PFX/ground_truth.json"
sleep 2  # let the last decisions flush to the archive

echo; echo "==================== microguard evaluate (field view) ===================="
python -m microguard.cli evaluate --collected "$ARCHIVE" \
  --access-log "$PFX/access.log" --invite-token cohort1 | tee "$PFX/evaluate-report.md"

echo; echo "==================== scorecard (exact ground truth) ===================="
python "$LAB/scorecard.py" "$ARCHIVE" "$PFX/ground_truth.json" | tee "$PFX/scorecard.md"
echo; echo "Reports saved under $PFX/ (evaluate-report.md, scorecard.md)."
