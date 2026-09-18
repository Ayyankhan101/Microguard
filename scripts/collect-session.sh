#!/usr/bin/env bash
# Host a short, observe-only session that collects REAL human sessions, so the
# micrograd model can finally be trained on real human traffic (the one thing
# the repo lacks -- see microguard/collect.py). You run it, share the printed
# HTTPS link with people you know, wait ~15-20 min, Ctrl-C, then run the one
# evaluate command it prints.
#
#   bash scripts/collect-session.sh                 # cloudflared (no account)
#   bash scripts/collect-session.sh --tunnel ngrok  # ngrok (needs authtoken)
#
# Nothing is ever blocked (--block-threshold 1.0). The page is a plain, honest
# landing page about this project. Keep the link to people you know: a public
# link gets crawled, and a JS-running crawler would pollute the human label.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

TUNNEL="cloudflared"
REDIS_URL="${COLLECT_REDIS_URL:-redis://localhost:6379/14}"
SERVE_PORT=8455
NGINX_PORT=8080
while [ $# -gt 0 ]; do
  case "$1" in
    --tunnel) TUNNEL="$2"; shift 2;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done

WORK="scripts/collect/.run"
DATA="data"
ARCHIVE="$DATA/session.jsonl"
ACCESS="$DATA/session-access.log"
TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(3))')"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1"; exit 1; }; }
need nginx; need "$TUNNEL"
redis-cli -u "$REDIS_URL" ping >/dev/null 2>&1 || { echo "Redis not reachable at $REDIS_URL (start redis-server)"; exit 1; }

case "$TUNNEL" in
  cloudflared) REALIP_HEADER="CF-Connecting-IP";;
  ngrok)       REALIP_HEADER="X-Forwarded-For";;
  *) echo "--tunnel must be cloudflared or ngrok"; exit 2;;
esac

echo "==> workspace $WORK"
rm -rf "$WORK"; mkdir -p "$WORK/site" "$DATA"
redis-cli -u "$REDIS_URL" flushdb >/dev/null
: > "$ARCHIVE"

# --- the landing site: honest content + the fingerprint script + a hidden
# honeypot link. A visit that clicks around produces a multi-request session.
build_page() { # title, body -> stdout
  cat <<HTML
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$1</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:40rem;
margin:2rem auto;padding:0 1rem;line-height:1.6;color:#111}nav a{margin-right:1rem}
h1{font-size:1.6rem}.muted{color:#666;font-size:.9rem}</style></head><body>
<nav><a href="/">Home</a><a href="/how.html">How it works</a><a href="/about.html">About</a></nav>
$2
<a href="/_hp/archive" style="display:none" tabindex="-1" aria-hidden="true" rel="nofollow">archive</a>
<script src="/microguard/fingerprint.js" defer></script>
</body></html>
HTML
}
build_page "Microguard" '<h1>Microguard</h1>
<p>A small bot-detection project built on <a href="https://github.com/karpathy/micrograd">micrograd</a>.
It tells automated traffic from real people in web-server logs.</p>
<p>This page is part of a class project: it is collecting a few minutes of real,
consenting human visits so the model can be trained on genuine human behaviour
instead of synthetic data. Nothing you do here is blocked or stored beyond the
request pattern. Have a look at <a href="/how.html">how it works</a>.</p>' > "$WORK/site/index.html"
build_page "How it works" '<h1>How it works</h1>
<p>It scores each session on timing, request shape, and headers, and blends a
tiny neural network with a set of heuristic rules. Read more on the
<a href="/about.html">about</a> page or go <a href="/">back home</a>.</p>
<p class="muted">This visit is observed only. No verdict here blocks anyone.</p>' > "$WORK/site/how.html"
build_page "About" '<h1>About this project</h1>
<p>Microguard is an end-of-semester machine-learning project. Thanks for helping
by visiting -- a real human session is genuinely useful data. Head <a href="/">home</a>
or see <a href="/how.html">how it works</a>.</p>' > "$WORK/site/about.html"
printf 'User-agent: *\nDisallow: /_hp/\n' > "$WORK/site/robots.txt"

sed -e "s#__PREFIX__#$PWD/$WORK#g" \
    -e "s#__REALIP_HEADER__#$REALIP_HEADER#g" \
    -e "s#__SERVE_PORT__#$SERVE_PORT#g" \
    scripts/collect/nginx.conf > "$WORK/nginx.conf"

cleanup() {
  echo; echo "==> stopping"
  [ -n "${TUN_PID:-}" ] && kill "$TUN_PID" 2>/dev/null
  nginx -p "$PWD/$WORK/" -c "$PWD/$WORK/nginx.conf" -s stop 2>/dev/null
  [ -n "${SERVE_PID:-}" ] && kill "$SERVE_PID" 2>/dev/null
  [ -f "$WORK/access.log" ] && cp "$WORK/access.log" "$ACCESS"
  echo
  echo "================= now label what you collected ================="
  echo "microguard evaluate --collected $ARCHIVE \\"
  echo "  --access-log $ACCESS --invite-token $TOKEN"
  echo "================================================================"
  echo "Look for: 'Invited actors that ran the fingerprint script: N/N' near 1."
}
trap cleanup EXIT INT TERM

echo "==> start microguard serve (observe-only, --collect-to) on :$SERVE_PORT"
microguard serve --host 127.0.0.1 --port "$SERVE_PORT" \
  --redis-url "$REDIS_URL" --block-threshold 1.0 \
  --collect-to "$ARCHIVE" >"$WORK/serve.log" 2>&1 &
SERVE_PID=$!
for _ in $(seq 1 30); do
  curl -sf -o /dev/null -H "X-Real-IP: 9.9.9.9" -H "X-Original-URI: /" \
    "http://127.0.0.1:$SERVE_PORT/check" && break; sleep 0.5
done

echo "==> start nginx on :$NGINX_PORT"
nginx -p "$PWD/$WORK/" -c "$PWD/$WORK/nginx.conf" >"$WORK/nginx.boot.log" 2>&1 &
sleep 2
curl -sf -o /dev/null -H "X-Forwarded-For: 203.0.113.9" "http://127.0.0.1:$NGINX_PORT/" \
  || { echo "nginx did not serve; see $WORK/error.log"; cat "$WORK/error.log" 2>/dev/null; exit 1; }
# Prove the fingerprint route is reachable before anyone visits.
curl -sf -o /dev/null "http://127.0.0.1:$NGINX_PORT/microguard/fingerprint.js" \
  || { echo "fingerprint.js route is broken; not sharing a link that can't label humans"; exit 1; }

echo "==> open HTTPS tunnel ($TUNNEL)"
if [ "$TUNNEL" = "cloudflared" ]; then
  cloudflared tunnel --url "http://127.0.0.1:$NGINX_PORT" --no-autoupdate \
    >"$WORK/tunnel.log" 2>&1 &
  TUN_PID=$!
  URL=""
  for _ in $(seq 1 40); do
    URL="$(grep -Eo 'https://[a-z0-9.-]+\.trycloudflare\.com' "$WORK/tunnel.log" | head -1)"
    [ -n "$URL" ] && break; sleep 1
  done
else
  ngrok http "$NGINX_PORT" --log stdout >"$WORK/tunnel.log" 2>&1 &
  TUN_PID=$!
  URL=""
  for _ in $(seq 1 40); do
    URL="$(grep -Eo 'https://[a-z0-9.-]+\.ngrok[a-z.-]+' "$WORK/tunnel.log" | head -1)"
    [ -n "$URL" ] && break; sleep 1
  done
fi
[ -n "$URL" ] || { echo "tunnel did not come up; see $WORK/tunnel.log"; tail -5 "$WORK/tunnel.log"; exit 1; }

INVITE="$URL/?ref=$TOKEN"
sleep 3
if curl -sf -o /dev/null "$URL/"; then STATE="reachable"; else STATE="not reachable yet (give it a few more seconds)"; fi

cat <<BANNER

============================================================
  SHARE THIS LINK with ~30 people you know (a group chat):
      $INVITE
  ("open this and click around for a minute")
  Tunnel is $STATE. Invite token: $TOKEN
  Nothing is blocked; sessions archive to $ARCHIVE
  Aim for 30+ visitors, then press Ctrl-C here to stop + label.
============================================================
BANNER

# Wait until you Ctrl-C. Print a heartbeat with the running visitor count.
while true; do
  sleep 30
  n=$(wc -l < "$ARCHIVE" 2>/dev/null | tr -d ' ')
  echo "   ... $n scored requests collected so far ($(date +%H:%M:%S)). Ctrl-C to finish."
done
