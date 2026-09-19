# How to deploy in-process (FastAPI or Flask)

Wrap your application so bot requests are rejected before your handlers run, with
no separate service to operate. Two lines of code and a Redis connection.

Use this when you own the application. If nginx already fronts your traffic and
you would rather keep filtering at the proxy, see
[deploying behind nginx](howto-deploy-behind-nginx.md).

## Prerequisites

- Redis reachable from your application process
- `pip install 'microguard[live,fastapi]'` or `pip install 'microguard[live,flask]'`
- A trained model at `microguard/data/model.json` (ships inside the package, so a `pip install` has it)

## Steps

### 1. Wrap the application

**FastAPI or any ASGI app:**

```python
from fastapi import FastAPI
from microguard.live.middleware import MicroguardASGI

app = FastAPI()

@app.get("/products/{item_id}")
def read_item(item_id: int):
    return {"item_id": item_id}

app = MicroguardASGI(app, redis_url="redis://localhost:6379")
```

Wrap **after** your routes are declared, and assign the result back to `app` so
your server runs the wrapper. `MicroguardASGI` is a plain ASGI callable, so it
also works with Starlette, Litestar, or anything speaking ASGI 3.

Non-HTTP scopes — WebSocket connections and lifespan events — pass through
unscored.

**Flask or any WSGI app:**

```python
from flask import Flask
from microguard.live.middleware import MicroguardWSGI

app = Flask(__name__)

@app.route("/products/<int:item_id>")
def read_item(item_id):
    return {"item_id": item_id}

app.wsgi_app = MicroguardWSGI(app.wsgi_app)
```

Note the difference: Flask keeps its own `app` object, so you replace
`app.wsgi_app` rather than reassigning `app`. Reassigning `app` breaks
`flask run` and anything that expects a Flask instance.

### 2. Tell it where the real client IP comes from

Sessions key on the client IP. If your app sits behind a load balancer or CDN,
the address the middleware sees is the proxy's, and every visitor collapses into
one shared session.

Set `X-Real-IP` at your proxy and microguard uses it automatically. If your proxy
sets `X-Forwarded-For` instead, opt in explicitly:

```python
app = MicroguardASGI(
    app,
    redis_url="redis://localhost:6379",
    trust_forwarded_for=True,   # ONLY if a proxy overwrites this header
)
```

Only enable this if something in front of you **overwrites** `X-Forwarded-For`
rather than appending to it. Otherwise a client sends its own value, gets a fresh
session on every request, and never accumulates the history that detection
depends on. See
[the trust boundary](explanation-how-blocking-works.md#the-client-ip-is-the-trust-boundary).

### 3. Read the verdict in your handlers (optional)

On requests that pass, the middleware attaches its decision as request headers.
Client-supplied `X-Microguard-*` headers are stripped first, so what you read is
microguard's.

```python
@app.get("/products/{item_id}")
def read_item(item_id: int, request: Request):
    label = request.headers.get("x-microguard-label")     # "human"
    score = float(request.headers.get("x-microguard-score", 0))
    if score > 0.6:
        log.info("borderline visitor %s scored %.2f", request.client.host, score)
    return {"item_id": item_id}
```

Useful for logging borderline traffic, or for serving a cheaper response to
clients that scored high without blocking them outright.

## Verification

Run your app, then check both paths. A normal request:

```bash
curl -si http://127.0.0.1:8000/products/1 -H "X-Real-IP: 203.0.113.5" | head -1
```

```
HTTP/1.1 200 OK
```

A scanner path:

```bash
curl -si http://127.0.0.1:8000/wp-admin/setup-config.php -H "X-Real-IP: 203.0.113.9" | head -1
```

```
HTTP/1.1 403 Forbidden
```

Or assert it in your test suite, which is where this belongs long-term:

```python
from starlette.testclient import TestClient

def test_scanner_is_blocked():
    client = TestClient(app)          # the wrapped app
    resp = client.get("/wp-admin/setup-config.php",
                      headers={"X-Real-IP": "203.0.113.9"})
    assert resp.status_code == 403
    assert resp.json()["heuristic_reason"] == "vulnerability scanner pattern detected"
```

The Flask equivalent uses `app.test_client()` and `resp.get_json()`.

## Troubleshooting

**`ImportError: Real-time mode requires the 'live' extra`.** Install it:
`pip install 'microguard[live]'`. The base package deliberately has no Redis
dependency.

**`TypeError: __init__() got an unexpected keyword argument`.** A misspelled
option. The middleware rejects unknown keywords rather than silently running at
the default, which is the point — `block_treshold=0.5` would otherwise leave you
at 0.85 believing you had tightened it.

**Every visitor shares one session.** The middleware is seeing your proxy's
address. Check what arrives:

```python
print(request.headers.get("x-real-ip"), request.client.host)
```

Fix it at the proxy (set `X-Real-IP`) rather than by enabling
`trust_forwarded_for` blindly.

**Requests are slow.** Each scored request makes a Redis round trip. If Redis is
on another host, that latency lands on every request. Move it closer, or run the
[nginx deployment](howto-deploy-behind-nginx.md) where the check server can sit
next to Redis.

**Nothing is blocked and the logs say "scoring failed, allowing request".** Redis
is unreachable. Microguard fails open by design — your app stays up but nothing
is filtered. Alert on this line rather than treating it as noise. See
[failing open](explanation-how-blocking-works.md#failing-open).

**WebSocket connections are not being filtered.** Correct — non-HTTP ASGI scopes
pass through unscored. Filter those at your proxy if you need to.

## Related

- [API reference](reference-live-api.md) — constructor arguments, decision payload, headers
- [How to tune blocking](howto-tune-blocking.md)
- [How blocking works](explanation-how-blocking-works.md)
