# How to deploy behind nginx

Put microguard in front of an existing site using nginx's `auth_request` module,
so bots are stopped at the proxy and never reach your application. Your
application code does not change.

Use this when nginx already terminates your traffic. If your app is FastAPI or
Flask and you would rather not run a second service, see
[deploying in-process](howto-deploy-in-process.md) instead.

## Prerequisites

- nginx built with `ngx_http_auth_request_module` (check with `nginx -V 2>&1 | grep auth_request`)
- Redis reachable from wherever microguard will run
- `pip install 'microguard[live]'`
- A trained model at `data/model.json` (ships with the repo)

## Steps

### 1. Start the check server

```bash
microguard serve --host 127.0.0.1 --port 8400 --redis-url redis://localhost:6379
```

Confirm the banner reports what you expect, in particular `model: loaded`:

```
microguard check server listening on 127.0.0.1:8400
  redis: redis://localhost:6379
  threshold: 0.85
  session TTL: 1800s
  model: loaded
  trust X-Forwarded-For: False
```

If it says `model: NOT LOADED (heuristics only)`, scoring will run on the rule
engine alone. Fix that before continuing unless you intend it.

Keep the server on `127.0.0.1` unless nginx runs on a different host. It has no
authentication of its own — anything that can reach it can ask it to score
arbitrary requests.

### 2. Add the auth_request wiring to nginx

In the `server` block protecting your site:

```nginx
location / {
    auth_request /_microguard_check;

    # Forward microguard's verdict to your backend (optional but useful)
    auth_request_set $mg_label  $upstream_http_x_microguard_label;
    auth_request_set $mg_score  $upstream_http_x_microguard_score;
    auth_request_set $mg_reason $upstream_http_x_microguard_reason;
    proxy_set_header X-Microguard-Label  $mg_label;
    proxy_set_header X-Microguard-Score  $mg_score;
    proxy_set_header X-Microguard-Reason $mg_reason;

    proxy_pass http://your-backend;
}

# The fingerprint routes. PUBLIC, unlike the check endpoint below: a browser
# has to be able to fetch the script and post its hash, so this location has no
# `internal`. Optional — skip the whole block if you are not using
# fingerprinting, and nothing else changes.
#
# The bounds are not decoration. This is the only public, body-accepting route
# on the check server, and that server is a stdlib http.server which Python's
# own docs say must not face the internet directly. nginx buffers the body and
# enforces these limits, so the Python process only ever sees a small, complete
# request.
#
# Exact matches, never a prefix: a prefix location for /microguard/ with a
# URI in its proxy_pass target would also publish /check as
# /microguard/check.
location = /microguard/fp {
    proxy_pass http://127.0.0.1:8400/fp;

    # A SHA-256 hex digest in a JSON envelope is about 100 bytes. microguard
    # caps it again server-side; this stops the body reaching Python at all.
    client_max_body_size  2k;
    client_body_timeout   5s;
    send_timeout          5s;
    proxy_read_timeout    5s;

    # One page load submits once. This is generous for a real visitor and
    # useless for anyone trying to flood the endpoint.
    limit_req zone=microguard_fp burst=5 nodelay;

    proxy_set_header X-Real-IP $remote_addr;
    # Same reasoning as the check endpoint: the hash is bound to this IP, and a
    # spoofable value would let an attacker bind a hash to someone else.
    proxy_set_header X-Forwarded-For "";
}

location = /microguard/fingerprint.js {
    proxy_pass http://127.0.0.1:8400/fingerprint.js;
}

# Goes in the http {} block, alongside your other zones.
# limit_req_zone $binary_remote_addr zone=microguard_fp:10m rate=30r/m;

location = /_microguard_check {
    internal;
    proxy_pass http://127.0.0.1:8400/check;

    # auth_request discards the body; say so explicitly
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";

    # What microguard scores
    proxy_set_header X-Original-URI    $request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header User-Agent        $http_user_agent;
    proxy_set_header Referer           $http_referer;

    # Drop any client-supplied X-Forwarded-For. Sessions are keyed on this IP,
    # so a spoofable value lets a bot get a fresh session per request and never
    # build a detectable history.
    proxy_set_header X-Forwarded-For "";
}
```

The `X-Forwarded-For` line is the one people skip. nginx forwards client request
headers to upstreams by default, so without it a client can send its own
`X-Forwarded-For` and choose its session identity. See
[the trust boundary](explanation-how-blocking-works.md#the-client-ip-is-the-trust-boundary).

### 3. Reload nginx

```bash
nginx -t && nginx -s reload
```

`nginx -t` first, always. A config error here takes the whole site down, not just
bot filtering.

### 4. Give visitors a real error page

By default a blocked visitor gets nginx's bare 403. Point it somewhere useful:

```nginx
error_page 403 /blocked.html;

location = /blocked.html {
    internal;
    root /var/www/static;
}
```

## Verification

Confirm a normal request still reaches your backend:

```bash
curl -si https://your-site/ | head -1
```

```
HTTP/1.1 200 OK
```

Confirm a scanner path is blocked *by nginx*, not just by microguard:

```bash
curl -si https://your-site/wp-admin/setup-config.php | head -1
```

```
HTTP/1.1 403 Forbidden
```

Confirm the verdict is reaching your backend, if you wired the headers in step 2 —
log `X-Microguard-Label` and `X-Microguard-Reason` on one request and check they
arrive populated.

## Troubleshooting

**Everything returns 500.** nginx treats any `auth_request` response that is not
2xx, 401, or 403 as an error. Either the check server is unreachable, or it is
returning something unexpected. Confirm it directly:

```bash
curl -si http://127.0.0.1:8400/check -H "X-Real-IP: 1.2.3.4" | head -1
```

**Never expose port 8400 directly.** Everything above assumes nginx is in
front of it. The check server is a stdlib `http.server`, which has no request
timeout and no cap on threads, and [Python's own
documentation](https://docs.python.org/3/library/http.server.html) says it is
not suitable for production use facing the internet. Behind nginx that is fine:
nginx buffers, bounds and times out every request before Python sees it.

**Fingerprinting needs HTTPS.** The script hashes in the browser using
SubtleCrypto, which only exists in a secure context — HTTPS, or `localhost`. On
a plain-HTTP origin the script logs a console warning and does nothing, so no
fingerprint ever arrives. That matters because the absence rule reads a missing
fingerprint as evidence, which would make an HTTP site look like it was full of
bots. Either serve over HTTPS or leave the fingerprint rules unpromoted.

If that works and nginx still 500s, check `proxy_pass` points at `/check` and the
`location` is marked `internal`.

**Everything is allowed, including obvious scanners.** Most likely the client IP
is not what you think. Add it to your access log and check that distinct visitors
produce distinct values:

```nginx
log_format mg '$remote_addr "$http_user_agent" mg=$mg_label';
```

If every request shows the same IP, nginx is passing its own address rather than
the client's — check the `X-Real-IP` line in step 2.

**Everything is blocked after a deploy.** Check the check server's logs for
`scoring failed, allowing request`. If Redis went away, microguard fails open and
allows everything, so a total block is more likely a threshold set too low. See
[tuning blocking](howto-tune-blocking.md).

**Nothing is blocked and the log says "scoring unavailable".** Redis is
unreachable from the check server. Microguard is failing open by design — the
site stays up but nothing is filtered. Fix Redis; alert on this line.

**Legitimate API clients are being blocked.** Recognized webhook and RPC senders
are never blocked, but an unrecognized one can trip the sequence rules. See
[tuning blocking](howto-tune-blocking.md#allow-a-known-client).

## Related

- [API reference](reference-live-api.md) — every flag, header, and response field
- [How blocking works](explanation-how-blocking-works.md) — why fail-open, why the IP matters
- [How to tune blocking](howto-tune-blocking.md)
