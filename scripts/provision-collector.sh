#!/usr/bin/env bash
# Bootstrap a Microguard observe-only collector on Amazon Linux 2023.
#
# Run ON the EC2 instance, as root (or via cloud-init user-data).
#
# What this sets up:
#   nginx  :80/:443  -> auth_request -> microguard serve on 127.0.0.1:8400
#   redis            -> loopback only, session + signal state
#   collector        -> append-only JSONL archive of every scored decision
#
# What it deliberately does NOT do:
#   - block anything (--block-threshold 1.0 with a strict > can never fire)
#   - expose port 8400 (directly reachable, /check is an oracle)
#   - expose the dashboard (loopback only; reach it over an SSH tunnel)
#
# TLS is a separate step and is NOT optional -- see the runbook. The browser
# fingerprint script needs crypto.subtle, which requires a secure context. On
# plain HTTP it is inert, and the absence rule then makes the whole site look
# bot-infested.

set -euo pipefail

DOMAIN="${1:-}"
COLLECT_TO="${COLLECT_TO:-/var/lib/microguard/collected.jsonl}"
SERVE_USER="${SERVE_USER:-microguard}"

if [ -z "$DOMAIN" ]; then
    echo "usage: $0 <domain>   e.g. $0 collect.example.com" >&2
    exit 1
fi

echo "==> Packages"
dnf -y update
dnf -y install nginx redis6 python3.12 python3.12-pip git

echo "==> nginx must have auth_request compiled in"
if ! nginx -V 2>&1 | grep -q with-http_auth_request_module; then
    echo "FATAL: this nginx lacks ngx_http_auth_request_module." >&2
    echo "Without it the whole blocking design does not exist." >&2
    exit 1
fi

echo "==> Redis, loopback only"
sed -i 's/^# *bind .*/bind 127.0.0.1/' /etc/redis6/redis6.conf || true
systemctl enable --now redis6

echo "==> Service account and state directory"
id -u "$SERVE_USER" >/dev/null 2>&1 || useradd --system --shell /sbin/nologin "$SERVE_USER"
install -d -o "$SERVE_USER" -g "$SERVE_USER" /var/lib/microguard
install -d -o "$SERVE_USER" -g "$SERVE_USER" /opt/microguard

echo "==> Microguard"
python3.12 -m pip install --upgrade pip
python3.12 -m pip install 'microguard[live] @ git+https://github.com/Ayyankhan101/microguard.git'

echo "==> systemd units"
cat >/etc/systemd/system/microguard-serve.service <<UNIT
[Unit]
Description=Microguard check server (observe-only)
After=network.target redis6.service
Requires=redis6.service

[Service]
User=${SERVE_USER}
# --block-threshold 1.0 with a strict > comparison means no score can ever
# exceed it. Nothing is blocked; everything is scored and recorded.
ExecStart=/usr/local/bin/microguard serve \\
    --host 127.0.0.1 --port 8400 \\
    --block-threshold 1.0 \\
    --collect-to ${COLLECT_TO} \\
    --deployment-id prod-1
Restart=always
RestartSec=2
# nginx turns a dead /check into a 500 for the visitor, so the process dying
# is an outage even though Redis failing inside it is not.
[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/microguard-signals.service <<UNIT
[Unit]
Description=Microguard threat-intel refresher (out of the request path)
After=network.target redis6.service
Requires=redis6.service

[Service]
User=${SERVE_USER}
ExecStart=/usr/local/bin/microguard signals --interval 300
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
UNIT

echo "==> nginx site"
cat >/etc/nginx/conf.d/microguard.conf <<NGINX
# One page load submits one fingerprint; this is generous for a visitor.
limit_req_zone \$binary_remote_addr zone=microguard_fp:10m rate=30r/m;

server {
    listen 80;
    server_name ${DOMAIN};

    # certbot rewrites this block to add TLS. Until it runs, the fingerprint
    # script cannot execute -- crypto.subtle needs a secure context.

    # The check itself. internal = unreachable from outside; /check is an
    # oracle if exposed, and port 8400 must never be published either.
    location = /_microguard_check {
        internal;
        proxy_pass http://127.0.0.1:8400/check;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI \$request_uri;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Original-Method \$request_method;
        proxy_set_header User-Agent \$http_user_agent;
        proxy_set_header Referer \$http_referer;
    }

    # The fingerprint routes: public by design, answering 200 with identical
    # bytes for every outcome, so they cannot be used as an oracle. Same block
    # as docs/howto-deploy-behind-nginx.md. fingerprint.js posts to
    # /microguard/fp, so these are the routes that have to match, and
    # X-Real-IP binds the hash to the visitor rather than to 127.0.0.1.
    # Exact matches, never a prefix: a prefix location with a URI in
    # proxy_pass would also publish /check as /microguard/check.
    location = /microguard/fp {
        proxy_pass http://127.0.0.1:8400/fp;
        client_max_body_size  2k;
        client_body_timeout   5s;
        send_timeout          5s;
        proxy_read_timeout    5s;
        limit_req zone=microguard_fp burst=5 nodelay;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For "";
    }

    location = /microguard/fingerprint.js {
        proxy_pass http://127.0.0.1:8400/fingerprint.js;
    }

    location / {
        auth_request /_microguard_check;
        root /usr/share/nginx/html;
        index index.html;
    }
}
NGINX

systemctl daemon-reload
systemctl enable --now microguard-serve microguard-signals
nginx -t && systemctl enable --now nginx

cat <<DONE

==> Provisioned. NOT yet collecting usefully -- two steps left:

  1. TLS (mandatory, not cosmetic):
       dnf -y install certbot python3-certbot-nginx
       certbot --nginx -d ${DOMAIN}

  2. Put the fingerprint script on your page, inside <body>:
       <script src="/microguard/fingerprint.js" defer></script>

Archive:   ${COLLECT_TO}
Dashboard: ssh -L 8500:127.0.0.1:8500 <host>, then microguard dashboard

Nothing is blocked at --block-threshold 1.0. Verify before sharing the link:
  curl -sS -o /dev/null -w '%{http_code}\\n' https://${DOMAIN}/    # expect 200
  systemctl is-active microguard-serve microguard-signals nginx redis6
DONE
