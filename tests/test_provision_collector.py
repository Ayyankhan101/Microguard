"""The collector's nginx config must route what fingerprint.js calls, and the
/check oracle must never be reachable through a public prefix location.

scripts/provision-collector.sh shipped routing `location = /fp` while the
script posts to /microguard/fp, so every fingerprint was lost on the collector
and no visitor could ever be labeled human. This pins the two together.

Separately, a `location /microguard/ { proxy_pass http://127.0.0.1:8400/; }`
prefix block maps /microguard/check -> /check, publishing the scoring oracle.
Only exact-match locations are safe here.
"""

import re
from pathlib import Path

SCRIPT = Path("scripts/provision-collector.sh").read_text(encoding="utf-8")
FINGERPRINT_JS = Path("microguard/live/static/fingerprint.js").read_text(encoding="utf-8")
NGINX_DEPLOY_DOC = Path("docs/howto-deploy-behind-nginx.md").read_text(encoding="utf-8")


def _endpoint() -> str:
    return re.search(r"var ENDPOINT = '([^']+)'", FINGERPRINT_JS).group(1)


def _block(text: str, marker: str) -> str:
    start = text.index(marker)
    return text[start:text.index("}", start)]


def _fingerprint_block() -> str:
    return _block(SCRIPT, f"location = {_endpoint()} {{")


def test_the_endpoint_the_script_posts_to_is_routed():
    assert f"location = {_endpoint()} {{" in SCRIPT


def test_the_route_binds_the_hash_to_the_visitor_not_to_nginx():
    assert "X-Real-IP" in _fingerprint_block()


def test_the_public_route_is_rate_limited_by_a_defined_zone():
    assert "limit_req zone=microguard_fp" in _fingerprint_block()
    assert "zone=microguard_fp:" in SCRIPT


def test_the_check_endpoint_is_not_reachable_through_a_public_prefix():
    assert "location /microguard/ {" not in SCRIPT

    check_block = _block(SCRIPT, "location = /_microguard_check {")
    assert "internal;" in check_block

    proxy_line = "proxy_pass http://127.0.0.1:8400/check"
    assert SCRIPT.count(proxy_line) == check_block.count(proxy_line) == 1


def test_the_deploy_doc_does_not_use_a_public_prefix_either():
    assert "location /microguard/ {" not in NGINX_DEPLOY_DOC
