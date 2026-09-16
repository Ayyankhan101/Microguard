"""The collector's nginx config must route what fingerprint.js calls.

scripts/provision-collector.sh shipped routing `location = /fp` while the
script posts to /microguard/fp, so every fingerprint was lost on the collector
and no visitor could ever be labeled human. This pins the two together.
"""

import re
from pathlib import Path

SCRIPT = Path("scripts/provision-collector.sh").read_text(encoding="utf-8")
FINGERPRINT_JS = Path("microguard/live/static/fingerprint.js").read_text(encoding="utf-8")


def _fingerprint_block() -> str:
    start = SCRIPT.index("location /microguard/ {")
    return SCRIPT[start:SCRIPT.index("}", start)]


def test_the_endpoint_the_script_posts_to_is_routed():
    endpoint = re.search(r"var ENDPOINT = '([^']+)'", FINGERPRINT_JS).group(1)
    prefix = endpoint.rsplit("/", 1)[0] + "/"

    assert f"location {prefix} {{" in SCRIPT


def test_the_route_binds_the_hash_to_the_visitor_not_to_nginx():
    assert "X-Real-IP" in _fingerprint_block()


def test_the_public_route_is_rate_limited_by_a_defined_zone():
    assert "limit_req zone=microguard_fp" in _fingerprint_block()
    assert "zone=microguard_fp:" in SCRIPT
