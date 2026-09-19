"""CrowdSec as a baseline: replay an access log through the real engine.

CrowdSec (https://crowdsec.net) is a widely deployed open-source IPS. Running
it over the same access log a detector saw is the honest "what would an operator
reach for instead" comparison. It replays in a throwaway container, one-shot,
with the nginx + base-http + http-cve collections, and returns the IPs it raised
an alert on.

Two facts shape the wiring:

- **CrowdSec whitelists private ranges.** 10.0.0.0/8 and friends are trusted by
  its default whitelists, and the lab's actors live in 10.66/10.99. So for the
  lab logs each private actor IP is mapped 1:1 to a public one before replay and
  mapped back after (`_publicize`/`_restore`). microguard's own detectors key on
  behaviour, not IP, and score the real lab IPs; only CrowdSec needs this, and
  only because it is IP-reputation-aware. Public logs (Zanbil) pass through
  unchanged.
- **A file source tails from EOF.** The one-shot `crowdsec -dsn file://... `
  mode is what reads a whole cold log, so that is used rather than acquisition.

Returns None when Docker is unavailable, which the report records as "not run"
(PREREGISTRATION.md, Suite A detectors).
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

IMAGE = "crowdsecurity/crowdsec:latest"
COLLECTIONS = "crowdsecurity/nginx crowdsecurity/base-http-scenarios crowdsecurity/http-cve"
CACHE = Path(__file__).resolve().parents[1] / "results" / "crowdsec_cache"
PRIVATE_RE = re.compile(r"^10\.(66|99)\.")
STARTUP_TRIES = 25


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(
        ["docker", "info"], capture_output=True, timeout=20, check=False
    ).returncode == 0


def _publicize(line: str) -> str:
    """10.66.x.y -> 45.66.x.y, 10.99.x.y -> 45.99.x.y, at line start only."""
    return PRIVATE_RE.sub(lambda m: f"45.{m.group(1)}.", line, count=1)


def _restore(ip: str) -> str:
    return re.sub(r"^45\.(66|99)\.", lambda m: f"10.{m.group(1)}.", ip)


def _fingerprint(access_log: Path) -> str:
    h = hashlib.sha256()
    h.update(access_log.read_bytes())
    return h.hexdigest()[:16]


def crowdsec_flagged_ips(access_log: Path, use_cache: bool = True) -> set[str] | None:
    """The set of (original) IPs CrowdSec alerted on for this log.

    None if Docker is not available. Result is cached by log content, so
    re-scoring does not re-run the container.
    """
    access_log = Path(access_log)
    CACHE.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE / f"{_fingerprint(access_log)}.json"
    if use_cache and cache_file.exists():
        return set(json.loads(cache_file.read_text(encoding="utf-8")))
    if not _docker_ok():
        return None

    flagged = _replay(access_log)
    cache_file.write_text(json.dumps(sorted(flagged)), encoding="utf-8")
    return flagged


def _replay(access_log: Path) -> set[str]:
    name = f"csbench_{_fingerprint(access_log)}"
    with tempfile.TemporaryDirectory() as tmp:
        pub = Path(tmp) / "access.log"
        with access_log.open(encoding="utf-8", errors="replace") as src, \
                pub.open("w", encoding="utf-8") as dst:
            for line in src:
                dst.write(_publicize(line))
        acquis = Path(tmp) / "acquis.d"
        acquis.mkdir()
        acquis.chmod(0o777)

        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        subprocess.run([
            "docker", "run", "-d", "--name", name,
            "-e", "DISABLE_ONLINE_API=true", "-e", "CROWDSEC_BYPASS_DB_VOLUME_CHECK=true",
            "-e", f"COLLECTIONS={COLLECTIONS}",
            "-v", f"{acquis}:/etc/crowdsec/acquis.d",
            "-v", f"{pub}:/logs/access.log:ro",
            IMAGE,
        ], capture_output=True, check=True, timeout=60)
        try:
            _await_lapi(name)
            subprocess.run(
                ["docker", "exec", name, "crowdsec", "-no-api",
                 "-dsn", "file:///logs/access.log", "-type", "nginx"],
                capture_output=True, timeout=300, check=False,
            )
            raw = subprocess.run(
                ["docker", "exec", name, "cscli", "alerts", "list", "-o", "json"],
                capture_output=True, timeout=30, check=True, text=True,
            ).stdout
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)

    alerts = json.loads(raw) if raw.strip() else []
    return {_restore(a["source"]["ip"]) for a in alerts if a.get("source", {}).get("ip")}


def _await_lapi(name: str) -> None:
    import time
    for _ in range(STARTUP_TRIES):
        ok = subprocess.run(
            ["docker", "exec", name, "cscli", "lapi", "status"],
            capture_output=True, check=False,
        ).returncode == 0
        if ok:
            return
        time.sleep(3)
    raise RuntimeError(f"CrowdSec LAPI did not come up in container {name}")
