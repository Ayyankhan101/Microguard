"""Suite B1: the Zanbil e-commerce log (22-26 Jan 2019, ~10.3M nginx lines).

Real traffic with no labels, so labels are built only from evidence the
tested detectors never read, or from evidence removed before they run
(PREREGISTRATION.md, Suite B1). Subcommands, run in order:

    python -m benchmarks.public.zanbil split     # zip -> one log per local day
    python -m benchmarks.public.zanbil label     # actor labels per day
    python -m benchmarks.public.zanbil gaps      # human page-view gaps -> ladder pacing
    python -m benchmarks.public.zanbil run       # B1a-B1d, all offline detectors

Data: Kaggle mirror of doi:10.7910/DVN/3QBYB5 (CC0), fetched anonymously:
    curl -L -o benchmarks/data/zanbil/archive.zip \\
      https://www.kaggle.com/api/v1/datasets/download/eliasdabbas/web-server-access-logs
The Dataverse original restricts Access.log.zip; the Kaggle copy is the same log.

This dataset's derived timing files trained the shipped model's human class,
so nothing here evaluates the model. See PREREGISTRATION.md, "Leakage".
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
import sys
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path

from benchmarks.detectors import (
    Actor,
    Detector,
    load_actors,
    offline_scan,
    path_blocklist,
    rate_limit,
    rewrite_user_agent,
    scan_verdicts,
    ua_regex,
)
from benchmarks.metrics import Rate
from microguard.evaluate import PROBE_PREFIXES
from microguard.parser import parse_nginx_line

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "benchmarks" / "data" / "zanbil"
DAYS = DATA / "days"
LABELS = DATA / "labels"
RANGES = ROOT / "benchmarks" / "data" / "crawler_ranges"
RESULTS = ROOT / "benchmarks" / "results" / "zanbil"
GAPS_OUT = ROOT / "benchmarks" / "ladder" / "human_gaps.json"

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)
DATE_RE = re.compile(r"\[(\d{2})/(\w{3})/(\d{4}):")
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

# engine -> (UA claim, hostname suffixes that verify it)
ENGINES = {
    "google": (re.compile(r"googlebot", re.IGNORECASE), ("googlebot.com", "google.com")),
    "bing": (re.compile(r"bingbot|msnbot", re.IGNORECASE), ("search.msn.com",)),
    "yandex": (re.compile(r"yandex", re.IGNORECASE), ("yandex.ru", "yandex.net", "yandex.com")),
    "apple": (re.compile(r"applebot", re.IGNORECASE), ("applebot.apple.com",)),
    "baidu": (re.compile(r"baiduspider", re.IGNORECASE), ("baidu.com", "baidu.jp")),
}
CRAWLER_TOKEN = re.compile(r"bot|crawl|spider|slurp", re.IGNORECASE)
HUMAN_ACTIONS = ("/basket/add/", "/basket/checkout", "/order/create")
ASSET_PREFIXES = ("/image/", "/static/")
STAFF_PREFIX = "/orderAdministration/"
ASSET_EXT = re.compile(r"\.(css|js|png|jpe?g|gif|svg|webp|woff2?|ttf|ico|map)(\?|$)", re.IGNORECASE)
MAX_SESSION_GAP_S = 30 * 60


# --------------------------------------------------------------------------
# split
# --------------------------------------------------------------------------


def split() -> None:
    """Stream the 3.5 GB log once, writing one file per local calendar day."""
    DAYS.mkdir(parents=True, exist_ok=True)
    handles: dict[str, io.TextIOBase] = {}
    counts: dict[str, int] = defaultdict(int)
    unparsed = sampled = 0
    with zipfile.ZipFile(DATA / "archive.zip") as zf, zf.open("access.log") as raw:
        for n, line in enumerate(io.TextIOWrapper(raw, encoding="utf-8", errors="replace")):
            m = DATE_RE.search(line)
            if not m:
                unparsed += 1
                continue
            day = f"{m.group(3)}-{MONTHS[m.group(2)]:02d}-{m.group(1)}"
            if day not in handles:
                handles[day] = (DAYS / f"{day}.log").open("w", encoding="utf-8")
            handles[day].write(line)
            counts[day] += 1
            # Parse-rate check on a systematic sample: the whole suite rests on
            # microguard's parser reading these lines.
            if n % 100 == 0:
                sampled += 1
                if parse_nginx_line(line.rstrip("\n")) is None:
                    unparsed += 1
    for handle in handles.values():
        handle.close()
    total = sum(counts.values())
    rate = 1 - unparsed / max(sampled, 1)
    meta = {"lines_per_day": dict(sorted(counts.items())), "total": total,
            "parse_rate_sampled": rate, "sampled": sampled}
    (DATA / "split.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=2))
    if rate < 0.95:
        sys.exit(f"parse rate {rate:.1%} is under the pre-registered 95%; stop")


# --------------------------------------------------------------------------
# label
# --------------------------------------------------------------------------


@dataclass
class Evidence:
    uas: set[str] = field(default_factory=set)
    requests: int = 0
    probe: bool = False
    human_action: bool = False
    asset: bool = False
    staff: bool = False


def load_ranges() -> list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    ranges = []
    for engine, name in (("google", "googlebot.json"), ("bing", "bingbot.json")):
        payload = json.loads((RANGES / name).read_text(encoding="utf-8"))
        for prefix in payload["prefixes"]:
            cidr = prefix.get("ipv4Prefix") or prefix.get("ipv6Prefix")
            ranges.append((engine, ipaddress.ip_network(cidr)))
    return ranges


def load_hostnames() -> dict[str, tuple[str, set[str]]]:
    """ip -> (hostname, forward addresses), from the dataset's own lookup file."""
    out: dict[str, tuple[str, set[str]]] = {}
    with zipfile.ZipFile(DATA / "archive.zip") as zf, zf.open("client_hostname.csv") as raw:
        for row in csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8")):
            addresses = set(re.findall(r"[0-9a-fA-F:.]{3,}", row.get("address_list") or ""))
            out[row["client"]] = ((row.get("hostname") or "").lower(), addresses)
    return out


def verified_engine(
    ip: str, ranges, hostnames: dict[str, tuple[str, set[str]]]
) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for engine, net in ranges:
        if addr.version == net.version and addr in net:
            return engine
    hostname, addresses = hostnames.get(ip, ("", set()))
    if ip in addresses:
        for engine, (_claim, suffixes) in ENGINES.items():
            if any(hostname == s or hostname.endswith("." + s) for s in suffixes):
                return engine
    return None


def label_day(day_log: Path, ranges, hostnames) -> dict[str, dict]:
    evidence: dict[str, Evidence] = defaultdict(Evidence)
    with day_log.open(encoding="utf-8") as fh:
        for line in fh:
            entry = parse_nginx_line(line.rstrip("\n"))
            if entry is None:
                continue
            ev = evidence[entry.ip]
            ev.requests += 1
            ev.uas.add(entry.user_agent)
            path = entry.url.split("?", 1)[0]
            if path.startswith(PROBE_PREFIXES):
                ev.probe = True
            if path.startswith(HUMAN_ACTIONS):
                ev.human_action = True
            if path.startswith(ASSET_PREFIXES) or ASSET_EXT.search(path):
                ev.asset = True
            if path.startswith(STAFF_PREFIX):
                ev.staff = True

    labels: dict[str, dict] = {}
    for ip, ev in evidence.items():
        claimed = sorted(
            engine for engine, (claim, _s) in ENGINES.items()
            if any(claim.search(ua) for ua in ev.uas)
        )
        verified = verified_engine(ip, ranges, hostnames) if claimed else None
        bot = None
        if claimed:
            bot = "verified_crawler" if verified in claimed else "unverified_crawler"
        elif ev.probe:
            bot = "probe_bot"
        browser_like = all(ua.startswith("Mozilla/") and not CRAWLER_TOKEN.search(ua)
                           for ua in ev.uas)
        human = None
        if browser_like and ev.human_action and ev.asset:
            human = "staff" if ev.staff else "human_proxy"
        if bot and human:
            label = "conflict"
        else:
            label = bot or human or "unlabeled"
        labels[ip] = {"label": label, "requests": ev.requests, "claimed": claimed,
                      "verified": verified, "probe": ev.probe}
    return labels


def label() -> None:
    LABELS.mkdir(parents=True, exist_ok=True)
    ranges, hostnames = load_ranges(), load_hostnames()
    summary = {}
    for day_log in sorted(DAYS.glob("*.log")):
        labels = label_day(day_log, ranges, hostnames)
        (LABELS / f"{day_log.stem}.json").write_text(json.dumps(labels), encoding="utf-8")
        counts: dict[str, int] = defaultdict(int)
        for info in labels.values():
            counts[info["label"]] += 1
        summary[day_log.stem] = dict(sorted(counts.items()))
        print(day_log.stem, summary[day_log.stem], flush=True)
    (LABELS / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------
# gaps
# --------------------------------------------------------------------------


SITE_REFERER = re.compile(r"^https?://(?:www\.)?zanbil\.ir(/[^ ]*)$")


def gaps() -> None:
    """Seconds between consecutive page views of human-proxy actors.

    A page view is a GET answered 200 whose URL that same actor later sends
    as the Referer of another request: the browser rendered it and fetched
    what it embeds. URL shape cannot tell a page from a widget call on this
    site (`/settings/logo` is fetched on every page), but the Referer can.

    Gaps of 0 are the same second (redirects, double loads) and gaps over 30
    minutes are a new session; both are dropped. The ladder clips what
    remains to [1, 30] s at sampling time, and says so.
    """
    values: list[float] = []
    actors = 0
    for day_log in sorted(DAYS.glob("*.log")):
        labels = json.loads((LABELS / f"{day_log.stem}.json").read_text(encoding="utf-8"))
        humans = {ip for ip, info in labels.items() if info["label"] == "human_proxy"}
        gets: dict[str, list[tuple[float, str]]] = defaultdict(list)
        referred: dict[str, set[str]] = defaultdict(set)
        with day_log.open(encoding="utf-8") as fh:
            for line in fh:
                entry = parse_nginx_line(line.rstrip("\n"))
                if entry is None or entry.ip not in humans:
                    continue
                m = SITE_REFERER.match(entry.referer)
                if m:
                    referred[entry.ip].add(m.group(1))
                if entry.method == "GET" and entry.status == 200:
                    gets[entry.ip].append((entry.timestamp.timestamp(), entry.url))
        for ip, requests in gets.items():
            views = sorted(t for t, url in requests if url in referred[ip])
            if views:
                actors += 1
            values.extend(
                b - a for a, b in pairwise(views) if 0 < b - a <= MAX_SESSION_GAP_S
            )
    values.sort()
    qs = [values[round(q / 1000 * (len(values) - 1))] for q in range(1001)]
    payload = {
        "source": "Zanbil nginx log (Kaggle mirror of doi:10.7910/DVN/3QBYB5), human_proxy actors",
        "definition": "seconds between consecutive page views of one IP; a page view is a GET "
                      "answered 200 whose URL the same IP later sends as a Referer. 0 s and "
                      ">1800 s gaps dropped",
        "actors": actors,
        "gaps": len(values),
        "median_s": qs[500],
        "quantiles_permille": qs,
    }
    GAPS_OUT.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    print({k: v for k, v in payload.items() if k != "quantiles_permille"})


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------

DETECTORS: dict[str, Detector] = {
    "ua_regex": ua_regex,
    "rate_limit": rate_limit(),
    "path_blocklist": path_blocklist,
}


def _write_subset(day_log: Path, out: Path, ips: set[str], transform=None) -> int:
    """Copy one day's lines for `ips`, optionally transformed; returns lines written.

    Scan sessions are per IP, so dropping other actors' lines cannot change a
    kept actor's verdict.
    """
    written = 0
    with day_log.open(encoding="utf-8") as src, out.open("w", encoding="utf-8") as dst:
        for line in src:
            entry = parse_nginx_line(line.rstrip("\n"))
            if entry is None or entry.ip not in ips:
                continue
            new = transform(entry, line) if transform else line
            if new is not None:
                dst.write(new if new.endswith("\n") else new + "\n")
                written += 1
    return written


def _strip_ua(entry, line):
    return rewrite_user_agent(line.rstrip("\n"), entry.user_agent, CHROME_UA)


def _strip_probes(entry, line):
    return None if entry.url.split("?", 1)[0].startswith(PROBE_PREFIXES) else line


def _score(log: Path, truth: dict[str, bool], extra: dict[str, Detector]) -> dict:
    actors: dict[str, Actor] = load_actors([str(log)], ips=set(truth))
    detectors = {**DETECTORS, **extra}
    out = {}
    for name, detect in detectors.items():
        rates = {True: Rate(0, 0), False: Rate(0, 0)}
        for ip, is_bot in truth.items():
            actor = actors.get(ip)
            hit = detect(actor).flagged if actor is not None and actor.requests else False
            rates[is_bot] = rates[is_bot] + Rate(int(hit), 1)
        out[name] = {"bots_flagged": rates[True].as_dict(), "humans_flagged": rates[False].as_dict()}
    return out


def run() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    tmp = RESULTS / "tmp"
    tmp.mkdir(exist_ok=True)
    results: dict[str, dict] = {}
    for day_log in sorted(DAYS.glob("*.log")):
        day = day_log.stem
        labels = json.loads((LABELS / f"{day}.json").read_text(encoding="utf-8"))
        by_label: dict[str, set[str]] = defaultdict(set)
        for ip, info in labels.items():
            by_label[info["label"]].add(ip)
        day_out: dict[str, dict] = {"counts": {k: len(v) for k, v in by_label.items()}}

        tests = {
            "B1a_verified_as_is": (by_label["verified_crawler"], None),
            "B1b_crawlers_ua_stripped": (by_label["verified_crawler"] | by_label["unverified_crawler"], _strip_ua),
            "B1c_probe_bots_probes_removed": (by_label["probe_bot"], _strip_probes),
            "B1d_humans_as_is": (by_label["human_proxy"] | by_label["staff"], None),
        }
        for test, (ips, transform) in tests.items():
            if not ips:
                day_out[test] = {"actors": 0}
                continue
            log = tmp / f"{day}-{test}.log"
            _write_subset(day_log, log, ips, transform)
            present = {e for e in ips if e in _ips_in(log)}
            if test == "B1d_humans_as_is":
                truth = {ip: False for ip in present}
            else:
                truth = {ip: True for ip in present}
            scan = scan_verdicts(str(log)) if present else {}
            scored = _score(log, truth, {"mg_scan": offline_scan(scan)})
            day_out[test] = {"actors": len(ips), "actors_with_requests_left": len(present),
                             "detectors": scored}
            if test == "B1d_humans_as_is":
                staff = {ip: False for ip in present & by_label["staff"]}
                human = {ip: False for ip in present & by_label["human_proxy"]}
                day_out[test]["split"] = {
                    "staff": _score(log, staff, {"mg_scan": offline_scan(scan)}) if staff else {},
                    "human_proxy": _score(log, human, {"mg_scan": offline_scan(scan)}) if human else {},
                }
            print(day, test, len(present), flush=True)
        results[day] = day_out
    (RESULTS / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")


def _ips_in(log: Path) -> set[str]:
    with log.open(encoding="utf-8") as fh:
        return {line.split(" ", 1)[0] for line in fh if line.strip()}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("step", choices=["split", "label", "gaps", "run"])
    args = parser.parse_args(argv)
    {"split": split, "label": label, "gaps": gaps, "run": run}[args.step]()


if __name__ == "__main__":
    main()
