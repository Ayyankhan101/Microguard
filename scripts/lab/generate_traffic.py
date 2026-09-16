#!/usr/bin/env python3
"""Drive realistic bot and human traffic at the lab site, one source IP per actor.

Ground truth is exact because we assign every actor its IP and its class up
front. Bots are the real tools an attacker uses (ffuf, sqlmap, nuclei) plus
scripted scrapers; humans are multi-page sessions with browser headers, referer
chains, and human-scale gaps. Each actor carries its class IP in X-Forwarded-For,
which the lab nginx lifts into the client IP the scorer and the log both see.

Writes ground_truth.json ({ip: "bot"|"human"}) beside the archive.
"""
from __future__ import annotations

import json
import random
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = "http://127.0.0.1:8080"
BOT_NET, HUMAN_NET = "10.66", "10.99"

BROWSER_UAS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
]
PAGES = ["/", "/how.html", "/about.html", "/how.html", "/"]


def _req(path, ip, ua, referer=None, method="GET", body=None):
    url = BASE + path
    headers = {"X-Forwarded-For": ip, "User-Agent": ua}
    if referer:
        headers["Referer"] = BASE + referer
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:  # noqa: BLE001 - any network error is just a dropped request
        return 0


def human(i: int):
    """One realistic visitor: lands via an invite link, browses, fingerprints."""
    ip = f"{HUMAN_NET}.{i // 250}.{i % 250 + 1}"
    ua = random.choice(BROWSER_UAS)
    token = "cohort1"
    _req(f"/?ref={token}", ip, ua, referer=None)
    # A real browser fetches the deferred script and posts its hash on load,
    # within a second -- that burst is genuine browser behaviour.
    time.sleep(random.uniform(0.3, 0.9))
    _req("/microguard/fingerprint.js", ip, ua, referer="/")
    _req("/microguard/fp", ip, ua, referer="/", method="POST",
         body=json.dumps({"fingerprint_hash": f"{random.getrandbits(256):064x}"}).encode())
    prev = "/"
    # Then the person reads. Real dwell time is seconds to tens of seconds per
    # page; anything faster is a scraper. Short dwell is exactly what made an
    # earlier version of this generator trip the >50 req/min rule and inflate
    # the human false-positive rate, so it has to be realistic here.
    for page in random.sample(PAGES, k=random.randint(3, 5)):
        time.sleep(random.uniform(6.0, 18.0))
        _req(page, ip, ua, referer=prev)
        prev = page
    return ip


def scraper_bot(i: int):
    """Fast, headless, no dwell: many pages back to back, tool-ish UA."""
    ip = f"{BOT_NET}.10.{i + 1}"
    ua = random.choice(["python-requests/2.31.0", "Scrapy/2.11 (+https://scrapy.org)",
                        "Go-http-client/2.0", "curl/8.7.1"])
    for path in ["/", "/how.html", "/about.html", "/search?q=1", "/_hp/archive",
                 "/how.html", "/about.html", "/", "/search?q=2"]:
        _req(path, ip, ua)  # no referer, no gaps
    return ip


def credential_bot(i: int):
    """Hammers auth-ish and probe paths: the exploit-scan shape."""
    ip = f"{BOT_NET}.20.{i + 1}"
    ua = "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
    for path in ["/.env", "/wp-login.php", "/wp-admin/", "/.git/config",
                 "/phpmyadmin/", "/xmlrpc.php", "/.aws/credentials", "/boaform/admin/formLogin"]:
        _req(path, ip, ua)
    return ip


def run_tool(cmd, ip, name, log):
    if not shutil.which(cmd[0]):
        log(f"  skip {name}: {cmd[0]} not installed")
        return None
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=180, check=False)
        log(f"  {name} done ({ip})")
    except subprocess.TimeoutExpired:
        log(f"  {name} timed out, partial traffic kept ({ip})")
    except Exception as e:  # noqa: BLE001
        log(f"  {name} error: {e}")
    return ip


def main():
    n_humans = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    n_scrapers = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    n_cred = int(sys.argv[3]) if len(sys.argv) > 3 else 12
    out = sys.argv[4] if len(sys.argv) > 4 else "scripts/lab/.run/ground_truth.json"

    lock = threading.Lock()
    def log(m):
        with lock:
            print(m, flush=True)

    truth: dict[str, str] = {}

    # Real attack tools, each pinned to its own bot IP via X-Forwarded-For.
    ffuf_ip, sqlmap_ip, nuclei_ip = f"{BOT_NET}.30.1", f"{BOT_NET}.30.2", f"{BOT_NET}.30.3"
    wordlist = "scripts/lab/.run/wordlist.txt"
    with open(wordlist, "w") as w:
        w.write("".join(f"{p}\n" for p in (".env", "wp-login.php", "admin",
            "_hp", "how.html", "about.html", "phpmyadmin", ".git", "search", "robots.txt")))

    tool_jobs = [
        (["ffuf", "-u", f"{BASE}/FUZZ", "-w", wordlist, "-H", f"X-Forwarded-For: {ffuf_ip}",
          "-mc", "all", "-t", "10", "-p", "0.05", "-s"], ffuf_ip, "ffuf"),
        (["sqlmap", "-u", f"{BASE}/search?q=1", "--batch", "--level=1", "--risk=1",
          "--technique=B", "--headers", f"X-Forwarded-For: {sqlmap_ip}", "--flush-session",
          "--disable-coloring"], sqlmap_ip, "sqlmap"),
        (["nuclei", "-u", BASE, "-H", f"X-Forwarded-For: {nuclei_ip}", "-rl", "50",
          "-timeout", "3", "-silent", "-nc", "-tags", "exposure,misconfig,tech"],
         nuclei_ip, "nuclei"),
    ]

    log(f"humans={n_humans} scrapers={n_scrapers} credential={n_cred} + real tools")
    with ThreadPoolExecutor(max_workers=48) as pool:
        futs = []
        for cmd, ip, name in tool_jobs:
            truth[ip] = "bot"
            futs.append(pool.submit(run_tool, cmd, ip, name, log))
        for i in range(n_humans):
            truth[f"{HUMAN_NET}.{i // 250}.{i % 250 + 1}"] = "human"
            futs.append(pool.submit(human, i))
        for i in range(n_scrapers):
            truth[f"{BOT_NET}.10.{i + 1}"] = "bot"
            futs.append(pool.submit(scraper_bot, i))
        for i in range(n_cred):
            truth[f"{BOT_NET}.20.{i + 1}"] = "bot"
            futs.append(pool.submit(credential_bot, i))
        for f in futs:
            f.result()

    with open(out, "w") as fh:
        json.dump(truth, fh, indent=2)
    log(f"wrote {out}: {sum(v=='human' for v in truth.values())} human, "
        f"{sum(v=='bot' for v in truth.values())} bot actors")


if __name__ == "__main__":
    main()
