"""The static shop the ladder's actors visit.

Big enough that a crawl has depth (200 product pages) and with an app surface
an attack tool can aim at (`/search`, `/login`). Every HTML page embeds the
real fingerprint script, as the deployment docs tell an operator to.
"""

from __future__ import annotations

from pathlib import Path

PRODUCTS = 200
SCRIPT = '<script src="/microguard/fingerprint.js" defer></script>'


def product_path(i: int) -> str:
    return f"/catalog/p{i:03d}.html"


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{title}</title></head><body>"
        "<nav><a href=\"/\">Home</a> · <a href=\"/catalog/\">Catalog</a> · "
        "<a href=\"/login.html\">Sign in</a>"
        "<form action=\"/search\" method=\"get\"><input name=\"q\"><button>Search</button></form></nav>"
        f"<main>{body}</main>{SCRIPT}</body></html>\n"
    )


def build(root: Path) -> None:
    (root / "catalog").mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text(
        _page("Lab shop", "<h1>Lab shop</h1><p>Hand-picked things. Browse the "
              "<a href=\"/catalog/\">catalog</a>.</p>"),
        encoding="utf-8",
    )
    listing = "".join(
        f"<li><a href=\"{product_path(i)}\">Product {i}</a></li>" for i in range(1, PRODUCTS + 1)
    )
    (root / "catalog" / "index.html").write_text(
        _page("Catalog", f"<h1>Catalog</h1><ul>{listing}</ul>"), encoding="utf-8"
    )
    for i in range(1, PRODUCTS + 1):
        related = "".join(
            f"<li><a href=\"{product_path((i + k - 1) % PRODUCTS + 1)}\">Product "
            f"{(i + k - 1) % PRODUCTS + 1}</a></li>"
            for k in (1, 7, 31)
        )
        body = (
            f"<h1>Product {i}</h1><p>{'A sturdy, well-reviewed item. ' * 12}</p>"
            f"<p>Price: {9 + (i * 37) % 190}.99</p><h2>Related</h2><ul>{related}</ul>"
        )
        (root / "catalog" / f"p{i:03d}.html").write_text(_page(f"Product {i}", body), encoding="utf-8")
    (root / "login.html").write_text(
        _page("Sign in", "<h1>Sign in</h1><form id=\"login\" action=\"/login\" method=\"post\">"
              "<input name=\"username\" autocomplete=\"username\">"
              "<input name=\"password\" type=\"password\" autocomplete=\"current-password\">"
              "<button type=\"submit\">Sign in</button></form>"),
        encoding="utf-8",
    )
    (root / "search.html").write_text(
        _page("Search", "<h1>Results</h1><p>No products matched.</p>"), encoding="utf-8"
    )
    (root / "denied.html").write_text(
        _page("Sign in failed", "<h1>Wrong username or password</h1>"), encoding="utf-8"
    )
    (root / "robots.txt").write_text("User-agent: *\nAllow: /\n", encoding="utf-8")
