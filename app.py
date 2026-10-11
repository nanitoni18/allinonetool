# ============================================================
# Email journeys — Single-file Flask App (Neon Nexus Edition)
# Includes: Converter, Generators, Blocklist, Email Hunter
# Session: 1 hour  |  Theme: Neon Nexus  |  Deep-crawl Hunter
# ============================================================
from flask import Flask, request, jsonify, session, redirect, url_for, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from email.header import decode_header
from datetime import timedelta
import base64, random, string, secrets, socket, ipaddress, os, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Email Hunter deps (optional; app still runs if missing) ---
try:
    import requests
    from bs4 import BeautifulSoup
    import re as _re_h
    from urllib.parse import urljoin, urlparse, urlunparse
    from collections import deque as _deque_h
    HAS_HUNTER = True
except ImportError:
    HAS_HUNTER = False

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_123456789")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    SESSION_REFRESH_EACH_REQUEST=False,
)

SESSION_MAX_AGE = 60 * 60

LOGIN_USERNAME = os.environ.get("LOGIN_USERNAME", "admin")
LOGIN_PASSWORD_HASH = generate_password_hash(os.environ.get("LOGIN_PASSWORD", "admin"))


# ============================================================
# Error handler
# ============================================================
@app.errorhandler(Exception)
def _handle_any_error(e):
    if request.path.startswith("/api/"):
        if isinstance(e, HTTPException):
            return jsonify(error=e.description or e.name), e.code
        app.logger.exception("Unhandled error on %s", request.path)
        return jsonify(error=f"Server error: {type(e).__name__}: {e}"), 500
    if isinstance(e, HTTPException):
        return e
    app.logger.exception("Unhandled error on %s", request.path)
    return "Internal Server Error", 500


# ============================================================
# Email Hunter — deep crawler + extractor
# ============================================================
if HAS_HUNTER:
    HUNTER_MAX_TIME = 120
    HUNTER_TIMEOUT = 12
    HUNTER_UAS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    ]
    HUNTER_LINK_ATTRS = [
        "href", "src", "data-url", "data-href", "data-link", "data-target",
        "data-page", "data-route", "data-menu", "data-items", "data-submenu",
        "action", "formaction", "onclick"
    ]
    HUNTER_CONTACT_KEYWORDS = [
        "contact", "kontakt", "impressum", "about", "team", "directory",
        "service", "support", "help", "info", "personen", "mitarbeiter",
        "ansprechpartner", "generalvikariat", "ordinariat", "pfarreien",
        "dekanate", "referate", "stellenangebote", "presse", "medien",
        "ueber-uns", "uber-uns", "wir"
    ]
    HUNTER_GUESS_PATHS = [
        "/kontakt", "/impressum", "/uber-uns", "/ueber-uns", "/team",
        "/ansprechpartner", "/mitarbeiter", "/datenschutz", "/personen",
        "/generalvikariat", "/ordinariat", "/pfarreien", "/dekanate",
        "/referate", "/stellenangebote", "/presse", "/medien",
        "/contact", "/about", "/about-us", "/contact-us", "/imprint",
    ]

    _EMAIL_RE = _re_h.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    _OBFUSCATED_RE = _re_h.compile(
        r"([a-zA-Z0-9._%+\-]+)\s*(?:\[at\]|\(at\)|\bat\b)\s*"
        r"([a-zA-Z0-9.\-]+)\s*(?:\[dot\]|\(dot\)|\bdot\b)\s*"
        r"([a-zA-Z]{2,})",
        _re_h.IGNORECASE
    )
    _BAD_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
                ".css", ".js", ".ico", ".woff", ".woff2", ".ttf",
                ".pdf", ".zip", ".mp4", ".mp3", ".doc", ".docx",
                ".xls", ".xlsx", ".ppt", ".pptx", ".avi", ".mov", ".map")

    def _is_valid_email(e):
        if not e or len(e) > 254 or e.count("@") != 1:
            return False
        local, domain = e.split("@")
        if not local or not domain or "." not in domain:
            return False
        if domain.startswith(".") or domain.endswith("."):
            return False
        if any(domain.endswith(x) for x in _BAD_EXT):
            return False
        if local.startswith(".") or local.endswith("."):
            return False
        if len(local) < 2:
            return False
        return True

    def hunter_extract_emails(text):
        found = set()
        for m in _EMAIL_RE.findall(text):
            e = m.strip().rstrip(".,;:").lower()
            if _is_valid_email(e):
                found.add(e)
        for local, mid, tld in _OBFUSCATED_RE.findall(text):
            e = f"{local}@{mid}.{tld}".lower()
            if _is_valid_email(e):
                found.add(e)
        return found

    class EmailHunterCrawler:
        def __init__(self, start_url):
            self.start_url = start_url.rstrip("/")
            self.domain = urlparse(start_url).netloc.lower()
            self.domain_alt = self.domain[4:] if self.domain.startswith("www.") else "www." + self.domain
            self.visited = set()
            self.queue = _deque_h()
            self.emails = set()
            self.stats = {
                "pages_visited": 0, "contact_pages": 0,
                "errors": 0, "discovered": 0, "visited": 0,
            }
            self.start_time = None
            self._ua_index = 0

        def _ua(self):
            self._ua_index = (self._ua_index + 1) % len(HUNTER_UAS)
            return HUNTER_UAS[self._ua_index]

        def _is_internal(self, url):
            try:
                p = urlparse(url)
                n = p.netloc.lower()
                return n == self.domain or n == self.domain_alt or n == ""
            except Exception:
                return False

        def _normalize(self, base, link):
            try:
                if not link:
                    return None
                link = str(link).strip()
                if link in ("#", "", "javascript:void(0)", "javascript:;"):
                    return None
                low = link.lower()
                if low.startswith(("mailto:", "tel:", "javascript:", "whatsapp:",
                                    "sms:", "fax:", "data:", "about:")):
                    return None
                absolute = urljoin(base, link)
                p = urlparse(absolute)
                if p.scheme not in ("http", "https"):
                    return None
                return urlunparse(p._replace(fragment=""))
            except Exception:
                return None

        def _is_contact(self, url):
            path = urlparse(url).path.lower()
            return any(kw in path for kw in HUNTER_CONTACT_KEYWORDS)

        def _extract_links(self, soup, base_url):
            """DEEP extractor — finds URLs from everywhere in the page."""
            links = set()

            def _add(candidate):
                u = self._normalize(base_url, candidate)
                if u and self._is_internal(u):
                    links.add(u)

            # 1) Every <a href> — including hidden dropdown submenu links
            for a in soup.find_all("a", href=True):
                _add(a.get("href"))

            # 2) Every <link href>, <area href>
            for tag in soup.find_all(["link", "area"], href=True):
                _add(tag.get("href"))

            # 3) nav / menu / ul / ol — explicit submenu pass
            for nav in soup.find_all(["nav", "menu", "ul", "ol"]):
                for a in nav.find_all("a", href=True):
                    _add(a.get("href"))

            # 4) Elements with link-bearing attributes
            for tag in soup.find_all(True):
                for attr in HUNTER_LINK_ATTRS:
                    val = tag.get(attr)
                    if not val:
                        continue
                    if isinstance(val, list):
                        val = " ".join(str(x) for x in val)
                    val = str(val)

                    if attr == "onclick":
                        for m in _re_h.finditer(r"['\"]([^'\"]+)['\"]", val):
                            inner = m.group(1)
                            if inner.startswith(("/", "http", ".")):
                                _add(inner)
                        for m in _re_h.finditer(r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", val):
                            _add(m.group(1))
                        continue

                    if attr.startswith("data-"):
                        _add(val)
                        for m in _re_h.finditer(r"['\"]([^'\"]+)['\"]", val):
                            inner = m.group(1)
                            if inner.startswith(("/", "http")):
                                _add(inner)
                        for m in _re_h.finditer(r"(?:^|[\s,;\[\({])(/[a-zA-Z0-9_\-./]{2,})", val):
                            _add(m.group(1))
                        continue

                    _add(val)

            # 5) aria-controls / aria-owns — dropdown targets
            for tag in soup.find_all(attrs={"aria-controls": True}):
                ids = str(tag.get("aria-controls", "")).split()
                for tid in ids:
                    target = soup.find(id=tid)
                    if target:
                        for a in target.find_all("a", href=True):
                            _add(a.get("href"))

            # 6) JSON-LD structured data
            for script in soup.find_all("script", type="application/ld+json"):
                txt = script.string or script.get_text() or ""
                for m in _re_h.finditer(r'"(?:url|@id|sameAs|item|target)"\s*:\s*"([^"]+)"', txt):
                    _add(m.group(1))
                for m in _re_h.finditer(r'"(https?://[^"]+)"', txt):
                    _add(m.group(1))

            # 7) Inline <script> — router paths, arrays, nav JSON
            for script in soup.find_all("script"):
                if script.get("src"):
                    continue
                txt = script.string or script.get_text() or ""
                if not txt or len(txt) > 500000:
                    continue
                for m in _re_h.finditer(
                    r"['\"]((?:https?://[^'\"\s<>]+)|(?:/[a-zA-Z0-9_\-./]{2,}))['\"]",
                    txt
                ):
                    _add(m.group(1))
                for m in _re_h.finditer(r'"(?:path|href|url|link|to)"\s*:\s*"([^"]+)"', txt):
                    _add(m.group(1))

            # 8) <select><option value="/path">
            for opt in soup.find_all("option"):
                v = opt.get("value")
                if v and (v.startswith("/") or v.startswith("http")):
                    _add(v)

            # 9) <form action="">
            for form in soup.find_all("form", action=True):
                _add(form.get("action"))

            # 10) <template> blocks (Vue / custom)
            for tmpl in soup.find_all("template"):
                for a in tmpl.find_all("a", href=True):
                    _add(a.get("href"))
                for a in tmpl.find_all(True):
                    for attr in ("data-url", "data-href", "data-link"):
                        v = a.get(attr)
                        if v:
                            _add(v)

            return links

        def _fetch(self, url):
            headers = {
                "User-Agent": self._ua(),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9,de;q=0.8,fr;q=0.7",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Cache-Control": "max-age=0",
            }
            try:
                r = requests.get(url, headers=headers, timeout=HUNTER_TIMEOUT,
                                 allow_redirects=True)
                if r.status_code == 200:
                    if r.encoding and r.encoding.lower() in ("iso-8859-1", "ascii"):
                        r.encoding = r.apparent_encoding or "utf-8"
                    return r.text
                return None
            except Exception:
                self.stats["errors"] += 1
                return None

        def _discover_sitemaps(self):
            sitemaps = []
            try:
                r = requests.get(
                    f"{self.start_url}/robots.txt",
                    headers={"User-Agent": self._ua()}, timeout=8,
                )
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        if line.lower().startswith("sitemap:"):
                            sitemaps.append(line.split(":", 1)[1].strip())
            except Exception:
                pass
            for path in ["/sitemap.xml", "/sitemap", "/site-map",
                         "/sitemap_index.xml", "/sitemap-index.xml"]:
                sitemaps.append(urljoin(self.start_url, path))
            return list(set(sitemaps))

        def _parse_sitemap(self, sm_url, depth=0):
            urls = set()
            if depth > 2:
                return urls
            try:
                r = requests.get(sm_url, headers={"User-Agent": self._ua()}, timeout=8)
                if r.status_code != 200:
                    return urls
                soup = BeautifulSoup(r.text, "xml")
                for sm in soup.find_all("sitemap"):
                    loc = sm.find("loc")
                    if loc and loc.text:
                        urls.update(self._parse_sitemap(loc.text.strip(), depth + 1))
                for loc in soup.find_all("loc"):
                    urls.add(loc.text.strip())
            except Exception:
                pass
            return urls

        def _prioritize(self):
            prior, rest = [], []
            while self.queue:
                u = self.queue.popleft()
                (prior if self._is_contact(u) else rest).append(u)
            self.queue = _deque_h(prior + rest)

        def _enqueue_many(self, urls):
            for u in urls:
                if u not in self.visited and u not in self.queue:
                    self.queue.append(u)
                    self.stats["discovered"] += 1

        def crawl(self):
            self.start_time = time.time()
            self.queue.append(self.start_url)

            # Seed: sitemap
            for sm in self._discover_sitemaps():
                for u in self._parse_sitemap(sm):
                    if self._is_internal(u) and u not in self.visited:
                        self.queue.append(u)
                        self.stats["discovered"] += 1

            # Seed: guessed common paths (dropdowns, contact, etc.)
            for path in HUNTER_GUESS_PATHS:
                candidate = urljoin(self.start_url, path)
                if self._is_internal(candidate) and candidate not in self.visited:
                    self.queue.append(candidate)
                    self.stats["discovered"] += 1

            while self.queue and (time.time() - self.start_time) < HUNTER_MAX_TIME:
                self._prioritize()
                url = self.queue.popleft()
                if url in self.visited:
                    continue
                self.visited.add(url)
                self.stats["visited"] += 1

                html = self._fetch(url)
                if not html:
                    continue

                self.stats["pages_visited"] += 1
                if self._is_contact(url):
                    self.stats["contact_pages"] += 1

                # Emails from raw HTML (catches inline scripts, attributes, etc.)
                self.emails.update(hunter_extract_emails(html))

                try:
                    soup = BeautifulSoup(html, "html.parser")
                except Exception:
                    continue

                # Explicit mailto: extraction
                for a in soup.find_all("a", href=True):
                    href = str(a["href"])
                    if href.lower().startswith("mailto:"):
                        e = href[7:].split("?")[0].strip().lower()
                        if _is_valid_email(e):
                            self.emails.add(e)

                # Deep link extraction
                new_links = self._extract_links(soup, url)
                self._enqueue_many(new_links)

            self.stats["emails"] = len(self.emails)
            self.stats["time_taken"] = round(time.time() - self.start_time, 2)
            return {"emails": sorted(self.emails), "stats": self.stats}

    _hunter_store = {}
    _hunter_status = {}


# ============================================================
# INDEX_HTML — Neon Nexus Theme
# ============================================================
INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Email journeys — Neon Nexus</title>
<meta name="description" content="Email journey toolkit — encoder, generators, blocklist checks and email hunter, in a neon-lit command center.">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --radius:18px;
  --bg:#07080f;
  --bg-soft:#0c0e18;
  --panel:rgba(18,22,38,.72);
  --panel-2:rgba(24,28,48,.6);
  --panel-solid:#121626;
  --text:#e9ecf8;
  --text-soft:#a9b2cb;
  --muted:#697391;
  --line:rgba(120,140,220,.14);
  --line-strong:rgba(140,160,240,.28);
  --cyan:#00e5ff;
  --magenta:#ff2d95;
  --lime:#b8ff2b;
  --violet:#a855f7;
  --ok:#3ddc84;
  --warn:#ffc247;
  --danger:#ff5c8a;
  --shadow:0 20px 50px rgba(0,0,0,.55);
  --shadow-lg:0 34px 80px rgba(0,0,0,.7);
  --glow-cyan:0 0 40px rgba(0,229,255,.30);
  --glow-magenta:0 0 40px rgba(255,45,149,.28);
  --glow-lime:0 0 40px rgba(184,255,43,.25);
  --glow-violet:0 0 40px rgba(168,85,247,.30);
}
body.light{
  --bg:#eef1fa;
  --bg-soft:#e6ebf7;
  --panel:rgba(255,255,255,.82);
  --panel-2:rgba(240,244,255,.7);
  --panel-solid:#ffffff;
  --text:#0c1224;
  --text-soft:#3e4666;
  --muted:#6a7290;
  --line:rgba(20,30,80,.12);
  --line-strong:rgba(20,30,80,.24);
  --cyan:#0091a8;
  --magenta:#c8177a;
  --lime:#5f8f00;
  --violet:#6a2fd6;
  --ok:#1e8a4d;
  --warn:#b07700;
  --danger:#c02a5c;
  --shadow:0 20px 50px rgba(60,80,160,.14);
  --shadow-lg:0 34px 80px rgba(60,80,160,.20);
  --glow-cyan:0 0 40px rgba(0,145,168,.20);
  --glow-magenta:0 0 40px rgba(200,23,122,.18);
  --glow-lime:0 0 40px rgba(95,143,0,.18);
  --glow-violet:0 0 40px rgba(106,47,214,.20);
}

*,*::before,*::after{box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  margin:0;min-height:100vh;
  font-family:'Space Grotesk',system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif;
  font-weight:400;
  background:var(--bg);color:var(--text);
  -webkit-font-smoothing:antialiased;
  transition:background .35s ease,color .35s ease;
  letter-spacing:-0.005em;
  overflow-x:hidden;
}
code,pre,.mono,.output{font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}

.bg-grid{
  position:fixed;inset:0;z-index:0;pointer-events:none;
  background-image:
    linear-gradient(rgba(120,140,220,.06) 1px, transparent 1px),
    linear-gradient(90deg, rgba(120,140,220,.06) 1px, transparent 1px);
  background-size:44px 44px;
  mask-image:radial-gradient(ellipse 90% 70% at 50% 40%, #000 40%, transparent 100%);
  -webkit-mask-image:radial-gradient(ellipse 90% 70% at 50% 40%, #000 40%, transparent 100%);
}
body.light .bg-grid{opacity:.5}

.bg-orbs{position:fixed;inset:0;overflow:hidden;pointer-events:none;z-index:0}
.bg-orbs span{position:absolute;border-radius:50%;filter:blur(120px);opacity:.45;animation:drift 26s ease-in-out infinite}
.bg-orbs span:nth-child(1){width:620px;height:620px;background:radial-gradient(circle,var(--cyan),transparent 70%);top:-220px;left:-180px}
.bg-orbs span:nth-child(2){width:520px;height:520px;background:radial-gradient(circle,var(--magenta),transparent 70%);top:-140px;right:-160px;animation-delay:-8s}
.bg-orbs span:nth-child(3){width:520px;height:520px;background:radial-gradient(circle,var(--lime),transparent 70%);bottom:-220px;left:38%;animation-delay:-16s}
.bg-orbs span:nth-child(4){width:420px;height:420px;background:radial-gradient(circle,var(--violet),transparent 70%);top:40%;right:10%;animation-delay:-12s}
body.light .bg-orbs span{opacity:.25}
@keyframes drift{0%,100%{transform:translate3d(0,0,0) scale(1)}50%{transform:translate3d(40px,-50px,0) scale(1.14)}}

.app{position:relative;z-index:1;max-width:1280px;margin:0 auto;padding:22px 22px 0}

.topbar{
  position:sticky;top:12px;z-index:40;
  display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;
  padding:12px 16px;margin:0 0 30px;
  background:var(--panel);
  backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);
  border:1px solid var(--line);border-radius:16px;
  box-shadow:var(--shadow);
}
.brand{display:flex;align-items:center;gap:12px;cursor:pointer;user-select:none}
.brand svg{width:42px;height:42px;flex:0 0 auto;filter:drop-shadow(0 6px 18px rgba(0,229,255,.4))}
.brand b{display:block;font-size:15.5px;font-weight:600;letter-spacing:-.01em}
.brand span{display:block;color:var(--muted);font-size:9.5px;letter-spacing:2px;margin-top:2px;font-weight:600}
.nav{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.nav button{
  border:1px solid transparent;background:transparent;color:var(--text-soft);
  padding:9px 15px;border-radius:10px;cursor:pointer;font-weight:500;font-size:13.5px;
  transition:.2s ease;font-family:inherit;letter-spacing:-.01em;
}
.nav button:hover{color:var(--text);background:var(--panel-2);border-color:var(--line)}
.nav button.active{
  color:#050612;background:linear-gradient(120deg,var(--cyan),var(--lime));
  box-shadow:var(--glow-cyan);
  font-weight:600;
}
body.light .nav button.active{color:#fff}
.nav .icon-btn{padding:9px 13px;font-size:15px;background:var(--panel-2);border:1px solid var(--line)}
.nav .logout{
  background:transparent;border:1px solid color-mix(in srgb,var(--danger) 40%,transparent);
  color:var(--danger);font-weight:500;
}
.nav .logout:hover{background:color-mix(in srgb,var(--danger) 12%,transparent);color:var(--danger)}

.page{display:none;animation:fade .4s ease}
.page.active{display:block}
@keyframes fade{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}

.home-wrap{
  display:grid;grid-template-columns:1.15fr .85fr;gap:48px;align-items:center;
  padding:26px 6px 52px;
}
.hero-left{max-width:640px}
.status-chip{
  display:inline-flex;align-items:center;gap:9px;
  padding:7px 15px;border-radius:99px;
  font-size:11.5px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;
  background:color-mix(in srgb,var(--cyan) 12%,transparent);
  color:var(--cyan);border:1px solid color-mix(in srgb,var(--cyan) 35%,transparent);
  font-family:'JetBrains Mono',monospace;
}
.status-chip .dot{width:7px;height:7px;border-radius:50%;background:var(--cyan);box-shadow:0 0 12px var(--cyan);animation:pulse 1.8s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.85)}}

.hero-title{
  font-size:clamp(42px,5.6vw,72px);line-height:.98;margin:24px 0 22px;
  letter-spacing:-.04em;font-weight:700;
}
.hero-title .line-1{display:block;color:var(--text)}
.hero-title .line-2{
  display:block;font-weight:500;
  background:linear-gradient(100deg,var(--cyan) 0%,var(--lime) 30%,var(--magenta) 60%,var(--violet) 100%);
  -webkit-background-clip:text;background-clip:text;color:transparent;
  background-size:220% auto;animation:shine 8s linear infinite;
}
@keyframes shine{to{background-position:220% center}}

.hero-desc{
  color:var(--text-soft);font-size:16px;line-height:1.75;margin:0 0 30px;max-width:560px;
}
.hero-desc code{
  background:color-mix(in srgb,var(--cyan) 12%,transparent);
  color:var(--cyan);padding:2px 7px;border-radius:6px;
  font-size:13px;font-family:'JetBrains Mono',monospace;
  border:1px solid color-mix(in srgb,var(--cyan) 22%,transparent);
}

.hero-actions{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:34px}

.terminal{
  background:#05060c;
  border:1px solid rgba(0,229,255,.20);
  border-radius:14px;overflow:hidden;
  box-shadow:var(--shadow-lg), 0 0 60px rgba(0,229,255,.08);
  font-family:'JetBrains Mono',monospace;
  position:relative;
}
.terminal::before{
  content:'';position:absolute;inset:0;border-radius:14px;padding:1px;
  background:linear-gradient(135deg,rgba(0,229,255,.4),transparent 40%,rgba(255,45,149,.4));
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
  -webkit-mask-composite:xor;mask-composite:exclude;
  pointer-events:none;
}
.term-bar{
  display:flex;align-items:center;gap:8px;padding:11px 14px;
  background:rgba(10,12,22,.9);border-bottom:1px solid rgba(120,140,220,.12);
}
.term-bar .dot{width:10px;height:10px;border-radius:50%}
.term-bar .dot.r{background:#ff5f57}
.term-bar .dot.y{background:#ffbd2e}
.term-bar .dot.g{background:#28c840}
.term-bar b{margin-left:8px;font-size:11.5px;font-weight:500;color:var(--muted);letter-spacing:.06em}
.term-body{padding:20px 18px;font-size:12px;line-height:1.85;color:var(--text-soft)}
.term-line{display:flex;gap:12px;padding:3px 0;word-break:break-all}
.term-prompt{color:var(--lime);flex:0 0 auto;font-weight:500}
.term-out{color:#8b9bc6}
.term-out.cyan{color:var(--cyan)}
.term-out.magenta{color:var(--magenta)}
.term-out.lime{color:var(--lime)}
.term-cursor{display:inline-block;width:8px;height:14px;background:var(--cyan);margin-left:4px;animation:blink 1s steps(1) infinite;vertical-align:middle}
@keyframes blink{50%{opacity:0}}

.quick-stats{
  display:grid;grid-template-columns:repeat(4,1fr);gap:14px;
  margin-bottom:52px;
}
.qs-card{
  padding:22px 20px;border-radius:16px;
  background:var(--panel);border:1px solid var(--line);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  box-shadow:var(--shadow);
  position:relative;overflow:hidden;
  transition:.3s ease;
}
.qs-card::before{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--cyan),var(--magenta),var(--lime));
  opacity:.7;
}
.qs-card:hover{transform:translateY(-4px);border-color:var(--line-strong);box-shadow:var(--shadow-lg)}
.qs-num{
  display:block;font-size:30px;font-weight:700;letter-spacing:-.04em;line-height:1;margin-bottom:8px;
  background:linear-gradient(120deg,var(--cyan),var(--magenta));
  -webkit-background-clip:text;background-clip:text;color:transparent;
}
.qs-lbl{font-size:11px;color:var(--muted);letter-spacing:.14em;text-transform:uppercase;font-weight:500}

.feature-grid{
  display:grid;grid-template-columns:repeat(6,1fr);gap:18px;margin-bottom:32px;
}
.feat{
  grid-column:span 3;
  padding:28px;border-radius:20px;
  background:var(--panel);border:1px solid var(--line);
  backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);
  box-shadow:var(--shadow);
  position:relative;overflow:hidden;
  transition:.35s ease;
  cursor:pointer;
}
.feat:hover{
  transform:translateY(-4px);
  border-color:var(--line-strong);
  box-shadow:var(--shadow-lg);
}
.feat:hover .feat-glow{opacity:1}
.feat-glow{
  position:absolute;inset:0;opacity:0;transition:.4s ease;pointer-events:none;
  background:radial-gradient(circle at 20% 0%, var(--glow-color,var(--cyan)) 0%, transparent 55%);
  opacity:0;
}
.feat.f-cyan{--glow-color:var(--cyan);--accent-color:var(--cyan)}
.feat.f-magenta{--glow-color:var(--magenta);--accent-color:var(--magenta)}
.feat.f-lime{--glow-color:var(--lime);--accent-color:var(--lime)}
.feat.f-violet{--glow-color:var(--violet);--accent-color:var(--violet)}
.feat:hover .feat-glow{opacity:.9}
.feat-inner{position:relative;z-index:1}
.feat-tag{
  display:inline-block;font-family:'JetBrains Mono',monospace;
  font-size:10px;font-weight:600;letter-spacing:.14em;
  padding:3px 9px;border-radius:6px;
  color:var(--accent-color);
  background:color-mix(in srgb,var(--accent-color) 14%,transparent);
  border:1px solid color-mix(in srgb,var(--accent-color) 30%,transparent);
  margin-bottom:16px;
  text-transform:uppercase;
}
.feat h3{margin:0 0 10px;font-size:20px;font-weight:600;letter-spacing:-.02em;line-height:1.25}
.feat p{color:var(--text-soft);font-size:13.5px;line-height:1.7;margin:0}
.feat-btn{
  display:inline-flex;align-items:center;gap:8px;margin-top:20px;
  font-size:13px;font-weight:600;color:var(--accent-color);cursor:pointer;
  border:0;background:transparent;padding:0;font-family:inherit;
  transition:.25s ease;
}
.feat-btn:hover{gap:12px}
.feat-btn .arrow{transition:.25s ease}
.feat-btn:hover .arrow{transform:translateX(3px)}
.feat.wide{grid-column:span 6}

.section-head{display:flex;justify-content:space-between;align-items:flex-end;gap:20px;margin:4px 0 22px;flex-wrap:wrap}
.section-head h2{margin:0;font-size:28px;letter-spacing:-.03em;font-weight:600}
.section-head h2 .accent{
  background:linear-gradient(100deg,var(--cyan),var(--magenta));
  -webkit-background-clip:text;background-clip:text;color:transparent;
}
.section-head p{margin:6px 0 0;color:var(--muted);font-size:13.5px;line-height:1.7;max-width:760px}

.card{
  background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  padding:24px;box-shadow:var(--shadow);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
}
.card h3{margin:0 0 16px;font-size:16px;font-weight:600;letter-spacing:-.01em}

.tabs{
  display:flex;gap:4px;margin-bottom:20px;flex-wrap:wrap;padding:4px;
  background:var(--panel-2);border-radius:12px;width:fit-content;border:1px solid var(--line);
}
.tab{
  padding:9px 16px;border-radius:9px;border:0;background:transparent;
  color:var(--muted);cursor:pointer;font-weight:500;font-size:13px;
  transition:.2s;font-family:inherit;letter-spacing:-.005em;
}
.tab:hover{color:var(--text)}
.tab.active{
  color:#050612;background:linear-gradient(120deg,var(--cyan),var(--lime));
  font-weight:600;box-shadow:var(--glow-cyan);
}
body.light .tab.active{color:#fff}

.workspace{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.label{
  display:block;color:var(--muted);font-size:10.5px;font-weight:600;
  letter-spacing:1.6px;margin:0 0 8px;text-transform:uppercase;
  font-family:'JetBrains Mono',monospace;
}
textarea,input[type=text],input[type=number]{
  width:100%;font:inherit;font-size:14px;color:var(--text);
  background:var(--panel-2);border:1px solid var(--line);border-radius:12px;
  padding:13px 15px;outline:none;transition:.2s;font-family:inherit;
}
textarea{min-height:170px;resize:vertical;line-height:1.7}
textarea:focus,input:focus{
  border-color:var(--cyan);
  box-shadow:0 0 0 3px color-mix(in srgb,var(--cyan) 18%,transparent);
  background:var(--panel-solid);
}
textarea[readonly]{cursor:text}

.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}
.result{margin-top:14px}
.output{
  min-height:96px;white-space:pre-wrap;word-break:break-word;
  background:var(--panel-2);border:1px solid var(--line);border-radius:12px;
  padding:14px 15px;font-family:'JetBrains Mono',monospace;
  font-size:12.5px;line-height:1.7;color:var(--text-soft);
}
.output-wrap{display:flex;gap:8px;align-items:stretch}
.output-wrap .output{flex:1;min-width:0}
.copy-btn{
  border:1px solid var(--line);background:var(--panel-2);color:var(--text-soft);
  border-radius:12px;padding:0 15px;cursor:pointer;font-weight:500;font-size:12px;
  min-width:80px;transition:.2s;font-family:inherit;
}
.copy-btn:hover{
  border-color:var(--cyan);color:var(--cyan);
  background:color-mix(in srgb,var(--cyan) 8%,transparent);
}

.notice{
  padding:13px 16px;border:1px solid var(--line);border-radius:12px;
  background:var(--panel-2);color:var(--text-soft);
  font-size:13px;line-height:1.7;margin-bottom:18px;
}
.hidden{display:none!important}

button.primary,button.secondary{
  border:0;border-radius:12px;padding:12px 22px;cursor:pointer;
  font-weight:600;font-size:14px;transition:.2s ease;font-family:inherit;
  letter-spacing:-.005em;
}
button.primary{
  color:#050612;
  background:linear-gradient(120deg,var(--cyan),var(--lime));
  box-shadow:var(--glow-cyan);
}
body.light button.primary{color:#fff}
button.primary:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 0 50px rgba(0,229,255,.5)}
button.secondary{
  background:var(--panel-2);color:var(--text);border:1px solid var(--line);
}
button.secondary:hover:not(:disabled){
  border-color:var(--line-strong);transform:translateY(-2px);background:var(--panel-solid);
}
button:disabled{opacity:.5;cursor:not-allowed;transform:none!important}

.controls3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:8px 0 6px}
.helper,.status{color:var(--muted);font-size:12.5px;line-height:1.7}
.status{margin-top:12px;min-height:18px}
.gen-panel{margin-top:18px}

.bl-form{display:grid;grid-template-columns:1fr 1fr auto auto;gap:12px;align-items:end}
.bl-field label{
  display:block;color:var(--muted);font-size:10.5px;font-weight:600;
  letter-spacing:1.6px;margin:0 0 8px;text-transform:uppercase;
  font-family:'JetBrains Mono',monospace;
}
.bl-status{margin-top:16px;color:var(--text-soft);font-size:13px;line-height:1.7}
.bl-health{display:flex;gap:18px;flex-wrap:wrap;margin-top:12px;font-size:12px;color:var(--muted)}
.bl-health b{color:var(--text);font-weight:600}
.bl-progress{
  height:6px;border-radius:99px;background:var(--panel-2);
  overflow:hidden;margin-top:16px;border:1px solid var(--line);
}
.bl-progress-bar{
  height:100%;width:0;
  background:linear-gradient(90deg,var(--cyan),var(--magenta),var(--lime));
  transition:width .3s ease;
}

.bl-summary{display:grid;grid-template-columns:repeat(7,1fr);gap:12px;margin-top:20px}
.bl-summary-item{
  padding:18px 12px;border:1px solid var(--line);border-radius:14px;
  background:var(--panel);text-align:center;box-shadow:var(--shadow);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
}
.bl-summary-item b{
  display:block;font-size:24px;margin-bottom:4px;letter-spacing:-.04em;font-weight:700;
  background:linear-gradient(120deg,var(--cyan),var(--magenta));
  -webkit-background-clip:text;background-clip:text;color:transparent;
}
.bl-summary-item span{
  color:var(--muted);font-size:10.5px;font-weight:600;
  letter-spacing:1.2px;text-transform:uppercase;font-family:'JetBrains Mono',monospace;
}

.bl-table-wrap{
  margin-top:20px;overflow:auto;border:1px solid var(--line);border-radius:16px;
  max-height:660px;box-shadow:var(--shadow);
}
.bl-table{width:100%;min-width:1040px;border-collapse:collapse;background:var(--panel-solid)}
.bl-table thead th{
  position:sticky;top:0;z-index:2;background:var(--panel-2);
  color:var(--muted);font-size:10.5px;letter-spacing:1.2px;text-transform:uppercase;
  font-weight:600;padding:14px 12px;border-bottom:1px solid var(--line);
  text-align:center;font-family:'JetBrains Mono',monospace;
}
.bl-table td{
  padding:11px 12px;border-bottom:1px solid var(--line);
  font-size:12.5px;text-align:center;vertical-align:middle;
}
.bl-table tbody tr:hover td{background:var(--panel-2)}
.bl-table tbody tr:last-child td{border-bottom:0}
.ip-cell,.rdns-cell{text-align:left!important;font-family:'JetBrains Mono',monospace;font-size:11.5px!important}
.bl-status-pill{
  display:inline-block;padding:3px 10px;border-radius:99px;font-size:10px;
  font-weight:600;letter-spacing:.4px;border:1px solid transparent;
  font-family:'JetBrains Mono',monospace;
}
.bl-ok{color:var(--ok);background:color-mix(in srgb,var(--ok) 13%,transparent);border-color:color-mix(in srgb,var(--ok) 32%,transparent)}
.bl-listed{color:var(--danger);background:color-mix(in srgb,var(--danger) 13%,transparent);border-color:color-mix(in srgb,var(--danger) 32%,transparent)}
.bl-error{color:var(--warn);background:color-mix(in srgb,var(--warn) 15%,transparent);border-color:color-mix(in srgb,var(--warn) 34%,transparent)}
.bl-na{color:var(--muted);background:var(--panel-2);border-color:var(--line)}
.bl-total td{background:var(--panel-2);font-weight:700;border-top:2px solid var(--line-strong)}
.bl-dbl-domain{display:block;margin-top:5px;color:var(--muted);font-size:10.5px;word-break:break-all}

.footer{
  text-align:center;color:var(--muted);font-size:12px;
  padding:48px 0 28px;letter-spacing:.02em;
}
.footer .grad{
  background:linear-gradient(100deg,var(--cyan),var(--magenta));
  -webkit-background-clip:text;background-clip:text;color:transparent;
  font-weight:600;
}

.toasts{position:fixed;right:18px;bottom:18px;z-index:100;display:flex;flex-direction:column;gap:10px}
.toast{
  padding:13px 18px;border-radius:12px;font-size:13px;font-weight:500;
  background:var(--panel-solid);border:1px solid var(--line);color:var(--text);
  box-shadow:var(--shadow-lg);animation:toastIn .3s ease;max-width:340px;
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
}
.toast.ok{border-color:color-mix(in srgb,var(--ok) 50%,transparent);color:var(--ok)}
.toast.err{border-color:color-mix(in srgb,var(--danger) 50%,transparent);color:var(--danger)}
@keyframes toastIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}

.session-banner{
  position:fixed;top:14px;left:50%;transform:translateX(-50%);
  z-index:200;padding:9px 16px;border-radius:99px;
  background:var(--panel-solid);border:1px solid var(--line);color:var(--muted);
  font-size:12px;font-weight:500;box-shadow:var(--shadow);display:none;
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
}
.session-banner.show{display:block;animation:toastIn .3s ease}
.session-banner b{
  background:linear-gradient(100deg,var(--cyan),var(--magenta));
  -webkit-background-clip:text;background-clip:text;color:transparent;
}

@media(max-width:980px){
  .home-wrap{grid-template-columns:1fr;padding:18px 4px 34px;gap:34px}
  .feature-grid{grid-template-columns:1fr 1fr}
  .feat, .feat.wide{grid-column:span 1}
  .feat.wide{grid-column:span 2}
  .quick-stats{grid-template-columns:repeat(2,1fr)}
  .workspace,.controls3{grid-template-columns:1fr}
  .bl-form{grid-template-columns:1fr}
  .bl-summary{grid-template-columns:repeat(3,1fr)}
}
@media(max-width:640px){
  .app{padding:14px 14px 0}
  .topbar{position:static}
  .nav{width:100%}
  .nav button{flex:1 1 auto}
  .feature-grid{grid-template-columns:1fr}
  .feat, .feat.wide{grid-column:auto}
  .quick-stats{grid-template-columns:repeat(2,1fr)}
  .bl-summary{grid-template-columns:repeat(2,1fr)}
  .output-wrap{flex-direction:column}
  .copy-btn{padding:11px;width:100%}
}
</style>
</head>
<body>
<div class="bg-grid"></div>
<div class="bg-orbs"><span></span><span></span><span></span><span></span></div>
<div id="session-banner" class="session-banner">Session expires in <b id="session-countdown">60:00</b></div>

<div class="app">
  <header class="topbar">
    <div class="brand" onclick="showPage('home')">
      <svg viewBox="0 0 64 64" aria-hidden="true">
        <defs><linearGradient id="lg" x1="0" x2="1" y1="0" y2="1">
          <stop stop-color="#00e5ff"/><stop offset=".5" stop-color="#b8ff2b"/><stop offset="1" stop-color="#ff2d95"/>
        </linearGradient></defs>
        <path d="M32 5 55 18v28L32 59 9 46V18z" fill="none" stroke="url(#lg)" stroke-width="3.5" stroke-linejoin="round"/>
        <text x="32" y="40" text-anchor="middle" font-family="Space Grotesk,sans-serif" font-size="19" font-weight="700" fill="url(#lg)">{U}</text>
      </svg>
      <div><b>Email journeys</b><span>NEON NEXUS · V5</span></div>
    </div>
    <nav class="nav">
      <button id="nav-home" onclick="showPage('home')">Home</button>
      <button id="nav-converter" onclick="showPage('converter')">Converter</button>
      <button id="nav-generator" onclick="showPage('generator')">Generators</button>
      <button id="nav-blocklist" onclick="showPage('blocklist')">Blocklist</button>
      <button id="nav-hunter" onclick="showPage('hunter')">Email Hunter</button>
      <button class="icon-btn" id="theme-btn" onclick="toggleTheme()" title="Toggle theme">☀</button>
      <button class="logout" onclick="logoutUser()">Logout</button>
    </nav>
  </header>

  <!-- ================= HOME ================= -->
  <section id="home" class="page active">
    <div class="home-wrap">
      <div class="hero-left">
        <span class="status-chip"><span class="dot"></span>SYSTEM ONLINE · V5</span>
        <h1 class="hero-title">
          <span class="line-1">The email ops</span>
          <span class="line-2">command center.</span>
        </h1>
        <p class="hero-desc">
          One toolkit for everyone who ships email. Encode subject lines, forge identities,
          audit sending IPs, and hunt down publicly available addresses — all from a single
          neon-lit workspace. Built for people who care about <code>deliverability</code>,
          <code>reputation</code>, and <code>speed</code>.
        </p>
        <div class="hero-actions">
          <button class="primary" onclick="showPage('converter');setMode('encode')">Launch Converter</button>
          <button class="secondary" onclick="showPage('hunter')">Run Email Hunter</button>
        </div>
      </div>
      <div class="hero-right">
        <div class="terminal">
          <div class="term-bar">
            <span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
            <b>~ email-journeys --live</b>
          </div>
          <div class="term-body">
            <div class="term-line"><span class="term-prompt">$</span><span class="term-out">email-toolkit init --nexus</span></div>
            <div class="term-line"><span class="term-prompt">→</span><span class="term-out cyan">encoder</span><span class="term-out">q1 · q2 · q3 · b64 ready</span></div>
            <div class="term-line"><span class="term-prompt">→</span><span class="term-out lime">generators</span><span class="term-out">strings · words · names</span></div>
            <div class="term-line"><span class="term-prompt">→</span><span class="term-out magenta">blocklist</span><span class="term-out">zen · barracuda · dbl</span></div>
            <div class="term-line"><span class="term-prompt">→</span><span class="term-out cyan">hunter</span><span class="term-out">deep crawl · extract · dedupe</span></div>
            <div class="term-line"><span class="term-prompt">$</span><span class="term-out">status</span></div>
            <div class="term-line"><span class="term-prompt">✓</span><span class="term-out lime">all systems operational</span><span class="term-cursor"></span></div>
          </div>
        </div>
      </div>
    </div>

    <div class="quick-stats">
      <div class="qs-card"><span class="qs-num">3</span><span class="qs-lbl">Q Encoders</span></div>
      <div class="qs-card"><span class="qs-num">4</span><span class="qs-lbl">DNSBL Zones</span></div>
      <div class="qs-card"><span class="qs-num">120s</span><span class="qs-lbl">Hunt Window</span></div>
      <div class="qs-card"><span class="qs-num">60m</span><span class="qs-lbl">Session</span></div>
    </div>

    <div class="feature-grid">
      <div class="feat f-cyan" onclick="showPage('converter');setMode('encode')">
        <div class="feat-glow"></div>
        <div class="feat-inner">
          <span class="feat-tag">01 / ENCODE</span>
          <h3>UTF-8 Q & Base64 Converter</h3>
          <p>Three Q-encoding methods plus standard and underscore Base64. Every output is one click away from your clipboard.</p>
          <span class="feat-btn">Open converter <span class="arrow">→</span></span>
        </div>
      </div>
      <div class="feat f-magenta" onclick="showPage('converter');setMode('decode')">
        <div class="feat-glow"></div>
        <div class="feat-inner">
          <span class="feat-tag">02 / DECODE</span>
          <h3>Format-Aware Decoder</h3>
          <p>Paste any Q or Base64 encoded-word. Format is detected automatically, invisible characters are stripped, output is clean.</p>
          <span class="feat-btn">Open decoder <span class="arrow">→</span></span>
        </div>
      </div>
      <div class="feat f-lime" onclick="showPage('generator')">
        <div class="feat-glow"></div>
        <div class="feat-inner">
          <span class="feat-tag">03 / GENERATE</span>
          <h3>Random Generators</h3>
          <p>Cryptographically secure strings, pronounceable words, and brandable sender names — all in one panel.</p>
          <span class="feat-btn">Open generators <span class="arrow">→</span></span>
        </div>
      </div>
      <div class="feat f-violet" onclick="showPage('blocklist')">
        <div class="feat-glow"></div>
        <div class="feat-inner">
          <span class="feat-tag">04 / AUDIT</span>
          <h3>Bulk Blocklist Check</h3>
          <p>Query up to 1,024 IPv4s against Spamhaus ZEN and Barracuda. Resolve RDNS. Test DBL. Export the whole table as CSV.</p>
          <span class="feat-btn">Open blocklist <span class="arrow">→</span></span>
        </div>
      </div>
      <div class="feat f-cyan wide" onclick="showPage('hunter')">
        <div class="feat-glow"></div>
        <div class="feat-inner">
          <span class="feat-tag">05 / HUNT · DEEP CRAWL</span>
          <h3>Email Hunter — Deep Recursive Crawler</h3>
          <p>Enter any website URL. The hunter follows every link — including hidden dropdown submenus, navigation trees, footer links, data attributes, JSON-LD structured data, and inline JavaScript routing. Auto-guesses common paths like <code>/kontakt</code>, <code>/impressum</code>, <code>/pfarreien</code>. Extracts plain, <code>mailto:</code>, and obfuscated emails. Deduplicates. Public content only.</p>
          <span class="feat-btn">Open Email Hunter <span class="arrow">→</span></span>
        </div>
      </div>
    </div>
  </section>

  <!-- ================= CONVERTER ================= -->
  <section id="converter" class="page">
    <div class="section-head">
      <div><h2>UTF-8 &amp; Base64 <span class="accent">Converter</span></h2><p>Switch between Encode and Decode. Format detection on decode is automatic.</p></div>
    </div>
    <div class="tabs">
      <button id="encode-tab" class="tab active" onclick="setMode('encode')">Encode</button>
      <button id="decode-tab" class="tab" onclick="setMode('decode')">Decode</button>
    </div>

    <div id="encode-panel">
      <div class="workspace">
        <div class="card">
          <h3>Input</h3>
          <label class="label" for="enc-input">Plain text</label>
          <textarea id="enc-input" placeholder="Type or paste the text you want to encode…"></textarea>
          <div class="actions">
            <button class="primary" onclick="encodeText()">Convert</button>
            <button class="secondary" onclick="clearBox('enc-input')">Clear</button>
          </div>
        </div>
        <div class="card">
          <h3>UTF-8 Q Outputs</h3>
          <div class="result"><label class="label">Q Method 1</label>
            <div class="output-wrap"><div id="q1" class="output"></div><button class="copy-btn" onclick="copyText('q1',this)">Copy</button></div></div>
          <div class="result"><label class="label">Q Method 2</label>
            <div class="output-wrap"><div id="q2" class="output"></div><button class="copy-btn" onclick="copyText('q2',this)">Copy</button></div></div>
          <div class="result"><label class="label">Q Method 3</label>
            <div class="output-wrap"><div id="q3" class="output"></div><button class="copy-btn" onclick="copyText('q3',this)">Copy</button></div></div>
        </div>
      </div>
      <div class="card" style="margin-top:18px">
        <h3>Base64 Outputs</h3>
        <div class="workspace">
          <div><label class="label">Standard Base64</label>
            <div class="output-wrap"><div id="b64" class="output"></div><button class="copy-btn" onclick="copyText('b64',this)">Copy</button></div></div>
          <div><label class="label">Underscore Base64</label>
            <div class="output-wrap"><div id="b64u" class="output"></div><button class="copy-btn" onclick="copyText('b64u',this)">Copy</button></div></div>
        </div>
      </div>
    </div>

    <div id="decode-panel" class="hidden">
      <div class="notice">Paste any UTF-8 Q or Base64 encoded-word. The format is detected automatically and invisible characters are removed from the result.</div>
      <div class="card">
        <h3>Decode</h3>
        <label class="label" for="dec-input">Encoded input</label>
        <textarea id="dec-input" placeholder="=?UTF-8?Q?Hello_World?="></textarea>
        <div class="actions">
          <button class="primary" onclick="decodeText()">Decode</button>
          <button class="secondary" onclick="clearDecode()">Clear</button>
        </div>
        <div class="result"><label class="label">Detected format</label><div id="detected" class="output" style="min-height:56px"></div></div>
        <div class="result"><label class="label">Output</label>
          <div class="output-wrap"><div id="dec-output" class="output" style="min-height:110px"></div><button class="copy-btn" onclick="copyText('dec-output',this)">Copy</button></div></div>
      </div>
    </div>
  </section>

  <!-- ================= GENERATORS ================= -->
  <section id="generator" class="page">
    <div class="section-head">
      <div><h2>Random <span class="accent">Generators</span></h2><p>Cryptographically strong strings, pronounceable random words, and brandable names.</p></div>
    </div>
    <div class="tabs">
      <button id="gen-string-tab" class="tab active" onclick="genTab('string')">String Generator</button>
      <button id="gen-word-tab" class="tab" onclick="genTab('word')">Random Words</button>
      <button id="gen-name-tab" class="tab" onclick="genTab('name')">Name Generator</button>
    </div>

    <div id="gen-string" class="card gen-panel">
      <h3>Random String Generator</h3>
      <p class="helper">Uppercase, lowercase and digits — generated with a cryptographically secure RNG.</p>
      <div class="controls3">
        <div><label class="label" for="stringMin">Min length</label><input id="stringMin" type="number" value="10" min="1" max="10000"></div>
        <div><label class="label" for="stringMax">Max length</label><input id="stringMax" type="number" value="20" min="1" max="10000"></div>
        <div><label class="label" for="stringCount">Results</label><input id="stringCount" type="number" value="10" min="1" max="100"></div>
      </div>
      <div class="actions">
        <button class="primary" onclick="generateStrings()">Generate</button>
        <button class="secondary" onclick="copyArea('stringOut',this)">Copy All</button>
        <button class="secondary" onclick="clearArea('stringOut')">Clear</button>
      </div>
      <label class="label" for="stringOut">Output</label>
      <textarea id="stringOut" readonly placeholder="Results appear here…"></textarea>
      <div id="stringStatus" class="status"></div>
    </div>

    <div id="gen-word" class="card gen-panel hidden">
      <h3>Random Words Generator</h3>
      <p class="helper">Natural-looking words built from alternating consonants and vowels.</p>
      <div class="controls3">
        <div><label class="label" for="wordMin">Min length</label><input id="wordMin" type="number" value="8" min="1" max="10000"></div>
        <div><label class="label" for="wordMax">Max length</label><input id="wordMax" type="number" value="20" min="1" max="10000"></div>
        <div><label class="label" for="wordCount">Results</label><input id="wordCount" type="number" value="10" min="1" max="1000"></div>
      </div>
      <div class="actions">
        <button class="primary" onclick="generateWords()">Generate</button>
        <button class="secondary" onclick="copyArea('wordOut',this)">Copy All</button>
        <button class="secondary" onclick="clearArea('wordOut')">Clear</button>
      </div>
      <label class="label" for="wordOut">Output</label>
      <textarea id="wordOut" readonly placeholder="Results appear here…"></textarea>
      <div id="wordStatus" class="status"></div>
    </div>

    <div id="gen-name" class="card gen-panel hidden">
      <h3>Name Generator</h3>
      <p class="helper">Each result joins 2 or 3 parts with <code>-</code>, <code>.</code> or <code>_</code>.</p>
      <div class="controls3">
        <div><label class="label" for="nameCount">Results</label><input id="nameCount" type="number" value="10" min="1" max="1000"></div>
      </div>
      <div class="actions">
        <button class="primary" onclick="generateNames()">Generate</button>
        <button class="secondary" onclick="copyArea('nameOut',this)">Copy All</button>
        <button class="secondary" onclick="clearArea('nameOut')">Clear</button>
      </div>
      <label class="label" for="nameOut">Output</label>
      <textarea id="nameOut" readonly placeholder="Results appear here…"></textarea>
      <div id="nameStatus" class="status"></div>
    </div>
  </section>

  <!-- ================= BLOCKLIST ================= -->
  <section id="blocklist" class="page">
    <div class="section-head">
      <div>
        <h2>Bulk <span class="accent">Blocklist Check</span></h2>
        <p>Check an IPv4 range against Spamhaus ZEN (CSS / PBL / SBL / XBL) and Barracuda, then resolve RDNS and test its registered domain against Spamhaus DBL. LISTED means a recognized listing response was found — otherwise the result is N/A.</p>
      </div>
    </div>

    <div class="card">
      <div class="bl-form">
        <div class="bl-field">
          <label for="bl-first-ip">First IP address</label>
          <input id="bl-first-ip" type="text" placeholder="66.78.52.2" autocomplete="off" spellcheck="false">
        </div>
        <div class="bl-field">
          <label for="bl-last-ip">Last IP address</label>
          <input id="bl-last-ip" type="text" placeholder="66.78.52.254" autocomplete="off" spellcheck="false">
        </div>
        <button class="primary" id="bl-check-btn" onclick="checkBlocklist()">Check Range</button>
        <button class="secondary" id="bl-cancel-btn" onclick="cancelBlocklist()" disabled>Cancel</button>
      </div>
      <div id="bl-status" class="bl-status">Maximum 1,024 IP addresses per check.</div>
      <div id="bl-health" class="bl-health"></div>
      <div class="bl-progress hidden" id="bl-progress"><div class="bl-progress-bar" id="bl-progress-bar"></div></div>
      <div class="actions" id="bl-export-wrap" style="display:none">
        <button class="secondary" onclick="exportBlocklistCsv()">Export CSV</button>
      </div>
    </div>

    <div id="bl-summary" class="bl-summary hidden"></div>

    <div id="bl-results" class="bl-table-wrap hidden">
      <table class="bl-table">
        <thead><tr><th>IP</th><th>CSS</th><th>PBL</th><th>SBL</th><th>Barracuda</th><th>RDNS</th><th>DBL</th></tr></thead>
        <tbody id="bl-tbody"></tbody>
      </table>
    </div>
  </section>

  <!-- ================= EMAIL HUNTER ================= -->
  <section id="hunter" class="page">
    <div class="section-head">
      <div>
        <h2>Email <span class="accent">Hunter</span></h2>
        <p>Enter a website URL. We'll crawl its public internal pages for up to 2 minutes — including hidden dropdown submenus, navigation trees, footer links, JSON-LD structured data, and inline JavaScript routing. Extracts every publicly available email (including obfuscated ones), removes duplicates, and shows the results.</p>
      </div>
    </div>

    <div class="card">
      <label class="label" for="hunter-url">Website URL</label>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <input id="hunter-url" type="text" placeholder="https://example.com" autocomplete="off" spellcheck="false" style="flex:1;min-width:240px">
        <button class="primary" id="hunter-btn" onclick="startEmailHunter()">Start Crawl</button>
        <button class="secondary" id="hunter-cancel" onclick="cancelEmailHunter()" disabled>Cancel</button>
      </div>
      <div id="hunter-status" class="status" style="margin-top:14px"></div>
      <div class="bl-progress hidden" id="hunter-progress" style="margin-top:6px">
        <div class="bl-progress-bar" id="hunter-progress-bar" style="width:8%"></div>
      </div>
    </div>

    <div id="hunter-stats" class="bl-summary hidden" style="margin-top:20px"></div>

    <div class="card" id="hunter-emails-card" style="margin-top:20px;display:none">
      <h3>Emails Found (<span id="hunter-count">0</span>)</h3>
      <div class="actions" style="margin-top:0;margin-bottom:12px">
        <button class="secondary" onclick="copyHunterEmails(this)">Copy All</button>
        <button class="secondary" onclick="exportHunterCsv()">Export CSV</button>
      </div>
      <div id="hunter-emails" class="output" style="min-height:80px;max-height:520px;overflow:auto"></div>
    </div>
  </section>

  <div class="footer">Email journeys · <span class="grad">Neon Nexus</span> · Embedded logo, favicon and BIMI endpoint · <span id="year"></span></div>
</div>

<div id="toasts" class="toasts"></div>

<script>
const $ = (id) => document.getElementById(id);
const PAGES = ['home', 'converter', 'generator', 'blocklist', 'hunter'];
const state = { blAbort: null, blData: null };

const SESSION_MAX_AGE_MS = 60 * 60 * 1000;
const SESSION_START_KEY = 'ej_session_start';
const SESSION_BANNER_DELAY_MS = 55 * 60 * 1000;

function sessionStart() {
  let t = parseInt(sessionStorage.getItem(SESSION_START_KEY) || '0', 10);
  if (!t || Date.now() - t > SESSION_MAX_AGE_MS) {
    t = Date.now();
    sessionStorage.setItem(SESSION_START_KEY, String(t));
  }
  return t;
}

function checkSession() {
  const elapsed = Date.now() - sessionStart();
  if (elapsed >= SESSION_MAX_AGE_MS) {
    sessionStorage.removeItem(SESSION_START_KEY);
    window.location.href = '/login?expired=1';
    return false;
  }
  return true;
}

function updateSessionBanner() {
  const banner = $('session-banner');
  const label = $('session-countdown');
  const elapsed = Date.now() - sessionStart();
  const remaining = Math.max(0, SESSION_MAX_AGE_MS - elapsed);
  if (remaining <= SESSION_MAX_AGE_MS - SESSION_BANNER_DELAY_MS && remaining > 0) {
    const m = String(Math.floor(remaining / 60000)).padStart(2, '0');
    const s = String(Math.floor((remaining % 60000) / 1000)).padStart(2, '0');
    label.textContent = m + ':' + s;
    banner.classList.add('show');
  } else {
    banner.classList.remove('show');
  }
}

sessionStart();
setInterval(function () {
  if (!checkSession()) return;
  updateSessionBanner();
}, 1000);

function showPage(name) {
  if (!checkSession()) return;
  PAGES.forEach((p) => $(p).classList.toggle('active', p === name));
  document.querySelectorAll('.nav button[id^="nav-"]').forEach((b) => b.classList.remove('active'));
  const btn = $('nav-' + name);
  if (btn) btn.classList.add('active');
  window.scrollTo({ top: 0, behavior: 'smooth' });
  if (name === 'blocklist') refreshHealth();
}

function setMode(mode) {
  showPage('converter');
  $('encode-panel').classList.toggle('hidden', mode !== 'encode');
  $('decode-panel').classList.toggle('hidden', mode !== 'decode');
  $('encode-tab').classList.toggle('active', mode === 'encode');
  $('decode-tab').classList.toggle('active', mode === 'decode');
}

function genTab(mode) {
  ['string', 'word', 'name'].forEach((x) => {
    $('gen-' + x).classList.toggle('hidden', x !== mode);
    $('gen-' + x + '-tab').classList.toggle('active', x === mode);
  });
}

function toggleTheme() {
  const light = document.body.classList.toggle('light');
  localStorage.setItem('theme', light ? 'light' : 'dark');
  $('theme-btn').textContent = light ? '☾' : '☀';
}
(function initTheme() {
  const saved = localStorage.getItem('theme');
  const light = saved === 'light';
  document.body.classList.toggle('light', light);
  $('theme-btn').textContent = light ? '☾' : '☀';
})();

function logoutUser() {
  sessionStorage.removeItem(SESSION_START_KEY);
  window.location.href = '/logout';
}

function toast(message, kind) {
  const el = document.createElement('div');
  el.className = 'toast ' + (kind || '');
  el.textContent = message;
  $('toasts').appendChild(el);
  setTimeout(() => {
    el.style.transition = 'opacity .25s, transform .25s';
    el.style.opacity = '0';
    el.style.transform = 'translateY(10px)';
    setTimeout(() => el.remove(), 260);
  }, 2600);
}

function legacyCopy(value) {
  const ta = document.createElement('textarea');
  ta.value = value;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.top = '-1000px';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  ta.setSelectionRange(0, value.length);
  document.execCommand('copy');
  document.body.removeChild(ta);
}

async function writeClipboard(value) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(value);
    return;
  }
  legacyCopy(value);
}

async function copyValue(value, btn) {
  if (!value) { toast('Nothing to copy', 'err'); return; }
  try {
    await writeClipboard(value);
    if (btn) {
      const old = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(() => { btn.textContent = old; }, 1000);
    }
    toast('Copied to clipboard', 'ok');
  } catch (e) {
    toast('Clipboard access failed', 'err');
  }
}

function copyText(id, btn) { copyValue($(id).textContent, btn); }
function copyArea(id, btn) { copyValue($(id).value, btn); }
function clearBox(id) { $(id).value = ''; }
function clearArea(id) { $(id).value = ''; }
function clearDecode() {
  $('dec-input').value = '';
  $('dec-output').textContent = '';
  $('detected').textContent = '';
}

async function api(url, opts) {
  const res = await fetch(url, opts);
  if (res.status === 401) {
    sessionStorage.removeItem(SESSION_START_KEY);
    window.location.href = '/login?expired=1';
    throw new Error('Session expired');
  }
  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch (e) {
    throw new Error('Server returned non-JSON (HTTP ' + res.status + ')');
  }
  if (!res.ok) throw new Error(data.error || ('Request failed (HTTP ' + res.status + ')'));
  return data;
}

async function encodeText() {
  const text = $('enc-input').value;
  if (!text) {
    ['q1', 'q2', 'q3', 'b64', 'b64u'].forEach((x) => { $(x).textContent = ''; });
    return;
  }
  try {
    const d = await api('/api/encode', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' },
      body: JSON.stringify({ text: text, _nonce: (crypto.randomUUID ? crypto.randomUUID() : String(Date.now())) })
    });
    $('q1').textContent = d.q1;
    $('q2').textContent = d.q2;
    $('q3').textContent = d.q3;
    $('b64').textContent = d.base64;
    $('b64u').textContent = d.base64_underscore;
  } catch (e) { toast(e.message, 'err'); }
}

async function decodeText() {
  const value = $('dec-input').value.trim();
  if (!value) { toast('Enter encoded text first', 'err'); return; }
  try {
    const d = await api('/api/decode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: value })
    });
    $('detected').textContent = d.detected;
    $('dec-output').textContent = d.output;
  } catch (e) {
    $('detected').textContent = '';
    $('dec-output').textContent = 'Error: ' + e.message;
    toast(e.message, 'err');
  }
}

function readRange(a, b) {
  let x = Math.max(1, Math.min(parseInt($(a).value, 10) || 1, 10000));
  let y = Math.max(1, Math.min(parseInt($(b).value, 10) || 20, 10000));
  return x > y ? [y, x] : [x, y];
}

async function generateStrings() {
  const range = readRange('stringMin', 'stringMax');
  const count = Math.max(1, Math.min(parseInt($('stringCount').value, 10) || 10, 100));
  try {
    const d = await api('/api/random/data', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind: 'string', min: range[0], max: range[1], count: count })
    });
    $('stringOut').value = d.results.join('\n');
    $('stringStatus').textContent = d.results.length + ' strings generated';
  } catch (e) { $('stringStatus').textContent = e.message; toast(e.message, 'err'); }
}

async function generateWords() {
  const range = readRange('wordMin', 'wordMax');
  const count = Math.max(1, Math.min(parseInt($('wordCount').value, 10) || 10, 1000));
  try {
    const d = await api('/api/random/data', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind: 'words', min: range[0], max: range[1], count: count })
    });
    $('wordOut').value = d.results.join('\n');
    $('wordStatus').textContent = d.results.length + ' random words generated';
  } catch (e) { $('wordStatus').textContent = e.message; toast(e.message, 'err'); }
}

async function generateNames() {
  const count = Math.max(1, Math.min(parseInt($('nameCount').value, 10) || 10, 1000));
  try {
    const d = await api('/api/random/names', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ count: count })
    });
    $('nameOut').value = d.results.join('\n');
    $('nameStatus').textContent = d.results.length + ' names generated';
  } catch (e) { $('nameStatus').textContent = e.message; toast(e.message, 'err'); }
}

function esc(v) {
  return String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

function pill(v) {
  const s = String(v || 'N/A').toUpperCase();
  if (s === 'LISTED') return '<span class="bl-status-pill bl-listed">LISTED</span>';
  if (s === 'OK') return '<span class="bl-status-pill bl-ok">OK</span>';
  if (s === 'ERROR') return '<span class="bl-status-pill bl-error">ERROR</span>';
  return '<span class="bl-status-pill bl-na">N/A</span>';
}

async function refreshHealth() {
  try {
    const d = await api('/api/blocklist/health', { method: 'GET' });
    const color = d.spamhaus_ok ? 'var(--ok)' : 'var(--danger)';
    $('bl-health').innerHTML =
      'Resolver: <b>' + esc((d.nameservers || []).join(', ') || 'system') + '</b>' +
      ' · Backend: <b>' + esc(d.dns_backend) + '</b>' +
      ' · DQS: <b>' + (d.dqs ? 'ON' : 'OFF') + '</b>' +
      ' · <span style="color:' + color + '">Spamhaus: <b>' + (d.spamhaus_ok ? 'OK' : 'BLOCKED') + '</b></span>' +
      (d.spamhaus_note ? ' — ' + esc(d.spamhaus_note) : '');
  } catch (e) {
    $('bl-health').textContent = 'Health check failed: ' + e.message;
  }
}

function renderSummary(t) {
  const items = [
    ['Total', t.total], ['CSS', t.css], ['PBL', t.pbl], ['SBL', t.sbl],
    ['Barracuda', t.barracuda], ['RDNS', t.rdns], ['DBL', t.dbl]
  ];
  $('bl-summary').innerHTML = items.map(function (x) {
    return '<div class="bl-summary-item"><b>' + esc(x[1]) + '</b><span>' + esc(x[0]) + '</span></div>';
  }).join('');
  $('bl-summary').classList.remove('hidden');
}

function renderResults(rows, totals) {
  const body = rows.map(function (r) {
    const domain = (r.dbl_domain && r.dbl_domain !== '-')
      ? '<span class="bl-dbl-domain">' + esc(r.dbl_domain) + '</span>' : '';
    const rdns = (r.rdns === '-')
      ? '<span class="bl-status-pill bl-na">No PTR</span>' : esc(r.rdns);
    return '<tr>' +
      '<td class="ip-cell">' + esc(r.ip) + '</td>' +
      '<td>' + pill(r.css) + '</td>' +
      '<td>' + pill(r.pbl) + '</td>' +
      '<td>' + pill(r.sbl) + '</td>' +
      '<td>' + pill(r.barracuda) + '</td>' +
      '<td class="rdns-cell">' + rdns + '</td>' +
      '<td>' + pill(r.dbl) + domain + '</td>' +
      '</tr>';
  }).join('');

  const totalRow = '<tr class="bl-total">' +
    '<td class="ip-cell">Total</td>' +
    '<td>' + esc(totals.css) + '</td>' +
    '<td>' + esc(totals.pbl) + '</td>' +
    '<td>' + esc(totals.sbl) + '</td>' +
    '<td>' + esc(totals.barracuda) + '</td>' +
    '<td>' + esc(totals.rdns) + '</td>' +
    '<td>' + esc(totals.dbl) + '</td>' +
    '</tr>';

  $('bl-tbody').innerHTML = body + totalRow;
  $('bl-results').classList.remove('hidden');
}

async function checkBlocklist() {
  const first = $('bl-first-ip').value.trim();
  const last = $('bl-last-ip').value.trim();
  const btn = $('bl-check-btn');
  const cancelBtn = $('bl-cancel-btn');
  const status = $('bl-status');
  const progress = $('bl-progress');
  const bar = $('bl-progress-bar');

  if (!first || !last) {
    status.textContent = 'Enter both the First IP address and the Last IP address.';
    toast('Both IP fields are required', 'err');
    return;
  }

  state.blAbort = new AbortController();
  const startedAt = Date.now();
  const tick = setInterval(function () {
    status.textContent = 'Checking ' + first + ' → ' + last + '… ' +
      ((Date.now() - startedAt) / 1000).toFixed(0) + 's';
  }, 1000);

  btn.disabled = true;
  btn.textContent = 'Checking…';
  cancelBtn.disabled = false;
  status.textContent = 'Checking ' + first + ' → ' + last + '…';
  progress.classList.remove('hidden');
  bar.style.width = '8%';
  $('bl-results').classList.add('hidden');
  $('bl-summary').classList.add('hidden');
  $('bl-export-wrap').style.display = 'none';
  state.blData = null;

  try {
    const d = await api('/api/blocklist/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ first_ip: first, last_ip: last }),
      signal: state.blAbort.signal
    });
    bar.style.width = '100%';
    state.blData = d;
    renderSummary(d.totals);
    renderResults(d.results, d.totals);
    $('bl-export-wrap').style.display = 'flex';

    let msg = 'Completed ' + d.results.length + ' IP checks in ' + d.elapsed + 's.';
    if (d.errors) msg += ' ' + d.errors + ' row(s) returned a provider error.';
    if (d.warning) msg += ' ' + d.warning;
    status.textContent = msg;
  } catch (e) {
    if (e && e.name === 'AbortError') {
      status.textContent = 'Check cancelled.';
    } else {
      status.textContent = e.message || 'Blocklist check failed.';
      toast(e.message || 'Blocklist check failed.', 'err');
    }
    $('bl-results').classList.add('hidden');
    $('bl-summary').classList.add('hidden');
    $('bl-export-wrap').style.display = 'none';
  } finally {
    clearInterval(tick);
    state.blAbort = null;
    btn.disabled = false;
    btn.textContent = 'Check Range';
    cancelBtn.disabled = true;
    setTimeout(function () { progress.classList.add('hidden'); bar.style.width = '0%'; }, 700);
  }
}

function cancelBlocklist() { if (state.blAbort) state.blAbort.abort(); }

function exportBlocklistCsv() {
  if (!state.blData || !state.blData.results) { toast('Nothing to export', 'err'); return; }
  const header = ['IP', 'CSS', 'PBL', 'SBL', 'Barracuda', 'RDNS', 'DBL_Domain', 'DBL'];
  const lines = [header.join(',')];
  state.blData.results.forEach(function (r) {
    lines.push([
      r.ip, r.css, r.pbl, r.sbl, r.barracuda, r.rdns,
      (r.dbl_domain || '-'), r.dbl
    ].map(function (v) {
      const s = String(v === null || v === undefined ? '' : v);
      return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    }).join(','));
  });
  const blob = new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'blocklist-check.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  toast('CSV exported', 'ok');
}

const hunterState = { abort: null, sid: null, pollTimer: null, data: null };

async function startEmailHunter() {
  const url = $('hunter-url').value.trim();
  if (!url) { toast('Please enter a URL', 'err'); return; }

  const btn = $('hunter-btn');
  const cancelBtn = $('hunter-cancel');
  const status = $('hunter-status');
  const progress = $('hunter-progress');
  const bar = $('hunter-progress-bar');

  hunterState.abort = new AbortController();
  hunterState.data = null;
  btn.disabled = true;
  btn.textContent = 'Crawling…';
  cancelBtn.disabled = false;
  progress.classList.remove('hidden');
  bar.style.width = '8%';
  $('hunter-stats').classList.add('hidden');
  $('hunter-emails-card').style.display = 'none';

  const startedAt = Date.now();
  const tick = setInterval(function () {
    const s = ((Date.now() - startedAt) / 1000).toFixed(0);
    status.textContent = 'Crawling ' + url + '… ' + s + 's (max 120s)';
    const pct = Math.min(95, 8 + (s / 120) * 87);
    bar.style.width = pct.toFixed(1) + '%';
  }, 1000);
  status.textContent = 'Starting crawl…';

  try {
    const d = await api('/api/email-hunter/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url }),
      signal: hunterState.abort.signal
    });
    hunterState.sid = d.session_id;
    clearInterval(tick);
    pollHunterResults(startedAt, tick);
  } catch (e) {
    clearInterval(tick);
    finishHunterUi();
    if (e.name === 'AbortError') { status.textContent = 'Cancelled.'; }
    else { status.textContent = e.message; toast(e.message, 'err'); }
  }
}

function pollHunterResults(startedAt, tick) {
  const status = $('hunter-status');
  hunterState.pollTimer = setInterval(async function () {
    if (!hunterState.sid) return;
    try {
      const d = await api('/api/email-hunter/results/' + hunterState.sid, { method: 'GET' });
      if (d.status === 'running') return;
      clearInterval(tick);
      clearInterval(hunterState.pollTimer);
      hunterState.pollTimer = null;

      if (d.error) {
        status.textContent = 'Error: ' + d.error;
        toast(d.error, 'err');
        finishHunterUi();
        return;
      }
      hunterState.data = d;
      displayHunterResults(d);
      finishHunterUi();
      $('hunter-progress-bar').style.width = '100%';
      setTimeout(function () { $('hunter-progress').classList.add('hidden'); }, 600);
    } catch (e) {
      clearInterval(tick);
      clearInterval(hunterState.pollTimer);
      hunterState.pollTimer = null;
      status.textContent = e.message;
      finishHunterUi();
    }
  }, 1500);
}

function displayHunterResults(d) {
  const s = d.stats || {};
  const stats = $('hunter-stats');
  const items = [
    ['Emails',        s.emails || 0],
    ['Pages',         s.pages_visited || 0],
    ['Contact Pages', s.contact_pages || 0],
    ['Discovered',    s.discovered || 0],
    ['Visited',       s.visited || 0],
    ['Errors',        s.errors || 0],
    ['Time (s)',      s.time_taken || 0],
  ];
  stats.innerHTML = items.map(function (x) {
    return '<div class="bl-summary-item"><b>' + esc(x[1]) + '</b><span>' + esc(x[0]) + '</span></div>';
  }).join('');
  stats.classList.remove('hidden');

  const emails = d.emails || [];
  $('hunter-count').textContent = emails.length;
  $('hunter-emails').textContent = emails.length ? emails.join('\n') : 'No emails found.';
  $('hunter-emails-card').style.display = 'block';

  $('hunter-status').textContent = 'Done — found ' + emails.length + ' unique email' +
    (emails.length === 1 ? '' : 's') + ' in ' + (s.time_taken || 0) + 's.';
}

function finishHunterUi() {
  const btn = $('hunter-btn');
  btn.disabled = false;
  btn.textContent = 'Start Crawl';
  $('hunter-cancel').disabled = true;
  hunterState.abort = null;
}

function cancelEmailHunter() {
  if (hunterState.pollTimer) { clearInterval(hunterState.pollTimer); hunterState.pollTimer = null; }
  if (hunterState.abort) hunterState.abort.abort();
  finishHunterUi();
  $('hunter-status').textContent = 'Cancelled.';
  setTimeout(function () { $('hunter-progress').classList.add('hidden'); }, 500);
}

async function copyHunterEmails(btn) {
  if (!hunterState.data || !hunterState.data.emails) { toast('Nothing to copy', 'err'); return; }
  await copyValue(hunterState.data.emails.join('\n'), btn);
}

function exportHunterCsv() {
  if (!hunterState.data || !hunterState.data.emails) { toast('Nothing to export', 'err'); return; }
  const lines = ['Email'].concat(hunterState.data.emails);
  const blob = new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'emails-despoil.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  toast('CSV exported', 'ok');
}

$('year').textContent = new Date().getFullYear();
showPage('home');

document.addEventListener('keydown', function (e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    const active = document.activeElement;
    if (active && active.id === 'enc-input') encodeText();
    if (active && active.id === 'dec-input') decodeText();
    if (active && active.id === 'hunter-url') startEmailHunter();
  }
});
</script>
</body>
</html>"""


# ============================================================
# Auth
# ============================================================
@app.before_request
def auth():
    public = {"login", "favicon", "favicon_ico", "bimi"}
    if request.endpoint in public:
        return
    if request.path in ("/favicon.svg", "/favicon.ico", "/bimi-logo.svg"):
        return

    if not session.get("logged_in"):
        if request.path.startswith("/api/"):
            return jsonify(success=False, error="Login required"), 401
        return redirect(url_for("login", next=request.path))

    login_time = session.get("login_time", 0)
    if time.time() - login_time > SESSION_MAX_AGE:
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify(success=False, error="Session expired"), 401
        return redirect(url_for("login", next=request.path, expired="1"))


LOGIN_HTML = '''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Sign in • Email journeys</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#07080f;color:#e9ecf8;font-family:'Space Grotesk',system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif;letter-spacing:-.01em;position:relative;overflow:hidden}
body::before,body::after{content:'';position:fixed;border-radius:50%;filter:blur(120px);opacity:.45;pointer-events:none}
body::before{width:520px;height:520px;background:radial-gradient(circle,#00e5ff,transparent 70%);top:-200px;left:-160px}
body::after{width:480px;height:480px;background:radial-gradient(circle,#ff2d95,transparent 70%);bottom:-200px;right:-160px}
.bg-grid{position:fixed;inset:0;pointer-events:none;z-index:0;background-image:linear-gradient(rgba(120,140,220,.07) 1px,transparent 1px),linear-gradient(90deg,rgba(120,140,220,.07) 1px,transparent 1px);background-size:44px 44px;mask-image:radial-gradient(ellipse 80% 60% at 50% 40%,#000 40%,transparent 100%);-webkit-mask-image:radial-gradient(ellipse 80% 60% at 50% 40%,#000 40%,transparent 100%)}
form{position:relative;z-index:2;width:min(400px,90vw);padding:38px;border:1px solid rgba(120,140,220,.18);border-radius:22px;background:rgba(18,22,38,.72);backdrop-filter:blur(22px);box-shadow:0 34px 80px rgba(0,0,0,.7)}
form::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;border-radius:22px 22px 0 0;background:linear-gradient(90deg,#00e5ff,#ff2d95,#b8ff2b)}
h2{margin:0 0 8px;font-size:24px;font-weight:700;letter-spacing:-.02em;background:linear-gradient(100deg,#00e5ff,#ff2d95);-webkit-background-clip:text;background-clip:text;color:transparent}
p{margin:6px 0;color:#8b9bc6;font-size:13.5px}
input,button{width:100%;padding:14px;margin-top:11px;border-radius:12px;border:1px solid rgba(120,140,220,.18);box-sizing:border-box;font:inherit;font-size:14.5px;font-family:inherit;letter-spacing:-.01em}
input{background:rgba(24,28,48,.6);color:#fff;outline:none;transition:.2s}
input:focus{border-color:#00e5ff;box-shadow:0 0 0 3px rgba(0,229,255,.18)}
button{background:linear-gradient(120deg,#00e5ff,#b8ff2b);color:#050612;font-weight:700;cursor:pointer;border:0;margin-top:20px;transition:.2s;box-shadow:0 10px 26px rgba(0,229,255,.35)}
button:hover{transform:translateY(-2px);box-shadow:0 16px 32px rgba(0,229,255,.5)}
.e{color:#ff5c8a;margin:10px 0 0;font-size:13px;font-weight:500}
.n{color:#ffc247;margin:10px 0 0;font-size:13px;font-weight:500}
</style></head><body><div class="bg-grid"></div><form method="post">
<h2>Email journeys</h2>
<p>Sign in to continue.</p>{{ERR}}{{NOTICE}}
<input name="username" placeholder="Username" required autofocus autocomplete="username">
<input name="password" type="password" placeholder="Password" required autocomplete="current-password">
<input type="hidden" name="next" value="{{NEXT}}">
<button type="submit">Login</button>
</form></body></html>'''


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        if secrets.compare_digest(u, LOGIN_USERNAME) and check_password_hash(LOGIN_PASSWORD_HASH, p):
            session.clear()
            session.permanent = True
            session["logged_in"] = True
            session["login_time"] = time.time()
            nxt = request.form.get("next", "") or ""
            return redirect(nxt if nxt.startswith("/") else "/")
        return login_page("Invalid username or password", request.form.get("next", "")), 401
    expired = request.args.get("expired", "")
    notice = "Your session expired. Please sign in again." if expired else ""
    return login_page("", request.args.get("next", ""), notice)


def login_page(error="", nxt="/", notice=""):
    err_html = '<p class="e">' + error + '</p>' if error else ""
    notice_html = '<p class="n">' + notice + '</p>' if notice else ""
    html = (LOGIN_HTML
            .replace("{{ERR}}", err_html)
            .replace("{{NOTICE}}", notice_html)
            .replace("{{NEXT}}", nxt or "/"))
    return Response(html, mimetype="text/html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    login_time = session.get("login_time", 0)
    if time.time() - login_time > SESSION_MAX_AGE:
        session.clear()
        return redirect(url_for("login", expired="1"))
    return Response(INDEX_HTML, mimetype="text/html")


# ============================================================
# SVG assets
# ============================================================
LOGO_SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#07080f"/><defs><linearGradient id="g" x1="0" x2="1" y1="0" y2="1"><stop stop-color="#00e5ff"/><stop offset=".5" stop-color="#b8ff2b"/><stop offset="1" stop-color="#ff2d95"/></linearGradient></defs><path d="M32 6 55 19v26L32 58 9 45V19z" fill="none" stroke="url(#g)" stroke-width="3.5" stroke-linejoin="round"/><text x="32" y="40" text-anchor="middle" font-family="Space Grotesk,sans-serif" font-size="19" font-weight="700" fill="url(#g)">{U}</text></svg>'
BIMI_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><title>Email journeys</title><rect width="100" height="100" fill="#07080f"/><defs><linearGradient id="g" x1="0" x2="1" y1="0" y2="1"><stop stop-color="#00e5ff"/><stop offset=".5" stop-color="#b8ff2b"/><stop offset="1" stop-color="#ff2d95"/></linearGradient></defs><path d="M50 10 86 31v38L50 90 14 69V31z" fill="none" stroke="url(#g)" stroke-width="4" stroke-linejoin="round"/><text x="50" y="60" text-anchor="middle" font-family="Space Grotesk,sans-serif" font-size="26" font-weight="700" fill="url(#g)">{U}</text></svg>'


@app.route("/favicon.svg")
def favicon():
    return Response(LOGO_SVG, mimetype="image/svg+xml")


@app.route("/favicon.ico")
def favicon_ico():
    return Response(LOGO_SVG, mimetype="image/svg+xml")


@app.route("/bimi-logo.svg")
def bimi():
    return Response(BIMI_SVG, mimetype="image/svg+xml")


# ============================================================
# Encode / Decode
# ============================================================
INVISIBLE = set("\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\u2065\u2066\u2067\u2068\u2069\u00ad\ufeff")

def clean_decoded(s):
    s = s.replace("\u00a0", " ").replace("\u2007", " ")
    return "".join(c for c in s if c not in INVISIBLE)

def q_byte(b):
    return "={:02X}".format(b)

def q1(text):
    parts = []
    for c in text:
        if c == " ":
            parts.append("_")
        else:
            parts.extend(q_byte(b) for b in c.encode("utf-8"))
    return "".join(parts)

def q2(text):
    parts = []
    for c in text:
        if c == " ":
            parts.append("_")
        elif c in "=?:_":
            parts.append(q_byte(ord(c)))
        elif c in string.ascii_letters:
            parts.append(q_byte(ord(c)) if random.random() < 0.50 else c)
        elif c in string.digits:
            parts.append(q_byte(ord(c)) if random.random() < 0.35 else c)
        elif ord(c) < 128 and 33 <= ord(c) <= 126:
            parts.append(q_byte(ord(c)))
        else:
            parts.extend(q_byte(b) for b in c.encode("utf-8"))
    return "".join(parts)

def _split_random_chunks(text, count):
    if count <= 1 or len(text) <= 1:
        return [text]
    count = min(count, len(text))
    cuts = sorted(random.sample(range(1, len(text)), count - 1))
    points = [0] + cuts + [len(text)]
    return [text[points[i]:points[i + 1]] for i in range(count)]

def _q3_utf8_word(text):
    payload = []
    for c in text:
        if c == " ":
            payload.append("=20" if random.random() < 0.25 else "_")
            continue
        for b in c.encode("utf-8"):
            ch = chr(b)
            if 33 <= b <= 126 and ch not in "=?_":
                if ch in string.ascii_letters:
                    payload.append(q_byte(b) if random.random() < 0.25 else ch)
                elif ch in string.digits:
                    payload.append(q_byte(b) if random.random() < 0.25 else ch)
                else:
                    payload.append(q_byte(b) if random.random() < 0.25 else ch)
            else:
                payload.append(q_byte(b))
    return "=?UTF-8?Q?" + "".join(payload) + "?="

def _b64_word(text):
    return "=?UTF-8?B?" + base64.b64encode(text.encode("utf-8")).decode("ascii") + "?="

def q3(text):
    if not text:
        return ""
    chunk_count = min(4, len(text)) if len(text) <= 24 else min(random.randint(4, 6), len(text))
    chunks = _split_random_chunks(text, chunk_count)
    return "".join(_q3_utf8_word(c) if i % 2 == 0 else _b64_word(c) for i, c in enumerate(chunks))

def custom_b64(text):
    raw = base64.b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")
    if not raw:
        return "=?UTF-8?B??="
    return "=?UTF-8?B?" + "_".join(raw) + "?="

def decode_q(value):
    value = value.strip().replace("\\", "")
    out = []
    for data, enc in decode_header(value):
        if isinstance(data, bytes):
            out.append(data.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(data)
    return clean_decoded("".join(out))

def decode_b64(value):
    value = value.strip().replace("\\", "")
    if value.startswith("=?") and value.endswith("?="):
        parts = value[2:-2].split("?")
        if len(parts) >= 3 and parts[1].upper() == "B":
            value = parts[2]
    if "=__" in value or value.endswith("__"):
        value = value.replace("=__", "").replace("_", "")
    value = value.replace(" ", "").replace("\n", "").replace("\r", "")
    value += "=" * ((4 - len(value) % 4) % 4)
    try:
        return clean_decoded(base64.b64decode(value, validate=False).decode("utf-8", errors="replace"))
    except Exception as e:
        raise ValueError("Invalid Base64 input") from e

@app.post("/api/encode")
def encode_api():
    t = (request.get_json(silent=True) or {}).get("text", "")
    response = jsonify(
        q1="=?UTF-8?Q?" + q1(t) + "?=",
        q2="=?UTF-8?Q?" + q2(t) + "?=",
        q3=q3(t),
        base64="=?UTF-8?B?" + base64.b64encode(t.encode()).decode() + "?=",
        base64_underscore=custom_b64(t),
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response

@app.post("/api/decode")
def decode_api():
    value = (request.get_json(silent=True) or {}).get("text", "").strip()
    if not value:
        return jsonify(error="Enter encoded text first"), 400
    try:
        v = value.replace("\\", "")
        upper = v.upper()
        if ("?Q?" in upper or upper.startswith("=?UTF-8?Q?")
                or upper.startswith("=?US-ASCII?Q?") or upper.startswith("=?ISO-8859-1?Q?")):
            return jsonify(output=decode_q(value), detected="UTF-8 Q")
        return jsonify(output=decode_b64(value), detected="Base64")
    except Exception as e:
        return jsonify(error=str(e)), 400


# ============================================================
# Random generators
# ============================================================
CONSONANTS = "bcdfghjklmnprstvwxyz"
VOWELS = "aeiou"
NAME_PREFIXES = ["nova","aeon","luma","vera","heli","ori","aqua","zeta","cyra","vire","kilo","pyra","luna","solar","terra","vent","vexa","aria","koda","zena","myra","orix","seva","tira"]
NAME_SUFFIXES = ["wave","flux","core","line","space","land","form","link","point","craft","field","scale","stone","vault","forge","path","node","port","gate","mark","flow","mesh","grid","byte"]

def _generate_word(min_len, max_len):
    n = random.randint(min_len, max_len)
    w = ""
    con = random.choice([True, False])
    while len(w) < n:
        w += random.choice(CONSONANTS if con else VOWELS)
        con = not con
    return w[:n]

@app.post("/api/random/data")
def random_data_api():
    data = request.get_json(silent=True) or {}
    kind = data.get("kind")
    count = max(1, min(int(data.get("count", 10)), 1000))
    min_len = max(1, min(int(data.get("min", 1)), 10000))
    max_len = max(1, min(int(data.get("max", 20)), 10000))
    min_len, max_len = sorted((min_len, max_len))
    if kind == "string":
        chars = string.ascii_letters + string.digits
        return jsonify(results=[
            "".join(secrets.choice(chars) for _ in range(random.randint(min_len, max_len)))
            for _ in range(count)
        ])
    if kind == "words":
        results, used, attempts = [], set(), 0
        while len(results) < count and attempts < count * 30:
            attempts += 1
            w = _generate_word(min_len, max_len).capitalize()
            if w not in used:
                used.add(w)
                results.append(w)
        return jsonify(results=results)
    return jsonify(error="Unknown generator"), 400

@app.route("/api/random/names", methods=["GET", "POST"])
def names_api():
    data = request.get_json(silent=True) or {}
    count = max(1, min(int(data.get("count", request.args.get("count", 10))), 100))
    results = []
    for _ in range(count):
        parts = []
        for _ in range(random.choice([2, 3])):
            style = random.choice(["pref", "suff", "word"])
            if style == "pref":
                parts.append(random.choice(NAME_PREFIXES))
            elif style == "suff":
                parts.append(random.choice(NAME_SUFFIXES))
            else:
                parts.append(_generate_word(4, 8).lower())
        results.append(random.choice(["-", ".", "_"]).join(parts))
    return jsonify(results=results)


# ============================================================
# Blocklist
# ============================================================
MAX_BLOCKLIST_IPS = int(os.environ.get("MAX_BLOCKLIST_IPS", "1024"))
BLOCKLIST_WORKERS = int(os.environ.get("BLOCKLIST_WORKERS", "24"))
DNS_TIMEOUT = float(os.environ.get("DNS_TIMEOUT", "3.0"))
DNS_LIFETIME = float(os.environ.get("DNS_LIFETIME", "5.0"))

DQS_KEY = os.environ.get("SPAMHAUS_DQS_KEY", "").strip()

if DQS_KEY:
    ZEN_ZONE = DQS_KEY + ".zen.dq.spamhaus.net"
    DBL_ZONE = DQS_KEY + ".dbl.dq.spamhaus.net"
else:
    ZEN_ZONE = "zen.spamhaus.org"
    DBL_ZONE = "dbl.spamhaus.org"

BARRACUDA_ZONE = "b.barracudacentral.org"

ZEN_CODES = {
    "127.0.0.2":  "SBL",
    "127.0.0.3":  "SBL CSS",
    "127.0.0.4":  "XBL (CBL)",
    "127.0.0.5":  "XBL (CBL)",
    "127.0.0.6":  "XBL (CBL)",
    "127.0.0.7":  "XBL (CBL)",
    "127.0.0.9":  "SBL DROP/EDROP",
    "127.0.0.10": "PBL (ISP)",
    "127.0.0.11": "PBL (Spamhaus)",
}

SPAMHAUS_ERROR_CODES = {
    "127.255.255.252": "Typing error in DNSBL name",
    "127.255.255.253": "Query via public/open resolver (blocked)",
    "127.255.255.254": "Excessive number of queries (rate limited)",
    "127.255.255.255": "Blocked (anonymous proxy / open relay)",
}

BARRACUDA_LISTED = {"127.0.0.2", "127.0.0.3"}
DBL_LISTED = {f"127.0.1.{i}" for i in range(2, 13)}

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except Exception:
    HAS_DNSPYTHON = False


def _build_resolver():
    if not HAS_DNSPYTHON:
        return None
    override = [s.strip() for s in os.environ.get("DNS_RESOLVERS", "").split(",") if s.strip()]
    try:
        if override:
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = override
        else:
            r = dns.resolver.Resolver()
        r.timeout = DNS_TIMEOUT
        r.lifetime = DNS_LIFETIME
        try:
            r.retry_servfail = False
        except Exception:
            pass
        return r
    except Exception:
        return None


_DNS_RESOLVER = _build_resolver()
USE_DNSPYTHON = HAS_DNSPYTHON and _DNS_RESOLVER is not None
RESOLVER_NAMESERVERS = list(getattr(_DNS_RESOLVER, "nameservers", []) or []) if USE_DNSPYTHON else []


def _dns_lookup_a(query):
    if USE_DNSPYTHON:
        try:
            answers = _DNS_RESOLVER.resolve(query, "A", raise_on_no_answer=False, lifetime=DNS_LIFETIME)
            rrset = getattr(answers, "rrset", None)
            if not rrset:
                return []
            return [str(rdata) for rdata in rrset]
        except Exception:
            return []
    try:
        return [a for a in socket.gethostbyname_ex(query)[2]]
    except Exception:
        return []


def _reverse_dns(ip):
    if USE_DNSPYTHON:
        try:
            answer = _DNS_RESOLVER.resolve_address(ip, lifetime=DNS_LIFETIME)
            rrset = getattr(answer, "rrset", None)
            if rrset:
                for rdata in rrset:
                    name = str(getattr(rdata, "target", rdata)).rstrip(".")
                    if name:
                        return name
        except Exception:
            pass
        return "-"
    box = {"host": "-"}
    def _worker():
        try:
            h, _, _ = socket.gethostbyaddr(ip)
            if h:
                box["host"] = h.rstrip(".")
        except Exception:
            pass
    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(DNS_LIFETIME)
    return box["host"]


def spamhaus_zen(ip):
    out = {"css": "N/A", "pbl": "N/A", "sbl": "N/A", "codes": [], "error_reason": None}
    rev = ".".join(reversed(ip.split(".")))
    answers = _dns_lookup_a(rev + "." + ZEN_ZONE)
    if not answers:
        return out
    for a in answers:
        out["codes"].append(a)
        if a in SPAMHAUS_ERROR_CODES:
            out["error_reason"] = SPAMHAUS_ERROR_CODES[a]
            continue
        label = ZEN_CODES.get(a)
        if not label:
            continue
        if "SBL" in label:
            out["sbl"] = "LISTED"
        if "CSS" in label:
            out["css"] = "LISTED"
        if "PBL" in label:
            out["pbl"] = "LISTED"
        if "XBL" in label or "DROP" in label:
            out["sbl"] = "LISTED"
    if out["error_reason"] and not any(v == "LISTED" for v in (out["css"], out["pbl"], out["sbl"])):
        out["css"] = "ERROR"
        out["pbl"] = "ERROR"
        out["sbl"] = "ERROR"
    return out


def barracuda_status(ip):
    rev = ".".join(reversed(ip.split(".")))
    answers = set(_dns_lookup_a(rev + "." + BARRACUDA_ZONE))
    if not answers:
        return "N/A"
    if answers & set(SPAMHAUS_ERROR_CODES):
        return "ERROR"
    if answers & BARRACUDA_LISTED:
        return "LISTED"
    for a in answers:
        if a.startswith("127."):
            return "LISTED"
    return "N/A"


def registered_domain(hostname):
    if not hostname or hostname == "-":
        return None
    try:
        labels = [x for x in hostname.strip().lower().rstrip(".").split(".") if x]
        if len(labels) < 2:
            return None
        multi = {"co.uk","org.uk","ac.uk","gov.uk","com.au","net.au","org.au",
                 "com.br","com.cn","com.hk","co.jp","co.in","co.nz","co.za",
                 "com.sg","com.mx","com.tr","com.tw"}
        suffix = ".".join(labels[-2:])
        if len(labels) >= 3 and suffix in multi:
            return ".".join(labels[-3:])
        return suffix
    except Exception:
        return None


def dbl_status(domain):
    if not domain:
        return "N/A"
    answers = set(_dns_lookup_a(domain + "." + DBL_ZONE))
    if not answers:
        return "N/A"
    if answers & set(SPAMHAUS_ERROR_CODES):
        return "ERROR"
    if answers & DBL_LISTED:
        return "LISTED"
    for a in answers:
        if a.startswith("127."):
            return "LISTED"
    return "N/A"


def check_blocklist_ip(ip):
    zen = spamhaus_zen(ip)
    result = {
        "ip": ip,
        "css": zen["css"],
        "pbl": zen["pbl"],
        "sbl": zen["sbl"],
        "barracuda": barracuda_status(ip),
        "rdns": "-",
        "dbl_domain": "-",
        "dbl": "N/A",
    }
    if zen["error_reason"]:
        result["spamhaus_error"] = zen["error_reason"]
    result["rdns"] = _reverse_dns(ip)
    if result["rdns"] != "-":
        dom = registered_domain(result["rdns"])
        if dom:
            result["dbl_domain"] = dom
            result["dbl"] = dbl_status(dom)
    return result


def blocklist_ip_range(first_ip, last_ip):
    try:
        first = ipaddress.IPv4Address(first_ip)
        last = ipaddress.IPv4Address(last_ip)
    except ipaddress.AddressValueError:
        raise ValueError("Please enter valid IPv4 addresses.")
    if int(last) < int(first):
        raise ValueError("Last IP address must be greater than or equal to First IP address.")
    count = int(last) - int(first) + 1
    if count > MAX_BLOCKLIST_IPS:
        raise ValueError("Maximum " + str(MAX_BLOCKLIST_IPS) + " IP addresses are allowed per check.")
    return [str(ipaddress.IPv4Address(n)) for n in range(int(first), int(last) + 1)]


@app.get("/api/blocklist/health")
def blocklist_health():
    if not USE_DNSPYTHON:
        return jsonify(
            dns_backend="system (no dnspython)",
            nameservers=[],
            dqs=DQS_KEY != "",
            spamhaus_ok=False,
            spamhaus_note="Install dnspython: pip install dnspython",
        )
    probe = _dns_lookup_a("2.0.0.127." + ZEN_ZONE)
    ok = True
    note = ""
    for a in probe:
        if a in SPAMHAUS_ERROR_CODES:
            ok = False
            note = SPAMHAUS_ERROR_CODES[a]
            break
    if not ok:
        note += ". Set DNS_RESOLVERS to a private recursive resolver " \
                "(e.g. 127.0.0.1 running unbound) or set SPAMHAUS_DQS_KEY."
    return jsonify(
        dns_backend="dnspython" if USE_DNSPYTHON else "system",
        nameservers=RESOLVER_NAMESERVERS,
        dqs=DQS_KEY != "",
        zone=ZEN_ZONE,
        spamhaus_ok=ok,
        spamhaus_note=note,
    )


@app.post("/api/blocklist/check")
def blocklist_check_api():
    data = request.get_json(silent=True) or {}
    first_ip = str(data.get("first_ip", "")).strip()
    last_ip = str(data.get("last_ip", "")).strip()
    if not first_ip or not last_ip:
        return jsonify(error="Enter both First IP address and Last IP address."), 400
    try:
        ips = blocklist_ip_range(first_ip, last_ip)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    started = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=min(BLOCKLIST_WORKERS, max(1, len(ips)))) as executor:
        futures = {executor.submit(check_blocklist_ip, ip): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                results.append(future.result())
            except Exception:
                results.append({
                    "ip": ip, "css": "N/A", "pbl": "N/A", "sbl": "N/A",
                    "barracuda": "N/A", "rdns": "-", "dbl_domain": "-", "dbl": "N/A"
                })

    results.sort(key=lambda r: int(ipaddress.IPv4Address(r["ip"])))
    totals = {
        "total": len(results),
        "css": sum(r["css"] == "LISTED" for r in results),
        "pbl": sum(r["pbl"] == "LISTED" for r in results),
        "sbl": sum(r["sbl"] == "LISTED" for r in results),
        "barracuda": sum(r["barracuda"] == "LISTED" for r in results),
        "rdns": sum(r["rdns"] != "-" for r in results),
        "dbl": sum(r["dbl"] == "LISTED" for r in results),
    }
    errors = sum(1 for r in results
                 if "ERROR" in (r["css"], r["pbl"], r["sbl"], r["barracuda"], r["dbl"]))

    payload = {
        "results": results,
        "totals": totals,
        "elapsed": round(time.time() - started, 2),
        "errors": errors,
        "dns_backend": "dnspython" if USE_DNSPYTHON else "system",
        "nameservers": RESOLVER_NAMESERVERS,
        "zone": ZEN_ZONE,
    }
    reasons = {r.get("spamhaus_error") for r in results if r.get("spamhaus_error")}
    if errors and errors == len(results):
        if reasons:
            payload["warning"] = ("Spamhaus refused every query: " + "; ".join(sorted(reasons)) +
                                  ". Set DNS_RESOLVERS=127.0.0.1 (unbound) or SPAMHAUS_DQS_KEY=your_key.")
        else:
            payload["warning"] = "Every query returned an error. Retry in a minute or switch resolver."
    return jsonify(payload)


# ============================================================
# Email Hunter API
# ============================================================
@app.post("/api/email-hunter/start")
def email_hunter_start():
    if not HAS_HUNTER:
        return jsonify(error="Email Hunter deps missing. Run: pip install requests beautifulsoup4"), 500
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()
    if not url:
        return jsonify(error="URL is required"), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    sid = secrets.token_urlsafe(12)
    _hunter_status[sid] = "running"
    _hunter_store[sid] = None

    def _run():
        try:
            crawler = EmailHunterCrawler(url)
            result = crawler.crawl()
            _hunter_store[sid] = result
            _hunter_status[sid] = "completed"
        except Exception as e:
            _hunter_store[sid] = {"error": str(e)}
            _hunter_status[sid] = "error"

    threading.Thread(target=_run, daemon=True).start()
    return jsonify(session_id=sid, status="running")


@app.get("/api/email-hunter/results/<sid>")
def email_hunter_results(sid):
    status = _hunter_status.get(sid, "unknown")
    if status == "running":
        return jsonify(status="running")
    result = _hunter_store.get(sid) or {"error": "No results"}
    return jsonify(status=status, **result)


# ============================================================
# Run
# ============================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
