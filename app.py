from flask import Flask, request, jsonify, session, redirect, url_for, Response, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from email.header import decode_header
from html import unescape as html_lib_unescape
import urllib.request, urllib.error, gzip
import base64, random, string, secrets, socket, ipaddress, os, threading, time, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, urldefrag
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_123456789"
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=False)

LOGIN_USERNAME = "admin"
LOGIN_PASSWORD_HASH = generate_password_hash("admin")


# ============================================================
# Error handler — non-API errors are NOT escalated to 500
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
# INDEX_HTML (embedded)
# ============================================================



# ============================================================
# Auth
# ============================================================
@app.before_request
def auth():
    public = {"login", "favicon", "bimi", "home"}
    if request.endpoint in public:
        return
    if request.path in ("/favicon.svg", "/bimi-logo.svg", "/favicon.ico"):
        return
    if not session.get("logged_in"):
        if request.path.startswith("/api/"):
            return jsonify(success=False, error="Login required"), 401
        if request.path == "/":
            return redirect(url_for("login", next="/"))


LOGIN_HTML = '''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Login • UTF-8 Converter Lab</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#07111f;color:#fff;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif}form{width:min(360px,90vw);padding:28px;border:1px solid #203651;border-radius:18px;background:#0d1b2e}input,button{width:100%;padding:12px;margin-top:9px;border-radius:9px;border:1px solid #29415e;box-sizing:border-box;font:inherit}input{background:#07111e;color:#fff;outline:none}input:focus{border-color:#42d9ff}button{background:#42d9ff;color:#06101b;font-weight:800;cursor:pointer;border:0}button:hover{background:#6ce4ff}.e{color:#ff8d9b;margin:6px 0 0;font-size:13px}h2{margin-top:0}p{margin:6px 0;color:#aeb9c5;font-size:14px}</style></head><body><form method="post"><h2>UTF-8 Converter Lab</h2><p>Sign in to continue.</p>{{ERR}}<input name="username" placeholder="Username" required autofocus autocomplete="username"><input name="password" type="password" placeholder="Password" required autocomplete="current-password"><input type="hidden" name="next" value="{{NEXT}}"><button type="submit">Login</button></form></body></html>'''


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        if secrets.compare_digest(u, LOGIN_USERNAME) and check_password_hash(LOGIN_PASSWORD_HASH, p):
            session.clear(); session["logged_in"] = True
            nxt = request.form.get("next", "")
            return redirect(nxt if nxt.startswith("/") else "/")
        return login_page("Invalid username or password", request.form.get("next", "")), 401
    return login_page("", request.args.get("next", ""))


def login_page(error="", nxt="/"):
    err_html = f'<p class="e">{error}</p>' if error else ""
    html = LOGIN_HTML.replace("{{ERR}}", err_html).replace("{{NEXT}}", nxt or "/")
    return Response(html, mimetype="text/html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    return render_template("index.html")


# ============================================================
# SVG assets (both /favicon.svg and /favicon.ico)
# ============================================================
LOGO_SVG = '''<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="#07111f"/><path d="M32 5 55 18v28L32 59 9 46V18z" fill="#091827" stroke="#42d9ff" stroke-width="3"/><text x="32" y="39" text-anchor="middle" font-family="Arial,sans-serif" font-size="21" font-weight="700" fill="#42d9ff">{U}</text></svg>'''
BIMI_SVG = '''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100"><title>UTF-8 Converter Lab</title><desc>UTF-8 Converter Lab brand logo</desc><rect width="100" height="100" fill="#07111f"/><path d="M50 9 88 31v38L50 91 12 69V31z" fill="#091827" stroke="#42d9ff" stroke-width="4"/><text x="50" y="59" text-anchor="middle" font-family="Arial,sans-serif" font-size="26" font-weight="700" fill="#42d9ff">{U}</text></svg>'''

@app.route("/favicon.svg")
def favicon(): return Response(LOGO_SVG, mimetype="image/svg+xml")

@app.route("/favicon.ico")
def favicon_ico(): return Response(LOGO_SVG, mimetype="image/svg+xml")

@app.route("/bimi-logo.svg")
def bimi(): return Response(BIMI_SVG, mimetype="image/svg+xml")


# ============================================================
# Encode / Decode
# ============================================================
INVISIBLE = set("\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\u2065\u2066\u2067\u2068\u2069\u00ad\ufeff")
def clean_decoded(s):
    s = s.replace("\u00a0", " ").replace("\u2007", " ")
    return "".join(c for c in s if c not in INVISIBLE)
def q_byte(b): return "={:02X}".format(b)

def q1(text):
    parts = []
    for c in text:
        if c == " ": parts.append("_")
        else: parts.extend(q_byte(b) for b in c.encode("utf-8"))
    return "".join(parts)

def q2(text):
    parts = []
    for c in text:
        if c == " ": parts.append("_")
        elif c in "=?:_": parts.append(q_byte(ord(c)))
        elif c in string.ascii_letters: parts.append(q_byte(ord(c)) if random.random() < 0.50 else c)
        elif c in string.digits: parts.append(q_byte(ord(c)) if random.random() < 0.35 else c)
        elif ord(c) < 128 and 33 <= ord(c) <= 126: parts.append(q_byte(ord(c)))
        else: parts.extend(q_byte(b) for b in c.encode("utf-8"))
    return "".join(parts)

def _split_random_chunks(text, count):
    if count <= 1 or len(text) <= 1: return [text]
    count = min(count, len(text))
    cuts = sorted(random.sample(range(1, len(text)), count - 1))
    points = [0] + cuts + [len(text)]
    return [text[points[i]:points[i+1]] for i in range(count)]

def _q3_utf8_word(text):
    payload = []
    for c in text:
        if c == " ": payload.append("_")
        else:
            for b in c.encode("utf-8"):
                if 33 <= b <= 126 and chr(b) not in "=?_": payload.append(chr(b))
                else: payload.append(q_byte(b))
    return "=?UTF-8?Q?" + "".join(payload) + "?="

def _b64_word(text):
    return f"=?UTF-8?B?{base64.b64encode(text.encode('utf-8')).decode('ascii')}?="

def q3(text):
    if not text: return ""
    chunk_count = min(4, len(text)) if len(text) <= 24 else min(random.randint(4, 6), len(text))
    chunks = _split_random_chunks(text, chunk_count)
    return "".join(_q3_utf8_word(c) if i % 2 == 0 else _b64_word(c) for i, c in enumerate(chunks))

def custom_b64(text):
    raw = base64.b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")
    if not raw: return "=?UTF-8?B??="
    return f"=?UTF-8?B?{'_'.join(raw)}?="

def decode_q(value):
    value = value.strip().replace("\\", "")
    out = []
    for data, enc in decode_header(value):
        if isinstance(data, bytes): out.append(data.decode(enc or "utf-8", errors="replace"))
        else: out.append(data)
    return clean_decoded("".join(out))

def decode_b64(value):
    value = value.strip().replace("\\", "")
    if value.startswith("=?") and value.endswith("?="):
        parts = value[2:-2].split("?")
        if len(parts) >= 3 and parts[1].upper() == "B": value = parts[2]
    if "=__" in value or value.endswith("__"): value = value.replace("=__", "").replace("_", "")
    value = value.replace(" ", "").replace("\n", "").replace("\r", "")
    value += "=" * ((4 - len(value) % 4) % 4)
    try: return clean_decoded(base64.b64decode(value, validate=False).decode("utf-8", errors="replace"))
    except Exception as e: raise ValueError("Invalid Base64 input") from e

@app.post("/api/encode")
def encode_api():
    t = (request.get_json(silent=True) or {}).get("text", "")
    response = jsonify(
        q1=f"=?UTF-8?Q?{q1(t)}?=", q2=f"=?UTF-8?Q?{q2(t)}?=", q3=q3(t),
        base64=f"=?UTF-8?B?{base64.b64encode(t.encode()).decode()}?=", base64_underscore=custom_b64(t))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response

@app.post("/api/decode")
def decode_api():
    value = (request.get_json(silent=True) or {}).get("text", "").strip()
    if not value: return jsonify(error="Enter encoded text first"), 400
    try:
        v = value.replace("\\", ""); upper = v.upper()
        if "?Q?" in upper or upper.startswith("=?UTF-8?Q?") or upper.startswith("=?US-ASCII?Q?") or upper.startswith("=?ISO-8859-1?Q?"):
            return jsonify(output=decode_q(value), detected="UTF-8 Q")
        return jsonify(output=decode_b64(value), detected="Base64")
    except Exception as e: return jsonify(error=str(e)), 400


# ============================================================
# Random generators
# ============================================================
CONSONANTS = "bcdfghjklmnprstvwxyz"
VOWELS = "aeiou"
NAME_PREFIXES = ["nova","aeon","luma","vera","heli","ori","aqua","zeta","cyra","vire","kilo","pyra","luna","solar","terra","vent","vexa","aria","koda","zena","myra","orix","seva","tira"]
NAME_SUFFIXES = ["wave","flux","core","line","space","land","form","link","point","craft","field","scale","stone","vault","forge","path","node","port","gate","mark","flow","mesh","grid","byte"]

def _generate_word(min_len, max_len):
    n = random.randint(min_len, max_len); w = ""; con = random.choice([True, False])
    while len(w) < n:
        w += random.choice(CONSONANTS if con else VOWELS); con = not con
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
        return jsonify(results=["".join(secrets.choice(chars) for _ in range(random.randint(min_len, max_len))) for _ in range(count)])
    if kind == "words":
        results, used, attempts = [], set(), 0
        while len(results) < count and attempts < count * 30:
            attempts += 1; w = _generate_word(min_len, max_len).capitalize()
            if w not in used: used.add(w); results.append(w)
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
            if style == "pref": parts.append(random.choice(NAME_PREFIXES))
            elif style == "suff": parts.append(random.choice(NAME_SUFFIXES))
            else: parts.append(_generate_word(4, 8).lower())
        results.append(random.choice(["-", ".", "_"]).join(parts))
    return jsonify(results=results)



# ============================================================
# Email Hunter — direct public-site spider
# ============================================================
# This crawler deliberately does NOT inherit HTTP_PROXY / HTTPS_PROXY.
# It uses urllib with ProxyHandler({}) first, then requests with trust_env=False
# as a fallback. The site limit is fixed at 120 seconds.
EH_EMAIL_REGEX = re.compile(
    r'(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}(?![A-Za-z0-9._%+-])'
)
EH_URL_REGEX = re.compile(r'https?://[^\s"\'<>]+', re.I)
EH_REL_URL_REGEX = re.compile(r'(?<![A-Za-z0-9_])(?:/[A-Za-z0-9][^\s"\'<>]{0,500})')
EH_CONTACT_KEYWORDS = re.compile(
    r'contact|kontakt|impressum|imprint|privacy|datenschutz|about|team|staff|person|people|'
    r'directory|department|abteilung|hauptabteilung|press|media|presse|newsletter|office|'
    r'ansprechpartner|service|help|support|career|jobs|verwaltung|generalvikariat|bistum|'
    r'pfarrei|pfarreien|glaube|bildung|finanzen|sitemap|site-map', re.I)
EH_OBFUSCATION_PATTERNS = [
    r'([A-Za-z0-9._%+-]+)\s*\[at\]\s*([A-Za-z0-9.-]+)\s*\[dot\]\s*([A-Za-z]{2,63})',
    r'([A-Za-z0-9._%+-]+)\s*\(at\)\s*([A-Za-z0-9.-]+)\s*\(dot\)\s*([A-Za-z]{2,63})',
    r'([A-Za-z0-9._%+-]+)\s+AT\s+([A-Za-z0-9.-]+)\s+DOT\s+([A-Za-z]{2,63})',
    r'([A-Za-z0-9._%+-]+)\s*\{at\}\s*([A-Za-z0-9.-]+)\s*\{dot\}\s*([A-Za-z]{2,63})',
    r'([A-Za-z0-9._%+-]+)\s*#AT#\s*([A-Za-z0-9.-]+)\s*#DOT#\s*([A-Za-z]{2,63})',
]
# Do not skip PDF here: public PDFs often contain contact emails.
EH_SKIP_EXTENSIONS = (
    '.jpg','.jpeg','.png','.gif','.bmp','.svg','.webp','.ico','.avif','.heic','.heif',
    '.css','.map','.js','.json','.xml','.rss','.atom','.zip','.rar','.7z','.tar','.gz','.bz2','.xz',
    '.mp3','.wav','.ogg','.mp4','.avi','.mov','.mkv','.webm','.woff','.woff2','.ttf','.otf','.eot'
)
EH_TRACKING_PARAMS = {'utm_source','utm_medium','utm_campaign','utm_term','utm_content','utm_id','gclid','fbclid','msclkid'}
EH_JOBS = {}
EH_JOBS_LOCK = threading.Lock()


def eh_normalize_url(url):
    try:
        url = urldefrag(str(url).strip())[0]
        if not url:
            return None
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc:
            return None
        from urllib.parse import parse_qsl, urlencode
        pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
                 if k.lower() not in EH_TRACKING_PARAMS]
        path = parsed.path or '/'
        if path != '/' and path.endswith('/'):
            path = path.rstrip('/')
        return parsed._replace(path=path, query=urlencode(pairs, doseq=True), fragment='').geturl()
    except Exception:
        return None


def eh_host_key(host):
    host = (host or '').lower().split(':', 1)[0].rstrip('.')
    return host[4:] if host.startswith('www.') else host


def eh_same_site(url, root_host, include_subdomains=True):
    host = eh_host_key(urlparse(url).netloc)
    root = eh_host_key(root_host)
    return host == root or (include_subdomains and host.endswith('.' + root))


def eh_valid_email(email):
    email = html_lib_unescape(str(email)).strip().strip('.,;:()[]{}<>"\'')
    return bool(email) and len(email) <= 254 and bool(EH_EMAIL_REGEX.fullmatch(email))


def eh_extract_emails(content):
    """Extract emails from HTML/source/text/bytes. Handles mailto and common obfuscations."""
    if content is None:
        return set()
    if isinstance(content, bytes):
        text = content.decode('utf-8', errors='ignore')
        # Some PDFs/documents expose email text only in their raw byte stream.
        if not text.strip():
            text = content.decode('latin-1', errors='ignore')
    else:
        text = str(content)
    decoded = html_lib_unescape(text)
    found = set()

    def scan(value):
        if not value:
            return
        value = html_lib_unescape(str(value))
        for m in EH_EMAIL_REGEX.findall(value):
            if eh_valid_email(m):
                found.add(m.lower())
        for pattern in EH_OBFUSCATION_PATTERNS:
            for m in re.finditer(pattern, value, re.I):
                candidate = f'{m.group(1).strip()}@{m.group(2).strip()}.{m.group(3).strip()}'
                if eh_valid_email(candidate):
                    found.add(candidate.lower())
        # info at example dot de / info (at) example (dot) de
        for m in re.finditer(
            r'([A-Za-z0-9._%+-]+)\s*(?:\[at\]|\(at\)|\bat\b)\s*'
            r'([A-Za-z0-9.-]+)\s*(?:\[dot\]|\(dot\)|\bdot\b)\s*([A-Za-z]{2,63})',
            value, re.I):
            candidate = f'{m.group(1)}@{m.group(2)}.{m.group(3)}'
            if eh_valid_email(candidate):
                found.add(candidate.lower())

    # Raw source catches script-generated email strings and mailto links.
    scan(decoded)
    if '<' in decoded and '>' in decoded:
        try:
            soup = BeautifulSoup(decoded, 'html.parser')
            scan(soup.get_text(' ', strip=True))
            for tag in soup.find_all(True):
                for attr in ('href','src','content','title','alt','aria-label','onclick',
                             'onmouseover','data-email','data-mail','data-email-address',
                             'data-contact','data-contact-email','data-value','data-url'):
                    value = tag.get(attr)
                    if value:
                        scan(value)
        except Exception:
            pass
    return found


def eh_is_contact_page(html, url=''):
    try:
        soup = BeautifulSoup(html or '', 'html.parser')
        title = soup.title.get_text(' ', strip=True) if soup.title else ''
        return bool(EH_CONTACT_KEYWORDS.search(f'{title} {url}'))
    except Exception:
        return bool(EH_CONTACT_KEYWORDS.search(url or ''))


def eh_should_skip(url):
    p = urlparse(url)
    return p.scheme not in ('http','https') or not p.netloc or p.path.lower().endswith(EH_SKIP_EXTENSIONS)


def eh_discover_links(html, current_url, root_host, include_subdomains=True):
    """Find href plus title/data/onclick/source URLs. Title text itself is not treated as a URL unless it contains one."""
    links = set()
    if not html:
        return links
    raw = html.decode('utf-8', errors='ignore') if isinstance(html, bytes) else str(html)
    decoded = html_lib_unescape(raw)

    def add(value):
        if not isinstance(value, str):
            return
        value = html_lib_unescape(value).strip().strip('\\\'"')
        if not value or value.lower().startswith(('javascript:','mailto:','tel:','sms:','data:')):
            return
        candidates = [value]
        candidates += re.findall(r'https?://[^\s"\'<>]+', value, re.I)
        candidates += re.findall(r'(?<![A-Za-z0-9_])/[A-Za-z0-9][^\s"\'<>)]{0,500}', value)
        for candidate in candidates:
            candidate = candidate.rstrip('.,;)]}')
            absolute = eh_normalize_url(urljoin(current_url, candidate))
            if absolute and not eh_should_skip(absolute) and eh_same_site(absolute, root_host, include_subdomains):
                links.add(absolute)

    try:
        soup = BeautifulSoup(decoded, 'html.parser')
        attrs = ('href','title','data-href','data-url','data-link','data-target','data-path','data-route',
                 'data-page','data-page-url','data-nav','data-menu-url','data-menu','data-item-url',
                 'data-target-url','data-route-url','data-endpoint','data-permalink','data-canonical',
                 'ng-href','routerlink','router-link','to','onclick','onmousedown')
        for tag in soup.find_all(True):
            for attr in attrs:
                value = tag.get(attr)
                if value:
                    add(value)
            if tag.name == 'meta' and str(tag.get('http-equiv','')).lower() == 'refresh':
                m = re.search(r'url\s*=\s*(.+)$', str(tag.get('content','')), re.I)
                if m:
                    add(m.group(1))
    except Exception:
        pass

    # Source-level URLs catch links generated by scripts/templates.
    for value in EH_URL_REGEX.findall(decoded):
        add(value)
    for value in EH_REL_URL_REGEX.findall(decoded):
        if not any(x in value.lower() for x in ('/wp-content/','/static/','/assets/','/fonts/')):
            add(value)
    return links


def eh_direct_fetch(url, timeout=5):
    """Fetch directly, ignoring OS/Python proxy environment variables."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/154 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,text/plain,application/pdf,application/json,*/*;q=0.8',
        'Accept-Language': 'de-DE,de;q=0.9,en;q=0.7',
        'Accept-Encoding': 'gzip',
        'Connection': 'close',
    }
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers=headers, method='GET')
    try:
        with opener.open(req, timeout=timeout) as response:
            data = response.read()
            if response.headers.get('Content-Encoding','').lower() == 'gzip':
                try:
                    data = gzip.decompress(data)
                except Exception:
                    pass
            return response.geturl(), int(response.status), dict(response.headers.items()), data, None
    except urllib.error.HTTPError as e:
        try:
            data = e.read()
        except Exception:
            data = b''
        return url, int(e.code), dict(e.headers.items()) if e.headers else {}, data, f'HTTP {e.code}: {e.reason}'
    except Exception as exc:
        return url, 0, {}, b'', f'{type(exc).__name__}: {exc}'


def eh_fallback_requests_fetch(url, timeout=5):
    """Second direct path; requests does not inherit proxy variables."""
    try:
        s = requests.Session()
        s.trust_env = False
        s.proxies = {}
        s.headers.update({'User-Agent':'Mozilla/5.0 Chrome/154 Safari/537.36'})
        r = s.get(url, timeout=timeout, allow_redirects=True)
        return r.url, r.status_code, dict(r.headers), r.content, None if r.ok else f'HTTP {r.status_code}'
    except Exception as exc:
        return url, 0, {}, b'', f'{type(exc).__name__}: {exc}'


def eh_sitemap_urls(base_url, root_host, include_subdomains=True, timeout=4, max_urls=50000):
    parsed = urlparse(base_url)
    origin = f'{parsed.scheme}://{parsed.netloc}'
    candidates = [origin+'/sitemap.xml', origin+'/sitemap_index.xml', origin+'/sitemap/sitemap.xml']
    rr = eh_direct_fetch(origin+'/robots.txt', timeout)
    if rr[1] == 200:
        text = rr[3].decode('utf-8','ignore')
        candidates += [line.split(':',1)[1].strip() for line in text.splitlines() if line.lower().startswith('sitemap:')]
    queue, seen, found = [], set(), set()
    for x in candidates:
        u = eh_normalize_url(x)
        if u and u not in seen:
            seen.add(u); queue.append(u)
    while queue and len(found) < max_urls:
        sm = queue.pop(0)
        final, status, headers, body, err = eh_direct_fetch(sm, timeout)
        if status != 200 or not body or len(body) > 50*1024*1024:
            continue
        text = body.decode('utf-8','ignore')
        for raw in re.findall(r'<loc>\s*(.*?)\s*</loc>', text, re.I|re.S):
            u = eh_normalize_url(raw.strip())
            if not u or not eh_same_site(u, root_host, include_subdomains):
                continue
            if u.lower().endswith(('.xml','.xml.gz')):
                if u not in seen:
                    seen.add(u); queue.append(u)
            elif not eh_should_skip(u):
                found.add(u)
    return found


def eh_special_seed_urls(base_url, root_host, include_subdomains=True):
    parsed = urlparse(base_url); origin = f'{parsed.scheme}://{parsed.netloc}'
    paths = ['/Sitemap','/sitemap','/site-map','/Impressum','/impressum','/Datenschutz','/datenschutz',
             '/Kontakt','/kontakt','/Contact','/contact','/About','/about','/Team','/team','/directory','/service']
    return {u for u in (eh_normalize_url(origin+x) for x in paths)
            if u and eh_same_site(u, root_host, include_subdomains)}


def eh_browser_available():
    try:
        import playwright.sync_api
        return True
    except Exception:
        return False


def eh_browser_fetch(browser, url, root_host, include_subdomains):
    page = None
    try:
        page = browser.new_page()
        page.set_default_navigation_timeout(7000)
        page.goto(url, wait_until='domcontentloaded', timeout=7000)
        try: page.wait_for_timeout(300)
        except Exception: pass
        final_url = eh_normalize_url(page.url) or url
        if not eh_same_site(final_url, root_host, include_subdomains):
            return final_url, '', set(), 'Redirected outside allowed site'
        html = page.content()
        return final_url, html, eh_discover_links(html, final_url, root_host, include_subdomains), None
    except Exception as exc:
        return url, '', set(), f'{type(exc).__name__}: {exc}'
    finally:
        try:
            if page: page.close()
        except Exception: pass


def eh_crawl_site(base_url, progress=None, include_subdomains=True, use_sitemap=True, render_js=True, **_ignored):
    """Crawl one public site for at most 120 seconds. No proxy, no login/CAPTCHA bypass."""
    base_url = eh_normalize_url(base_url)
    if not base_url:
        raise ValueError('Invalid HTTP/HTTPS URL')
    root_host = urlparse(base_url).netloc
    started = time.time()
    HARD_LIMIT, REQUEST_TIMEOUT = 120.0, 5.0
    MAX_PAGES, MAX_EMAILS, WORKERS = 50000, 50000, 24

    visited, queued = set(), set()
    frontier, results, email_sources = [], [], {}
    pages = contact_pages = errors = discovered = 0
    last_error = ''

    def add_url(url, depth=0):
        nonlocal discovered
        u = eh_normalize_url(url)
        if not u or u in visited or u in queued or eh_should_skip(u) or not eh_same_site(u, root_host, include_subdomains):
            return
        queued.add(u); frontier.append((u, depth)); discovered += 1

    add_url(base_url, 0)
    for u in eh_special_seed_urls(base_url, root_host, include_subdomains):
        add_url(u, 0)
    if use_sitemap and time.time()-started < 10:
        for u in eh_sitemap_urls(base_url, root_host, include_subdomains, timeout=3, max_urls=50000):
            add_url(u, 0)
            if time.time()-started >= 10: break

    browser = None
    browser_used = False
    if render_js and eh_browser_available() and time.time()-started < HARD_LIMIT-5:
        try:
            from playwright.sync_api import sync_playwright
            pw = sync_playwright().start()
            browser = pw.chromium.launch(headless=True, args=['--no-proxy-server','--disable-features=UseChromeOSDirectVideoDecoder'])
            browser_used = True
        except Exception as exc:
            last_error = f'Playwright unavailable: {type(exc).__name__}: {exc}'
            try: pw.stop()
            except Exception: pass

    def fetch(item):
        url, depth = item
        final, status, headers, body, err = eh_direct_fetch(url, REQUEST_TIMEOUT)
        # If urllib fails, try requests without environment proxies.
        if not body and status == 0 and time.time()-started < HARD_LIMIT:
            final2, status2, headers2, body2, err2 = eh_fallback_requests_fetch(url, REQUEST_TIMEOUT)
            if body2 or status2:
                final, status, headers, body, err = final2, status2, headers2, body2, err2
        return url, depth, final, status, headers, body, err

    pool = ThreadPoolExecutor(max_workers=WORKERS)
    try:
        while frontier and len(visited) < MAX_PAGES and len(email_sources) < MAX_EMAILS and time.time()-started < HARD_LIMIT:
            frontier.sort(key=lambda x: (0 if x[1] == 0 else 1, 0 if EH_CONTACT_KEYWORDS.search(x[0]) else 1, x[1]))
            batch=[]
            while frontier and len(batch) < WORKERS:
                item=frontier.pop(0); queued.discard(item[0])
                if item[0] not in visited:
                    visited.add(item[0]); batch.append(item)
            if not batch: continue
            futures=[pool.submit(fetch,item) for item in batch]
            for fut in as_completed(futures):
                if time.time()-started >= HARD_LIMIT: break
                url, depth, final, status, headers, body, err = fut.result()
                html = body.decode(headers.get('Content-Type','').split('charset=')[-1].split(';')[0].strip() or 'utf-8', errors='ignore') if body else ''
                content_type=(headers.get('Content-Type','') or '').lower()

                # Render JS only when normal fetch returned little/no useful HTML.
                if browser and (not body or (len(body) < 15000 and b'<script' in body.lower())) and time.time()-started < HARD_LIMIT-3:
                    bfinal,bhtml,blinks,berr=eh_browser_fetch(browser,url,root_host,include_subdomains)
                    if bhtml:
                        final,html,content_type=bfinal,bhtml,'text/html'
                        body=bhtml.encode('utf-8','ignore')
                        err=None
                    elif berr and not err:
                        err=berr

                if err and not body:
                    errors += 1; last_error=f'{url} -> {err}'
                if not body:
                    if progress: progress({'pages':pages,'queued':len(frontier),'emails':len(email_sources),'contact_pages':contact_pages,'errors':errors,'discovered':discovered,'visited':len(visited),'current_url':url,'last_error':last_error})
                    continue

                pages += 1
                is_contact=eh_is_contact_page(html,final)
                if is_contact: contact_pages += 1
                for email in sorted(eh_extract_emails(body)):
                    if email not in email_sources:
                        email_sources[email]=final
                        results.append({'email':email,'website':base_url,'source_page':final,'contact_page':is_contact})
                        if len(email_sources)>=MAX_EMAILS: break

                if content_type.startswith('text/html') or '<html' in html[:2000].lower():
                    links=eh_discover_links(html,final,root_host,include_subdomains)
                    for link in links:
                        add_url(link,depth+1)

                if progress: progress({'pages':pages,'queued':len(frontier),'emails':len(email_sources),'contact_pages':contact_pages,'errors':errors,'discovered':discovered,'visited':len(visited),'current_url':final,'last_error':last_error})
    finally:
        try: pool.shutdown(wait=False,cancel_futures=True)
        except TypeError: pool.shutdown(wait=False)
        try:
            if browser: browser.close()
        except Exception: pass
        try:
            if 'pw' in locals(): pw.stop()
        except Exception: pass

    return {'results':results,'pages':pages,'contact_pages':contact_pages,'errors':errors,'queued':len(frontier),
            'discovered':discovered,'visited':len(visited),'last_error':last_error,'elapsed':round(time.time()-started,2),
            'browser_used':browser_used,'time_limit_seconds':HARD_LIMIT}


def eh_job_update(job_id, **values):
    with EH_JOBS_LOCK:
        if job_id in EH_JOBS: EH_JOBS[job_id].update(values)


def eh_run_job(job_id, urls, config):
    started=time.time(); combined=[]
    totals={'websites':len(urls),'emails':0,'pages':0,'contact_pages':0,'errors':0,'discovered':0,'visited':0}
    warnings=[]
    try:
        for site_index,url in enumerate(urls,1):
            eh_job_update(job_id,status='running',current_site=url,site_index=site_index)
            def progress(info):
                eh_job_update(job_id,progress=info,totals={**totals,'emails':len({r['email'] for r in combined})+info.get('emails',0)})
            result=eh_crawl_site(url,progress=progress,**config)
            combined.extend(result['results'])
            for k in ('pages','contact_pages','errors','discovered','visited'): totals[k]+=result.get(k,0)
            totals['emails']=len({r['email'] for r in combined})
            if result.get('last_error'): warnings.append(result['last_error'])
            eh_job_update(job_id,totals=totals.copy(),site_done=site_index)
        unique={}
        for row in combined: unique[(row['email'],row['source_page'])]=row
        results=sorted(unique.values(),key=lambda r:(r['email'],r['website'],r['source_page']))
        totals['emails']=len({r['email'] for r in results})
        warning='Public HTTP/HTTPS pages only; no login/CAPTCHA/access-control bypass. '
        if warnings: warning += 'Last crawler note: ' + warnings[-1]
        eh_job_update(job_id,status='done',results=results,totals=totals,elapsed=round(time.time()-started,2),current_site='',warning=warning)
    except Exception as exc:
        eh_job_update(job_id,status='error',error=f'{type(exc).__name__}: {exc}',elapsed=round(time.time()-started,2))


def _eh_parse_config(data):
    return {'include_subdomains':bool(data.get('include_subdomains',True)), 'use_sitemap':bool(data.get('use_sitemap',True)), 'render_js':True}


@app.post('/api/email-hunter/start')
def email_hunter_start_api():
    data=request.get_json(silent=True) or {}; raw_urls=data.get('urls') or []
    if isinstance(raw_urls,str): raw_urls=re.split(r'[\r\n,]+',raw_urls)
    urls=[]
    for raw in raw_urls:
        u=eh_normalize_url(str(raw))
        if u and u not in urls: urls.append(u)
    if not urls: return jsonify(error='Enter at least one valid HTTP/HTTPS URL.'),400
    if len(urls)>10: return jsonify(error='Maximum 10 starting websites per crawl request.'),400
    job_id=secrets.token_urlsafe(12)
    job={'status':'queued','results':[],'totals':{'websites':len(urls),'emails':0,'pages':0,'contact_pages':0,'errors':0,'discovered':0,'visited':0},
         'progress':{'pages':0,'queued':0,'emails':0,'contact_pages':0,'errors':0,'discovered':0,'visited':0,'current_url':'','last_error':''},
         'current_site':urls[0],'site_index':0,'site_done':0,'urls':urls,'created':time.time()}
    with EH_JOBS_LOCK: EH_JOBS[job_id]=job
    threading.Thread(target=eh_run_job,args=(job_id,urls,{'include_subdomains':True,'use_sitemap':True,'render_js':True}),daemon=True).start()
    return jsonify(job_id=job_id,status='queued')


@app.get('/api/email-hunter/status/<job_id>')
def email_hunter_status_api(job_id):
    with EH_JOBS_LOCK:
        job=EH_JOBS.get(job_id)
        if not job: return jsonify(error='Crawl job not found or expired.'),404
        return jsonify(job)


@app.post('/api/email-hunter/crawl')
def email_hunter_crawl_api():
    data=request.get_json(silent=True) or {}; raw_urls=data.get('urls') or []
    if isinstance(raw_urls,str): raw_urls=re.split(r'[\r\n,]+',raw_urls)
    urls=[]
    for raw in raw_urls:
        u=eh_normalize_url(str(raw))
        if u and u not in urls: urls.append(u)
    if not urls: return jsonify(error='Enter at least one valid HTTP/HTTPS URL.'),400
    if len(urls)>10: return jsonify(error='Maximum 10 starting websites per crawl request.'),400
    started=time.time(); combined=[]; totals={'pages':0,'contact_pages':0,'errors':0,'discovered':0,'visited':0}; notes=[]
    for url in urls:
        r=eh_crawl_site(url,include_subdomains=True,use_sitemap=True,render_js=True); combined.extend(r['results'])
        for k in totals: totals[k]+=r.get(k,0)
        if r.get('last_error'): notes.append(r['last_error'])
    unique={(r['email'],r['source_page']):r for r in combined}
    results=sorted(unique.values(),key=lambda r:(r['email'],r['website'],r['source_page']))
    return jsonify(results=results,totals={'websites':len(urls),'emails':len({r['email'] for r in results}),**totals},elapsed=round(time.time()-started,2),
                   warning='Public HTTP/HTTPS pages only; no login/CAPTCHA/access-control bypass.'+((' Last crawler note: '+notes[-1]) if notes else ''))

# ============================================================
# Blocklist — Spamhaus zen (CSS / PBL / SBL) + Barracuda + DBL
# ============================================================
MAX_BLOCKLIST_IPS = int(os.environ.get("MAX_BLOCKLIST_IPS", "4096"))
BLOCKLIST_WORKERS = int(os.environ.get("BLOCKLIST_WORKERS", "32"))
DNS_TIMEOUT = float(os.environ.get("DNS_TIMEOUT", "3.0"))
DNS_LIFETIME = float(os.environ.get("DNS_LIFETIME", "5.0"))

DQS_KEY = os.environ.get("SPAMHAUS_DQS_KEY", "").strip()

if DQS_KEY:
    ZEN_ZONE = f"{DQS_KEY}.zen.dq.spamhaus.net"
    DBL_ZONE = f"{DQS_KEY}.dbl.dq.spamhaus.net"
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
        try: r.retry_servfail = False
        except Exception: pass
        return r
    except Exception:
        return None


_DNS_RESOLVER = _build_resolver()
USE_DNSPYTHON = HAS_DNSPYTHON and _DNS_RESOLVER is not None
RESOLVER_NAMESERVERS = list(getattr(_DNS_RESOLVER, "nameservers", []) or []) if USE_DNSPYTHON else []


def _dns_lookup_a(query):
    if USE_DNSPYTHON:
        try:
            answers = _DNS_RESOLVER.resolve(query, "A",
                                            raise_on_no_answer=False,
                                            lifetime=DNS_LIFETIME)
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
            if h: box["host"] = h.rstrip(".")
        except Exception:
            pass
    t = threading.Thread(target=_worker, daemon=True)
    t.start(); t.join(DNS_LIFETIME)
    return box["host"]


def spamhaus_zen(ip):
    out = {"css": "N/A", "pbl": "N/A", "sbl": "N/A", "codes": [], "error_reason": None}
    rev = ".".join(reversed(ip.split(".")))
    answers = _dns_lookup_a(f"{rev}.{ZEN_ZONE}")
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
        if "SBL" in label: out["sbl"] = "LISTED"
        if "CSS" in label: out["css"] = "LISTED"
        if "PBL" in label: out["pbl"] = "LISTED"
        if "XBL" in label or "DROP" in label: out["sbl"] = "LISTED"
    if out["error_reason"] and not any(v == "LISTED" for v in (out["css"], out["pbl"], out["sbl"])):
        out["css"] = "ERROR"; out["pbl"] = "ERROR"; out["sbl"] = "ERROR"
    return out


def barracuda_status(ip):
    rev = ".".join(reversed(ip.split(".")))
    answers = set(_dns_lookup_a(f"{rev}.{BARRACUDA_ZONE}"))
    if not answers: return "N/A"
    if answers & set(SPAMHAUS_ERROR_CODES): return "ERROR"
    if answers & BARRACUDA_LISTED: return "LISTED"
    for a in answers:
        if a.startswith("127."): return "LISTED"
    return "N/A"


def registered_domain(hostname):
    if not hostname or hostname == "-": return None
    try:
        labels = [x for x in hostname.strip().lower().rstrip(".").split(".") if x]
        if len(labels) < 2: return None
        multi = {"co.uk","org.uk","ac.uk","gov.uk","com.au","net.au","org.au",
                 "com.br","com.cn","com.hk","co.jp","co.in","co.nz","co.za",
                 "com.sg","com.mx","com.tr","com.tw"}
        suffix = ".".join(labels[-2:])
        if len(labels) >= 3 and suffix in multi: return ".".join(labels[-3:])
        return suffix
    except Exception:
        return None


def dbl_status(domain):
    if not domain: return "N/A"
    answers = set(_dns_lookup_a(f"{domain}.{DBL_ZONE}"))
    if not answers: return "N/A"
    if answers & set(SPAMHAUS_ERROR_CODES): return "ERROR"
    if answers & DBL_LISTED: return "LISTED"
    for a in answers:
        if a.startswith("127."): return "LISTED"
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
        raise ValueError(f"Maximum {MAX_BLOCKLIST_IPS} IP addresses are allowed per check.")
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
                results.append({"ip": ip, "css": "N/A", "pbl": "N/A", "sbl": "N/A",
                                "barracuda": "N/A", "rdns": "-",
                                "dbl_domain": "-", "dbl": "N/A"})

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
            payload["warning"] = (
                "Spamhaus refused every query: " + "; ".join(sorted(reasons)) +
                ". Set DNS_RESOLVERS=127.0.0.1 (unbound) or SPAMHAUS_DQS_KEY=your_key."
            )
        else:
            payload["warning"] = (
                "Every query returned an error. Retry in a minute or switch resolver."
            )
    return jsonify(payload)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
