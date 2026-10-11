# ============================================================
# Email journeys — Single-file Flask App (Final)
# ============================================================
from flask import Flask, request, jsonify, session, redirect, url_for, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from email.header import decode_header
from datetime import timedelta
import base64, random, string, secrets, socket, ipaddress, os, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_123456789")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=10),
    SESSION_REFRESH_EACH_REQUEST=False,   # absolute timeout, not inactivity
)

SESSION_MAX_AGE = 10 * 60  # 10 minutes in seconds

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
# INDEX_HTML
# ============================================================
INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Email journeys</title>
<meta name="description" content="Email journey toolkit — UTF-8 Q, Base64 encoder/decoder, random generators and bulk blocklist checks.">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --radius:20px;
  --bg:#fdf8f0;
  --bg-soft:#f6efe2;
  --panel:#ffffff;
  --panel2:#fbf4e9;
  --text:#1c1613;
  --text-soft:#5c524a;
  --muted:#8c8078;
  --line:#efe2cf;
  --line2:#dfcbb0;
  --accent:#e05a3a;
  --accent2:#e89b3c;
  --accent3:#d94a7a;
  --ok:#4d8a5e;
  --warn:#c07a1a;
  --danger:#c4394a;
  --shadow:0 22px 50px rgba(120,80,50,.10);
  --shadow-lg:0 34px 70px rgba(120,80,50,.16);
  --glow:0 0 40px rgba(224,90,58,.18);
}
body.dark{
  --bg:#100b0a;
  --bg-soft:#181110;
  --panel:#1a1413;
  --panel2:#221a18;
  --text:#f6ede2;
  --text-soft:#cdbfb1;
  --muted:#8e7f72;
  --line:#2b2220;
  --line2:#3d302c;
  --accent:#ff8a65;
  --accent2:#ffb356;
  --accent3:#ff6f9c;
  --ok:#6fbf85;
  --warn:#ffc247;
  --danger:#ff7a8a;
  --shadow:0 24px 60px rgba(0,0,0,.55);
  --shadow-lg:0 36px 80px rgba(0,0,0,.65);
  --glow:0 0 40px rgba(255,138,101,.22);
}

*,*::before,*::after{box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  margin:0;min-height:100vh;
  font-family:'Outfit',system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif;
  font-weight:400;
  background:var(--bg);color:var(--text);
  -webkit-font-smoothing:antialiased;
  transition:background .35s ease,color .35s ease;
  letter-spacing:-0.01em;
}
code,pre,.mono,.output{font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}

.bg-orbs{position:fixed;inset:0;overflow:hidden;pointer-events:none;z-index:0}
.bg-orbs span{position:absolute;border-radius:50%;filter:blur(120px);opacity:.55;animation:drift 26s ease-in-out infinite}
.bg-orbs span:nth-child(1){width:620px;height:620px;background:radial-gradient(circle,var(--accent),transparent 70%);top:-220px;left:-180px}
.bg-orbs span:nth-child(2){width:520px;height:520px;background:radial-gradient(circle,var(--accent2),transparent 70%);top:-140px;right:-160px;animation-delay:-8s}
.bg-orbs span:nth-child(3){width:520px;height:520px;background:radial-gradient(circle,var(--accent3),transparent 70%);bottom:-220px;left:38%;animation-delay:-16s}
body.dark .bg-orbs span{opacity:.32}
@keyframes drift{0%,100%{transform:translate3d(0,0,0) scale(1)}50%{transform:translate3d(40px,-50px,0) scale(1.14)}}

.app{position:relative;z-index:1;max-width:1260px;margin:0 auto;padding:22px 22px 0}

.topbar{
  position:sticky;top:12px;z-index:40;
  display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;
  padding:12px 16px;margin:0 0 30px;
  background:color-mix(in srgb,var(--panel) 78%,transparent);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border:1px solid var(--line);border-radius:18px;
  box-shadow:var(--shadow);
}
.brand{display:flex;align-items:center;gap:12px;cursor:pointer;user-select:none}
.brand svg{width:42px;height:42px;flex:0 0 auto;filter:drop-shadow(0 6px 16px rgba(224,90,58,.30))}
.brand b{display:block;font-size:15.5px;font-weight:700;letter-spacing:-.02em}
.brand span{display:block;color:var(--muted);font-size:9.5px;letter-spacing:2px;margin-top:2px;font-weight:600}
.nav{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.nav button{
  border:1px solid transparent;background:transparent;color:var(--text-soft);
  padding:9px 15px;border-radius:11px;cursor:pointer;font-weight:600;font-size:13.5px;
  transition:.2s ease;font-family:inherit;letter-spacing:-.01em;
}
.nav button:hover{color:var(--text);background:var(--panel2)}
.nav button.active{
  color:#fff;background:linear-gradient(120deg,var(--accent),var(--accent2));
  box-shadow:0 8px 22px rgba(224,90,58,.35);
}
.nav .icon-btn{padding:9px 13px;font-size:15px;background:var(--panel2);border:1px solid var(--line)}
.nav .logout{
  background:transparent;border:1px solid color-mix(in srgb,var(--danger) 35%,transparent);
  color:var(--danger);font-weight:600;
}
.nav .logout:hover{background:color-mix(in srgb,var(--danger) 12%,transparent);color:var(--danger)}

.page{display:none;animation:fade .4s ease}
.page.active{display:block}
@keyframes fade{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}

.home-hero{
  display:grid;grid-template-columns:1.05fr .95fr;gap:36px;align-items:center;
  padding:34px 8px 44px;
}
.hero-left{max-width:580px}
.pill{
  display:inline-flex;align-items:center;gap:8px;
  padding:6px 14px;border-radius:99px;
  font-size:12px;font-weight:600;letter-spacing:.02em;
  background:color-mix(in srgb,var(--accent) 10%,transparent);
  color:var(--accent);border:1px solid color-mix(in srgb,var(--accent) 25%,transparent);
}
.pill .dot{width:6px;height:6px;border-radius:50%;background:var(--accent);box-shadow:0 0 10px var(--accent);animation:pulse 1.8s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.hero-left h1{
  font-size:clamp(38px,5.4vw,66px);line-height:1.02;margin:22px 0 18px;
  letter-spacing:-.035em;font-weight:700;
}
.hero-left h1 .swipe{
  background:linear-gradient(100deg,var(--accent),var(--accent2),var(--accent3));
  -webkit-background-clip:text;background-clip:text;color:transparent;
  background-size:220% auto;animation:shine 7s linear infinite;font-style:italic;font-weight:800;
}
@keyframes shine{to{background-position:220% center}}
.hero-left p.lede{
  color:var(--text-soft);font-size:16.5px;line-height:1.7;margin:0 0 26px;max-width:540px;
}
.hero-cta{display:flex;gap:10px;flex-wrap:wrap}
.micro-stats{display:flex;gap:22px;margin-top:32px;padding-top:26px;border-top:1px solid var(--line);flex-wrap:wrap}
.micro-stats div{display:flex;flex-direction:column;gap:2px}
.micro-stats b{font-size:22px;font-weight:700;letter-spacing:-.03em;line-height:1}
.micro-stats span{font-size:11.5px;color:var(--muted);font-weight:500;letter-spacing:.02em}

.hero-right{position:relative}
.preview-window{
  position:relative;border-radius:22px;overflow:hidden;
  background:var(--panel);border:1px solid var(--line);
  box-shadow:var(--shadow-lg);transform:rotate(-1.2deg);
  transition:transform .5s ease;
}
.preview-window:hover{transform:rotate(0deg) translateY(-4px)}
.window-bar{
  display:flex;align-items:center;gap:8px;padding:12px 16px;
  background:var(--panel2);border-bottom:1px solid var(--line);
}
.window-bar .dot{width:10px;height:10px;border-radius:50%}
.window-bar .dot.r{background:#ff5f57}.window-bar .dot.y{background:#ffbd2e}.window-bar .dot.g{background:#28c840}
.window-bar b{margin-left:8px;font-size:12px;font-weight:600;color:var(--muted);letter-spacing:.04em}
.window-body{padding:20px;font-family:'JetBrains Mono',monospace;font-size:12px;line-height:1.9}
.win-line{display:flex;gap:10px;align-items:flex-start;padding:5px 0;word-break:break-all}
.win-tag{
  flex:0 0 auto;font-size:10px;font-weight:700;letter-spacing:.06em;
  padding:2px 8px;border-radius:6px;margin-top:2px;
}
.tag-in{background:color-mix(in srgb,var(--accent) 15%,transparent);color:var(--accent)}
.tag-q1{background:color-mix(in srgb,var(--accent2) 18%,transparent);color:var(--accent2)}
.tag-q2{background:color-mix(in srgb,var(--accent3) 15%,transparent);color:var(--accent3)}
.tag-b64{background:color-mix(in srgb,var(--ok) 15%,transparent);color:var(--ok)}
.win-text{color:var(--text-soft);font-size:11.5px;line-height:1.6}

.stats-strip{
  display:grid;grid-template-columns:repeat(4,1fr);gap:2px;
  background:var(--line);border-radius:20px;overflow:hidden;
  border:1px solid var(--line);margin-bottom:44px;
}
.stats-strip > div{padding:26px 22px;background:var(--panel);text-align:center}
.stats-strip b{display:block;font-size:34px;font-weight:700;letter-spacing:-.04em;line-height:1;margin-bottom:6px;
  background:linear-gradient(120deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;color:transparent;}
.stats-strip span{font-size:11.5px;color:var(--muted);font-weight:500;letter-spacing:.02em}

.bento{display:grid;grid-template-columns:1.4fr 1fr 1fr;grid-template-rows:auto auto;gap:16px;margin-bottom:20px}
.bento-card{
  padding:28px;border-radius:22px;
  background:var(--panel);border:1px solid var(--line);
  box-shadow:var(--shadow);position:relative;overflow:hidden;
  transition:.3s ease;
}
.bento-card:hover{transform:translateY(-3px);box-shadow:var(--shadow-lg);border-color:var(--line2)}
.bento-card.big{grid-column:1/3;grid-row:1}
.bento-card.tall{grid-column:3/4;grid-row:1/3}
.bento-card.wide{grid-column:1/3;grid-row:2}
.bento-card .bic{
  width:46px;height:46px;border-radius:14px;display:grid;place-items:center;font-size:22px;margin-bottom:16px;
  background:linear-gradient(135deg,color-mix(in srgb,var(--accent) 18%,transparent),color-mix(in srgb,var(--accent2) 18%,transparent));
  border:1px solid color-mix(in srgb,var(--accent) 20%,transparent);
}
.bento-card h3{margin:0 0 8px;font-size:19px;font-weight:700;letter-spacing:-.02em}
.bento-card p{color:var(--text-soft);font-size:13.5px;line-height:1.65;margin:0;max-width:520px}
.bento-card .baa{
  display:inline-flex;align-items:center;gap:6px;margin-top:16px;
  font-size:12.5px;font-weight:600;color:var(--accent);cursor:pointer;
  border:0;background:transparent;padding:0;font-family:inherit;
}
.bento-card .baa:hover{gap:10px}
.bento-card .baa::after{content:'→';transition:.2s}

.section-head{display:flex;justify-content:space-between;align-items:flex-end;gap:20px;margin:4px 0 20px;flex-wrap:wrap}
.section-head h2{margin:0;font-size:28px;letter-spacing:-.03em;font-weight:700}
.section-head p{margin:6px 0 0;color:var(--muted);font-size:13.5px;line-height:1.65;max-width:760px}

.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:24px;box-shadow:var(--shadow)}
.card h3{margin:0 0 16px;font-size:16px;font-weight:700;letter-spacing:-.02em}

.tabs{display:flex;gap:6px;margin-bottom:20px;flex-wrap:wrap;padding:5px;background:var(--panel2);border-radius:14px;width:fit-content;border:1px solid var(--line)}
.tab{padding:9px 16px;border-radius:10px;border:0;background:transparent;color:var(--muted);cursor:pointer;font-weight:600;font-size:13px;transition:.2s;font-family:inherit;letter-spacing:-.01em}
.tab:hover{color:var(--text)}
.tab.active{color:#fff;background:linear-gradient(120deg,var(--accent),var(--accent2));box-shadow:0 6px 18px rgba(224,90,58,.3)}

.workspace{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.label{display:block;color:var(--muted);font-size:10.5px;font-weight:700;letter-spacing:1.6px;margin:0 0 8px;text-transform:uppercase}
textarea,input[type=text],input[type=number]{
  width:100%;font:inherit;font-size:14px;color:var(--text);
  background:var(--panel2);border:1px solid var(--line);border-radius:13px;
  padding:13px 15px;outline:none;transition:.2s;font-family:inherit;
}
textarea{min-height:170px;resize:vertical;line-height:1.7}
textarea:focus,input:focus{border-color:var(--accent);box-shadow:0 0 0 4px color-mix(in srgb,var(--accent) 16%,transparent);background:var(--panel)}
textarea[readonly]{cursor:text}

.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}
.result{margin-top:14px}
.output{
  min-height:96px;white-space:pre-wrap;word-break:break-word;
  background:var(--panel2);border:1px solid var(--line);border-radius:13px;
  padding:14px 15px;font-family:'JetBrains Mono',monospace;
  font-size:12.5px;line-height:1.7;color:var(--text-soft);
}
.output-wrap{display:flex;gap:8px;align-items:stretch}
.output-wrap .output{flex:1;min-width:0}
.copy-btn{
  border:1px solid var(--line);background:var(--panel2);color:var(--text-soft);
  border-radius:13px;padding:0 15px;cursor:pointer;font-weight:600;font-size:12px;
  min-width:80px;transition:.2s;font-family:inherit;
}
.copy-btn:hover{border-color:var(--accent);color:var(--accent);background:color-mix(in srgb,var(--accent) 8%,transparent)}

.notice{padding:13px 16px;border:1px solid var(--line);border-radius:13px;background:var(--panel2);color:var(--text-soft);font-size:13px;line-height:1.65;margin-bottom:18px}
.hidden{display:none!important}

button.primary,button.secondary{border:0;border-radius:13px;padding:12px 22px;cursor:pointer;font-weight:600;font-size:14px;transition:.2s ease;font-family:inherit;letter-spacing:-.01em}
button.primary{color:#fff;background:linear-gradient(120deg,var(--accent),var(--accent2));box-shadow:0 10px 26px rgba(224,90,58,.32)}
button.primary:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 16px 32px rgba(224,90,58,.42)}
button.secondary{background:var(--panel2);color:var(--text);border:1px solid var(--line)}
button.secondary:hover:not(:disabled){border-color:var(--line2);transform:translateY(-2px);background:var(--panel)}
button:disabled{opacity:.5;cursor:not-allowed;transform:none!important}

.controls3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:8px 0 6px}
.helper,.status{color:var(--muted);font-size:12.5px;line-height:1.65}
.status{margin-top:12px;min-height:18px}
.gen-panel{margin-top:18px}

.bl-form{display:grid;grid-template-columns:1fr 1fr auto auto;gap:12px;align-items:end}
.bl-field label{display:block;color:var(--muted);font-size:10.5px;font-weight:700;letter-spacing:1.6px;margin:0 0 8px}
.bl-status{margin-top:16px;color:var(--text-soft);font-size:13px;line-height:1.65}
.bl-health{display:flex;gap:18px;flex-wrap:wrap;margin-top:12px;font-size:12px;color:var(--muted)}
.bl-health b{color:var(--text);font-weight:600}
.bl-progress{height:7px;border-radius:99px;background:var(--panel2);overflow:hidden;margin-top:16px;border:1px solid var(--line)}
.bl-progress-bar{height:100%;width:0;background:linear-gradient(90deg,var(--accent),var(--accent2),var(--accent3));transition:width .3s ease}

.bl-summary{display:grid;grid-template-columns:repeat(7,1fr);gap:12px;margin-top:20px}
.bl-summary-item{padding:18px 12px;border:1px solid var(--line);border-radius:16px;background:var(--panel);text-align:center;box-shadow:var(--shadow)}
.bl-summary-item b{display:block;font-size:24px;margin-bottom:4px;letter-spacing:-.04em;font-weight:700}
.bl-summary-item span{color:var(--muted);font-size:10.5px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase}

.bl-table-wrap{margin-top:20px;overflow:auto;border:1px solid var(--line);border-radius:18px;max-height:660px;box-shadow:var(--shadow)}
.bl-table{width:100%;min-width:1040px;border-collapse:collapse;background:var(--panel)}
.bl-table thead th{position:sticky;top:0;z-index:2;background:var(--panel2);color:var(--muted);font-size:10.5px;letter-spacing:1.2px;text-transform:uppercase;font-weight:700;padding:14px 12px;border-bottom:1px solid var(--line);text-align:center}
.bl-table td{padding:11px 12px;border-bottom:1px solid var(--line);font-size:12.5px;text-align:center;vertical-align:middle}
.bl-table tbody tr:hover td{background:var(--panel2)}
.bl-table tbody tr:last-child td{border-bottom:0}
.ip-cell,.rdns-cell{text-align:left!important;font-family:'JetBrains Mono',monospace;font-size:11.5px!important}
.bl-status-pill{display:inline-block;padding:3px 10px;border-radius:99px;font-size:10px;font-weight:700;letter-spacing:.4px;border:1px solid transparent}
.bl-ok{color:var(--ok);background:color-mix(in srgb,var(--ok) 13%,transparent);border-color:color-mix(in srgb,var(--ok) 30%,transparent)}
.bl-listed{color:var(--danger);background:color-mix(in srgb,var(--danger) 13%,transparent);border-color:color-mix(in srgb,var(--danger) 30%,transparent)}
.bl-error{color:var(--warn);background:color-mix(in srgb,var(--warn) 15%,transparent);border-color:color-mix(in srgb,var(--warn) 32%,transparent)}
.bl-na{color:var(--muted);background:var(--panel2);border-color:var(--line)}
.bl-total td{background:var(--panel2);font-weight:700;border-top:2px solid var(--line2)}
.bl-dbl-domain{display:block;margin-top:5px;color:var(--muted);font-size:10.5px;word-break:break-all}

.footer{text-align:center;color:var(--muted);font-size:12px;padding:48px 0 28px;letter-spacing:.02em}

.toasts{position:fixed;right:18px;bottom:18px;z-index:100;display:flex;flex-direction:column;gap:10px}
.toast{padding:13px 18px;border-radius:14px;font-size:13px;font-weight:600;background:var(--panel);border:1px solid var(--line);color:var(--text);box-shadow:var(--shadow-lg);animation:toastIn .3s ease;max-width:340px}
.toast.ok{border-color:color-mix(in srgb,var(--ok) 45%,transparent)}
.toast.err{border-color:color-mix(in srgb,var(--danger) 45%,transparent)}
@keyframes toastIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}

.session-banner{
  position:fixed;top:14px;left:50%;transform:translateX(-50%);
  z-index:200;padding:9px 16px;border-radius:99px;
  background:var(--panel);border:1px solid var(--line);color:var(--muted);
  font-size:12px;font-weight:600;box-shadow:var(--shadow);display:none;
}
.session-banner.show{display:block;animation:toastIn .3s ease}
.session-banner b{color:var(--accent)}

@media(max-width:980px){
  .home-hero{grid-template-columns:1fr;padding:18px 4px 30px;gap:28px}
  .bento{grid-template-columns:1fr 1fr;grid-template-rows:auto}
  .bento-card.big,.bento-card.tall,.bento-card.wide{grid-column:auto;grid-row:auto}
  .bento-card.big{grid-column:1/3}
  .workspace,.controls3{grid-template-columns:1fr}
  .bl-form{grid-template-columns:1fr}
  .bl-summary{grid-template-columns:repeat(3,1fr)}
}
@media(max-width:640px){
  .app{padding:14px 14px 0}
  .topbar{position:static}
  .nav{width:100%}
  .nav button{flex:1 1 auto}
  .stats-strip{grid-template-columns:repeat(2,1fr)}
  .bento{grid-template-columns:1fr}
  .bento-card.big,.bento-card.wide{grid-column:auto}
  .bl-summary{grid-template-columns:repeat(2,1fr)}
  .output-wrap{flex-direction:column}
  .copy-btn{padding:11px;width:100%}
}
</style>
</head>
<body>
<div class="bg-orbs"><span></span><span></span><span></span></div>
<div id="session-banner" class="session-banner">Session expires in <b id="session-countdown">10:00</b></div>

<div class="app">
  <header class="topbar">
    <div class="brand" onclick="showPage('home')">
      <svg viewBox="0 0 64 64" aria-hidden="true">
        <defs><linearGradient id="lg" x1="0" x2="1" y1="0" y2="1">
          <stop stop-color="#e05a3a"/><stop offset=".5" stop-color="#e89b3c"/><stop offset="1" stop-color="#d94a7a"/>
        </linearGradient></defs>
        <path d="M32 5 55 18v28L32 59 9 46V18z" fill="none" stroke="url(#lg)" stroke-width="3.5" stroke-linejoin="round"/>
        <text x="32" y="40" text-anchor="middle" font-family="Outfit,sans-serif" font-size="20" font-weight="700" fill="url(#lg)">{U}</text>
      </svg>
      <div><b>Email journeys</b><span>ENCODE • DECODE • GENERATE</span></div>
    </div>
    <nav class="nav">
      <button id="nav-home" onclick="showPage('home')">Home</button>
      <button id="nav-converter" onclick="showPage('converter')">Converter</button>
      <button id="nav-generator" onclick="showPage('generator')">Generators</button>
      <button id="nav-blocklist" onclick="showPage('blocklist')">Blocklist</button>
      <button class="icon-btn" id="theme-btn" onclick="toggleTheme()" title="Toggle theme">☾</button>
      <button class="logout" onclick="logoutUser()">Logout</button>
    </nav>
  </header>

  <!-- ================= HOME ================= -->
  <section id="home" class="page active">
    <div class="home-hero">
      <div class="hero-left">
        <span class="pill"><span class="dot"></span>Email Toolkit · v2</span>
        <h1>Every email journey, <span class="swipe">decoded right</span>.</h1>
        <p class="lede">Encode and decode UTF-8 Q and Base64 subject lines, generate random sender identities, and verify your sending IPs against every major blocklist — one workspace for the people who ship email.</p>
        <div class="hero-cta">
          <button class="primary" onclick="showPage('converter');setMode('encode')">Start Encoding</button>
          <button class="secondary" onclick="showPage('blocklist')">Check Blocklist</button>
        </div>
        <div class="micro-stats">
          <div><b>3</b><span>Q methods</span></div>
          <div><b>2</b><span>Base64 modes</span></div>
          <div><b>4</b><span>DNS blocklists</span></div>
          <div><b>10m</b><span>Session timeout</span></div>
        </div>
      </div>
      <div class="hero-right">
        <div class="preview-window">
          <div class="window-bar">
            <span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
            <b>email-journey.live</b>
          </div>
          <div class="window-body">
            <div class="win-line"><span class="win-tag tag-in">IN</span><span class="win-text">Your order has shipped 🎉</span></div>
            <div class="win-line"><span class="win-tag tag-q1">Q1</span><span class="win-text">=?UTF-8?Q?Your_order_has_shipped_=F0=9F=8E=89?=</span></div>
            <div class="win-line"><span class="win-tag tag-q2">Q2</span><span class="win-text">=?UTF-8?Q?Y=6Eur_=6Frder_has_sh=69pped_=F0=9F=8E=89?=</span></div>
            <div class="win-line"><span class="win-tag tag-b64">B64</span><span class="win-text">WW91ciBvcmRlciBoYXMgc2hpcHBlZCDwn46J</span></div>
          </div>
        </div>
      </div>
    </div>

    <div class="stats-strip">
      <div><b>99.9%</b><span>Decode accuracy</span></div>
      <div><b>1024</b><span>IPs per check</span></div>
      <div><b>24</b><span>Parallel workers</span></div>
      <div><b>0</b><span>Third-party JS</span></div>
    </div>

    <div class="bento">
      <div class="bento-card big">
        <div class="bic">✉️</div>
        <h3>UTF-8 Q Encoding — three flavours</h3>
        <p>Method&nbsp;1 uses fixed quoted-printable for full safety. Method&nbsp;2 mixes plain and encoded characters. Method&nbsp;3 splits subject lines into random chunks and interleaves Q and Base64 words for maximum obfuscation.</p>
        <button class="baa" onclick="showPage('converter');setMode('encode')">Open converter</button>
      </div>
      <div class="bento-card tall">
        <div class="bic">🧬</div>
        <h3>Smart Decoding</h3>
        <p>Paste any Q or Base64 encoded-word from a raw email and the app detects the format automatically — then strips invisible formatting characters like ZWSP, ZWNJ and BOM from the result.</p>
        <button class="baa" onclick="showPage('converter');setMode('decode')">Open decoder</button>
      </div>
      <div class="bento-card">
        <div class="bic">🎲</div>
        <h3>Random Generators</h3>
        <p>Secure strings, pronounceable words and brandable sender names.</p>
        <button class="baa" onclick="showPage('generator')">Open generators</button>
      </div>
      <div class="bento-card wide">
        <div class="bic">🛡️</div>
        <h3>Bulk Blocklist Check</h3>
        <p>Query up to 1,024 IPv4 addresses at once against Spamhaus ZEN (CSS / PBL / SBL / XBL) and Barracuda, then resolve RDNS and its registered domain against Spamhaus DBL. Export the whole table to CSV in one click.</p>
        <button class="baa" onclick="showPage('blocklist')">Open blocklist</button>
      </div>
    </div>
  </section>

  <!-- ================= CONVERTER ================= -->
  <section id="converter" class="page">
    <div class="section-head">
      <div><h2>UTF-8 &amp; Base64 Converter</h2><p>Switch between Encode and Decode. Format detection on decode is automatic.</p></div>
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
      <div><h2>Random Generators</h2><p>Cryptographically strong strings, pronounceable random words, and brandable names.</p></div>
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
        <h2>Bulk Blocklist Check</h2>
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

  <div class="footer">Email journeys · Embedded logo, favicon and BIMI endpoint · <span id="year"></span></div>
</div>

<div id="toasts" class="toasts"></div>

<script>
const $ = (id) => document.getElementById(id);
const PAGES = ['home', 'converter', 'generator', 'blocklist'];
const state = { blAbort: null, blData: null };

/* ============================================================
   Session timeout — 10 minutes, absolute
   ============================================================ */
const SESSION_MAX_AGE_MS = 10 * 60 * 1000;
const SESSION_START_KEY = 'ej_session_start';
const SESSION_BANNER_DELAY_MS = 8 * 60 * 1000; // show banner after 8 min

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
    const m = String(Math.floor(remaining / 60000)).padStart(1, '0');
    const s = String(Math.floor((remaining % 60000) / 1000)).padStart(2, '0');
    label.textContent = m + ':' + s;
    banner.classList.add('show');
  } else {
    banner.classList.remove('show');
  }
}

// Kick off session tracking
sessionStart();
setInterval(function () {
  if (!checkSession()) return;
  updateSessionBanner();
}, 1000);

/* ============================================================
   Navigation & theme
   ============================================================ */
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
  const dark = document.body.classList.toggle('dark');
  localStorage.setItem('theme', dark ? 'dark' : 'light');
  $('theme-btn').textContent = dark ? '☀' : '☾';
}
(function initTheme() {
  const saved = localStorage.getItem('theme');
  const dark = saved === 'dark';
  document.body.classList.toggle('dark', dark);
  $('theme-btn').textContent = dark ? '☀' : '☾';
})();

function logoutUser() {
  sessionStorage.removeItem(SESSION_START_KEY);
  window.location.href = '/logout';
}

/* ============================================================
   Toasts + clipboard
   ============================================================ */
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

/* ============================================================
   API helper — handles 401 as "session expired"
   ============================================================ */
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

/* ============================================================
   Converter
   ============================================================ */
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

/* ============================================================
   Generators
   ============================================================ */
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

/* ============================================================
   Blocklist
   ============================================================ */
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

/* ============================================================
   Boot
   ============================================================ */
$('year').textContent = new Date().getFullYear();
showPage('home');

document.addEventListener('keydown', function (e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    const active = document.activeElement;
    if (active && active.id === 'enc-input') encodeText();
    if (active && active.id === 'dec-input') decodeText();
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

    # Absolute 10-minute timeout
    login_time = session.get("login_time", 0)
    if time.time() - login_time > SESSION_MAX_AGE:
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify(success=False, error="Session expired"), 401
        return redirect(url_for("login", next=request.path, expired="1"))


LOGIN_HTML = '''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Sign in • Email journeys</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#100b0a;color:#f6ede2;font-family:'Outfit',system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif;letter-spacing:-.01em;position:relative;overflow:hidden}
body::before,body::after{content:'';position:fixed;border-radius:50%;filter:blur(120px);opacity:.4;pointer-events:none}
body::before{width:520px;height:520px;background:radial-gradient(circle,#e05a3a,transparent 70%);top:-200px;left:-160px}
body::after{width:480px;height:480px;background:radial-gradient(circle,#d94a7a,transparent 70%);bottom:-200px;right:-160px}
form{position:relative;z-index:2;width:min(400px,90vw);padding:38px;border:1px solid rgba(255,255,255,.08);border-radius:24px;background:rgba(255,255,255,.04);backdrop-filter:blur(22px);box-shadow:0 34px 80px rgba(0,0,0,.6)}
h2{margin:0 0 8px;font-size:24px;font-weight:700;letter-spacing:-.02em}
p{margin:6px 0;color:#a89687;font-size:13.5px}
input,button{width:100%;padding:14px;margin-top:11px;border-radius:13px;border:1px solid rgba(255,255,255,.09);box-sizing:border-box;font:inherit;font-size:14.5px;font-family:inherit;letter-spacing:-.01em}
input{background:rgba(255,255,255,.05);color:#fff;outline:none;transition:.2s}
input:focus{border-color:#e05a3a;box-shadow:0 0 0 4px rgba(224,90,58,.18)}
button{background:linear-gradient(120deg,#e05a3a,#e89b3c);color:#fff;font-weight:700;cursor:pointer;border:0;margin-top:20px;transition:.2s;box-shadow:0 10px 26px rgba(224,90,58,.35)}
button:hover{transform:translateY(-2px);box-shadow:0 16px 32px rgba(224,90,58,.45)}
.e{color:#ff7a8a;margin:10px 0 0;font-size:13px;font-weight:500}
.n{color:#ffb356;margin:10px 0 0;font-size:13px;font-weight:500}
</style></head><body><form method="post">
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
LOGO_SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#100b0a"/><defs><linearGradient id="g" x1="0" x2="1" y1="0" y2="1"><stop stop-color="#e05a3a"/><stop offset=".5" stop-color="#e89b3c"/><stop offset="1" stop-color="#d94a7a"/></linearGradient></defs><path d="M32 6 55 19v26L32 58 9 45V19z" fill="none" stroke="url(#g)" stroke-width="3.5" stroke-linejoin="round"/><text x="32" y="40" text-anchor="middle" font-family="Outfit,sans-serif" font-size="20" font-weight="700" fill="url(#g)">{U}</text></svg>'
BIMI_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><title>Email journeys</title><rect width="100" height="100" fill="#100b0a"/><defs><linearGradient id="g" x1="0" x2="1" y1="0" y2="1"><stop stop-color="#e05a3a"/><stop offset=".5" stop-color="#e89b3c"/><stop offset="1" stop-color="#d94a7a"/></linearGradient></defs><path d="M50 10 86 31v38L50 90 14 69V31z" fill="none" stroke="url(#g)" stroke-width="4" stroke-linejoin="round"/><text x="50" y="60" text-anchor="middle" font-family="Outfit,sans-serif" font-size="26" font-weight="700" fill="url(#g)">{U}</text></svg>'


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
    """Q-encode a chunk with randomised quoted-printable substitution."""
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
# Run
# ============================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
