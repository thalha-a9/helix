"""
Helix: a local web page (helix --serve).

    helix --serve              # then open http://127.0.0.1:8765/
    helix --serve --port 9000

A plain page for people who do not use a terminal: type a username, press
Check, read the accounts. It is also a small HTTP API:

    GET /api/scan?username=NAME&sources=builtin&purpose=...&token=TOKEN

The server listens on this computer only (127.0.0.1) and every API call
needs the token printed when it starts, which the page carries. A request
whose Host header is not this computer is refused, so a web page elsewhere
cannot make your browser run scans (DNS rebinding). Nothing is stored and
nothing is sent anywhere but the sites being checked.
"""

import html
import json
import secrets
from typing import Optional

from aiohttp import web

from helix_osint import __version__, api, i18n

DEFAULT_PORT = 8765
TOKEN = web.AppKey("token", str)
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "[::1]")

_PAGE = """<!doctype html>
<html lang="__LANG__" dir="__DIR__">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Helix</title>
<style>
:root{--bg:#fff;--fg:#16181d;--dim:#5b6472;--line:#d9dee6;--card:#f5f7fa;--ok:#1a7f37;--warn:#9a6700;--link:#0b5fff;--btn:#0b5fff;--btnfg:#fff}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0f1115;--fg:#e7eaf0;--dim:#9aa4b2;--line:#2a2f3a;--card:#171a21;--ok:#4ac26b;--warn:#d4a72c;--link:#79a8ff;--btn:#3b82f6;--btnfg:#fff}}
:root[data-theme="dark"]{--bg:#0f1115;--fg:#e7eaf0;--dim:#9aa4b2;--line:#2a2f3a;--card:#171a21;--ok:#4ac26b;--warn:#d4a72c;--link:#79a8ff;--btn:#3b82f6;--btnfg:#fff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans",sans-serif}
main{max-width:760px;margin:0 auto;padding:24px 16px 64px}h1{font-size:1.5rem;margin:0 0 6px}h2{font-size:1.1rem;margin:28px 0 8px}
p{margin:8px 0}.dim{color:var(--dim)}a{color:var(--link);word-break:break-all}
label{display:block;margin:14px 0 4px;font-weight:600}
input[type=text],select{width:100%;font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px}
.radio{font-weight:400;margin:6px 0}button{font:inherit;font-weight:600;margin-top:16px;padding:10px 22px;border-radius:8px;border:0;background:var(--btn);color:var(--btnfg);cursor:pointer}
button[disabled]{opacity:.6;cursor:default}.acc{border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:8px 0;background:var(--card)}
.acc b{display:block}.tag{font-size:.8rem;color:var(--dim)}.note{border-inline-start:3px solid var(--warn);padding-inline-start:10px;margin:12px 0}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.top select{width:auto}
</style>
</head>
<body>
<main>
<div class="top"><h1>Helix</h1>
<select id="lang" aria-label="__T_language__">__LANG_OPTIONS__</select></div>
<p>__T_intro__</p>
<p class="note dim">__T_responsible__</p>
<form id="f">
<label for="u">__T_username__</label>
<input id="u" type="text" autocomplete="off" autocapitalize="none" spellcheck="false" maxlength="50" required>
<label for="p">__T_purpose__</label>
<input id="p" type="text" maxlength="200" placeholder="__T_purpose_hint__">
<label>__T_sources__</label>
<label class="radio"><input type="radio" name="s" value="builtin" checked> __T_builtin__</label>
<label class="radio"><input type="radio" name="s" value="all"> __T_all__</label>
<button id="go" type="submit">__T_scan__</button>
</form>
<p id="status" class="dim" role="status"></p>
<div id="out"></div>
<p class="dim">Helix __VERSION__</p>
</main>
<script id="words" type="application/json">__WORDS__</script>
<script>
(function () {
  var T = JSON.parse(document.getElementById('words').textContent), token = '__TOKEN__';
  var out = document.getElementById('out'), status = document.getElementById('status'), go = document.getElementById('go');
  function el(tag, text, cls) { var e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
  document.getElementById('lang').addEventListener('change', function () { location.search = '?lang=' + this.value; });
  function card(r, extra) {
    var d = el('div', undefined, 'acc'); d.appendChild(el('b', r.platform));
    var url = String(r.url || '');
    if (/^https?:\\/\\//.test(url)) { var a = el('a', url); a.href = url; a.rel = 'noopener noreferrer'; a.target = '_blank'; d.appendChild(a); }
    else d.appendChild(el('span', url));
    if (extra) d.appendChild(el('div', extra, 'tag'));
    return d;
  }
  document.getElementById('f').addEventListener('submit', function (ev) {
    ev.preventDefault();
    out.textContent = ''; status.textContent = T.scanning; go.disabled = true;
    var q = new URLSearchParams({ username: document.getElementById('u').value, purpose: document.getElementById('p').value,
      sources: document.querySelector('input[name=s]:checked').value, token: token });
    fetch('/api/scan?' + q.toString()).then(function (r) { return r.json().then(function (j) { return [r.status, j]; }); })
      .then(function (pair) {
        var code = pair[0], j = pair[1]; go.disabled = false; status.textContent = '';
        if (code !== 200) { status.textContent = T[j.error] || (T.error + ': ' + (j.detail || j.error || code)); return; }
        var s = j.summary;
        out.appendChild(el('h2', T.found + ' (' + j.accounts.length + ')'));
        if (!j.accounts.length) out.appendChild(el('p', T.none));
        j.accounts.forEach(function (r) { out.appendChild(card(r, r.identity_confidence ? T.grade + ' ' + r.identity_confidence : '')); });
        if (j.unconfirmed.length) { out.appendChild(el('h2', T.unconfirmed)); j.unconfirmed.forEach(function (r) { out.appendChild(card(r)); }); }
        out.appendChild(el('p', s.answered + ' ' + T.answered + '.', 'dim'));
        if (s.unanswered) out.appendChild(el('p', s.unanswered + ' ' + T.unanswered, 'note dim'));
        if (j.left_out.length) out.appendChild(el('p', j.left_out.length + ' ' + T.left_out, 'dim'));
      }).catch(function (e) { go.disabled = false; status.textContent = T.error + ': ' + e; });
  });
})();
</script>
</body>
</html>
"""


def render(lang: str, token: str) -> str:
    """The page in one language. Every word is escaped; the words the script
    needs travel as JSON."""
    lang = lang if lang in i18n.TEXT else "en"
    t = i18n.words(lang)
    page = _PAGE.replace("__LANG__", lang).replace("__DIR__", "rtl" if lang in i18n.RTL else "ltr")
    options = "".join(f'<option value="{code}"{" selected" if code == lang else ""}>{html.escape(name)}</option>'
                      for code, name in i18n.LANGUAGES.items())
    page = page.replace("__LANG_OPTIONS__", options).replace("__VERSION__", html.escape(__version__))
    page = page.replace("__TOKEN__", token)
    page = page.replace("__WORDS__", json.dumps(t, ensure_ascii=False).replace("<", "\\u003c"))
    for key, value in t.items():
        page = page.replace(f"__T_{key}__", html.escape(value, quote=True))
    return page


def _local(request: web.Request) -> bool:
    host = (request.headers.get("Host") or "").rsplit(":", 1)[0].lower()
    return host in _LOCAL_HOSTS


def make_app(token: Optional[str] = None, scan=api.scan) -> web.Application:
    token = token or secrets.token_urlsafe(24)

    @web.middleware
    async def local_only(request, handler):
        if not _local(request):
            return web.json_response({"error": "local only"}, status=403)
        response = await handler(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    async def index(request):
        lang = request.query.get("lang") or i18n.pick(request.headers.get("Accept-Language", ""))
        return web.Response(text=render(lang, token), content_type="text/html", headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                       "script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; "
                                       "form-action 'none'; frame-ancestors 'none'"})

    async def run_scan(request):
        if not secrets.compare_digest(request.query.get("token", ""), token):
            return web.json_response({"error": "bad token"}, status=403)
        sources = request.query.get("sources", "builtin")
        try:
            report = await scan(request.query.get("username", ""), sources=sources,
                                purpose=request.query.get("purpose", ""),
                                nsfw=request.query.get("nsfw") == "1")
        except api.LeftOut:
            return web.json_response({"error": "refused"}, status=403)
        except ValueError as e:
            return web.json_response({"error": "invalid", "detail": str(e)}, status=400)
        if request.query.get("full") != "1":
            report = {k: v for k, v in report.items() if k != "results"}
        return web.json_response(report)

    app = web.Application(middlewares=[local_only])
    app[TOKEN] = token
    app.add_routes([web.get("/", index), web.get("/api/scan", run_scan)])
    return app


def serve(port: int = DEFAULT_PORT) -> None:
    app = make_app()
    print(f"  Helix is at http://127.0.0.1:{port}/  (this computer only; Ctrl+C stops it)")
    print(f"  API token: {app[TOKEN]}")
    web.run_app(app, host="127.0.0.1", port=port, print=None)
