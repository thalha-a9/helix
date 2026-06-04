"""
Helix — Local Heuristic False Positive Engine  v3.2
Hardened false-positive prevention with 7 detection layers:
  1. WAF / CAPTCHA page detection
  2. Registration / username-availability API trap detection
  3. Soft-404 content detection (error page served as 200 OK)
  4. Bad redirect path detection (login, search, about, 404 paths)
  5. Dead / parked site detection
  6. Generic title / login page detection
  7. Username format pre-validation per platform
"""
import re
from urllib.parse import urlparse
from typing import Tuple, List, Optional

# ── Score thresholds ──────────────────────────────────────────────────────────
_THRESHOLD_NORMAL = 60    # standard results
_THRESHOLD_HIGH   = 85    # og_meta high-confidence results (stricter)

# ── Score weights ─────────────────────────────────────────────────────────────
_SCORE_WAF              = 100   # instant purge: bot-challenge page
_SCORE_REG_API          = 100   # instant purge: registration availability API
_SCORE_SOFT_404         = 100   # instant purge: explicit not-found content
_SCORE_BAD_REDIRECT     = 90    # very strong: landed on login/search/about/404
_SCORE_DEAD_SITE        = 100   # instant purge: parked/dead domain
_SCORE_GENERIC          = 65    # single generic title = purge at normal threshold
_SCORE_SUBSTRING        = 65
_SCORE_LOGIN            = 45
_SCORE_ERROR            = 60
_SCORE_NO_TITLE_LOW     = 25
_SCORE_USER_ABSENT      = 10
_SCORE_EXT_SOURCE       = 8
_SCORE_NO_TITLE_WMN     = 50    # no og:title + WMN/Sherlock source = very suspicious
_SCORE_API_URL_LOW      = 35    # API URL with confidence=low (body not validated)

# ── Layer 1: WAF / CAPTCHA signatures ────────────────────────────────────────
_WAF_SIGNATURES = [
    "just a moment...", "checking your browser",
    "enable javascript and cookies", "ddos protection by cloudflare",
    "attention required!", "incapsula incident",
    "please verify you are a human", "cf-challenge",
    "challenge-platform", "security check", "are you a human",
    "bot protection", "access denied by", "ray id",
]

# ── Layer 2: Registration/availability API trap patterns ──────────────────────
# These URLs return 200 to mean "username is FREE to register",
# NOT that a profile exists. Matching any of these → instant purge.
_REGISTRATION_API_PATTERNS = [
    "checkusername",
    "check-username",
    "check_username",
    "username-available",
    "username_available",
    "/username/available",
    "validate/username",
    "user/exist/",
    "/accounts/lookup",
    "2017-06-30/users",          # Duolingo availability API
    "api-proxy/bbc/get",         # BodyBuilding.com
    "api/accounts/validate",     # BoardGameGeek
    "api/v4/users?username=",    # GitLab API (empty array = not found)
    "api/v1/accounts/lookup",    # Mastodon instances
    "wp-json/wporg/v1/username", # WordPress.org availability
    "GetCard/",                  # visnesscard
    "tapitag/api/v1/",           # TAPiTAG — RF number, not user profile
    "api/user/exist/",           # TryHackMe
    "/graphql",                  # GraphQL availability endpoints
    "NickAvailability",          # Znanija — isAvailable:false ≠ profile exists
    "operationName=NickAvailability",
]

# ── Layer 3: Soft-404 content strings ────────────────────────────────────────
# Sites that serve "not found" pages with HTTP 200.
_SOFT_404_MARKERS = [
    "not found", "page not found", "user not found", "profile not found",
    "usuario no encontrado", "utilisateur introuvable",
    "this username does not exist", "this account does not exist",
    "sorry, this user was not found", "there is nothing to see here",
    "nothing to see here", "page no longer exists",
    "player not found", "member not found",
    "sorry, that page doesn't exist", "sorry, we couldn't find",
    "we couldn't find this page", "we looked everywhere",
    "couldn't find this account", "this page isn't available",
    "this page doesn't exist", "error 404", "http 404",
    "404 not found", '"users":[]', '"data":""', '"data":[]',
    '"available":true',           # availability API → means NOT registered
    '"valid":false',              # X/Twitter format-rejection
    '"isValid":false',            # BGG
    '"msg":"invalid username"',   # Scratch
    '"exists":false',
    '"registered":false',
    "invalid username", "improper_format",
    "rip 2004", "rip, this page",  # dead sites
    # Specific platforms known to soft-404
    "usuario no encontrado",       # Arsmate
    "404 - page not found",
    "the page you requested was not found",
    '"isavailable":true',
    '"isavailable": true',
    "no user found",
    "this user doesn't exist",
    "we can't find the page",
    # Tinder
    "may have changed their id",
    "person you're looking for",
    # eBay
    "sorry, this user was not found",
    "this user was not found",
    # Brickset / Weblate / PyPI / Minecraft List
    "brickset.com/404",
    "page not found",
    "player not found",
    # getmonero
    "the user you requested does not exist",
    # MyFitnessPal empty author
    "no posts found",
    # PayPal.Me
    "something went wrong",
    # eBay specific
    "we looked everywhere and couldn",
    "we couldn't find the page",
    "this page isn't available",
    # dot.cards
    "this username does not exist",
    # Weblate
    "this user does not exist",
    # Brickset
    "brickset.com does not have a member",
    # Minecraft List
    "we could not find this player",
    # Arsmate
    "no se ha encontrado",
    # PyPI (user with no packages)
    "we looked everywhere but couldn",
    # Generic forum empty
    "has no posts",
    "0 posts",
    "no results found",
    "invalid user",
    "error: invalid user",
    "user not found",
    "this user does not exist",
]

# ── Layer 4: Bad redirect paths ───────────────────────────────────────────────
# If the final URL after redirects lands on one of these paths, the
# original profile URL doesn't exist — the server bounced the request.
_BAD_REDIRECT_PATHS = [
    "/404", "/not-found", "/not_found", "/notfound",
    "/error", "/errors",
    "/login", "/signin", "/sign-in", "/auth/login", "/auth/signin",
    "/sign-in-register", "/signup", "/sign-up", "/join", "/register",
    "/p/register.cgi",
    "/dashboard",                 # 247CTF sends missing profiles here
    "/search",                    # Adobe Community, Voices.com
    "/about", "/about/",          # Engadget sends missing editors here
    "/home", "/index", "/",
]

# ── Layer 5: Dead / parked site markers ──────────────────────────────────────
_DEAD_SITE_MARKERS = [
    "something new is coming", "site is shut down",
    "parked by godaddy", "this domain is for sale",
    "domain is parked", "buy this domain",
    "under construction", "coming soon",
    "we're working on something", "website is under maintenance",
    "server not found", "this site can't be reached",
    "err_name_not_resolved", "err_cert_common_name_invalid",
]

# ── Layer 5b: Hosts that are login-gated or CAPTCHA-blocked — always skip ────
# These will NEVER produce a verifiable result without an authenticated session.
_GATE_BLOCKED_HOSTS = {
    "bentbox.co",              # age-verify gate for all visitors
    "my.flightradar24.com",    # login required to view profiles
    "vivino.com",              # login required
    "magix.info",              # login required
    "forum.igromania.ru",      # CAPTCHA / login
    "forum.3dnews.tech",       # CAPTCHA / login
    "livemaster.ru",           # CAPTCHA block
    "blog.myfitnesspal.com",   # empty author page = always false positive
    "kwork.ru",                # login / maintenance redirect
    "paypal.com",              # paypal.me CAPTCHA fires on any URL, real or not
    "tinder.com",              # login gate, no verifiable profile page
    "zbiornik.com",            # adult login gate
    "voices.com",              # redirects to talent search for missing profiles
    "3dnews.tech",             # CAPTCHA / login (alias)
    "igromania.ru",            # CAPTCHA / login (alias)
    "slideshare.net",          # page no longer exists — all missing users 200
    "scribd.com",              # search results page, not a profile
    "ddosecrets.com",          # redirects to unrelated domain
    "hubski.com",              # login gate
    "ixbt.com",                # Russian forum login gate
    "kaggle.com",              # status_code only, soft-404s extensively
    "op.gg",                   # OP.GG search pages — same result for any query
    "faceit.com",              # login gate
    "truelancer.com",          # false positive for all usernames
    "exploretalent.com",       # false positive
    "freelancebay.com",        # false positive
    # Russian/obscure forums — status_code only, always 200 regardless of user
    "forum24.ru",              # alabay, kuban, jer, microcap, uaksu, volkodavcaoko
    "borda.ru",                # rodgersforum, starsonice, terminatorium
    "forum.rzn.info",          # Russian city forum
    "doublecmd.h1n.ru",        # small Russian forum
    "induste.com",             # status_code FP
    "moto-arena.ru",           # Russian moto forum
    "siava.ru",                # Russian forum
    "chelfishing.ru",          # Russian fishing forum
    "moto26.ru",               # Russian moto forum
    "mitsubishi-asx.net",      # Russian car forum
    "fkclub.ru",               # Russian forum
    "forum.palemoon.org",      # open registration, username = 200 even if absent
    "forums.scummvm.org",      # same
    "onanizm.club",            # adult Russian forum
    "forum.ignitioncasino.eu", # casino forum login gate
    "indiatv-forum.ru",        # Russian TV forum
    "syberpussy.com",          # adult, login gate
    "mailpass.site",           # credential leak site, always 200
    "forum.rastrnet.ru",       # Russian ISP forum
    "awd.ru",                  # search page — not a profile URL
    "astro-talks.ru",          # search page — not a profile URL
    "forum-ukraina.net",       # Ukrainian forum, status_code FP
    "politforums.net",         # Russian politics, param-based not a profile
    "xss.is",                  # hacker forum, login required to view profiles
    "forums.drom.ru",          # Russian car forum
    "forumsdrom.ru",           # same
    "l2bz.ru",                 # Russian gaming forum
    "kashanya.com",            # Russian site, status_code FP
    "rcprim.ru",               # Russian RC forum
    "radioskot.ru",            # Russian electronics forum
    "stalker-zone.info",       # Russian gaming, status_code FP
    "porevo.site",             # adult site
    "allmy.link",              # link-in-bio service, FP for all
    "bigo.tv",                 # login gate for profiles
    "chitalnya.ru",            # Russian literature, status_code FP
    "viddler.com",             # dead/legacy platform
    "ulub.pl",                 # Polish video, status_code FP
    "nokia-love.ru",           # dead Russian Nokia forum
    "elektrik-avto.ru",        # Russian EV forum
    "en.brickimedia.org",      # wiki — any username creates a page
    "milliarderr.com",         # Russian finance, status_code FP
    "ucozon.ru",               # Russian, status_code FP
    "vilinburg.net",           # Russian, status_code FP
    "aquamen.ru",              # Russian, status_code FP
    "tavr-obrazovanie.ru",     # Russian education, status_code FP
    "specchiasol.ru",          # Russian, status_code FP
    "teplohorosho.ru",         # Russian, status_code FP
    "dumskaya.net",            # Ukrainian news forum
    "maga-chat.com",           # political chat, login gate
    "iknifecollector.com",     # param-based URL, not a real profile
    "gta-multiplayer.cz",      # gaming, status_code FP
    "honda.org.ua",            # Ukrainian Honda forum
    "flashflashrevolution.com",# gaming, status_code FP
    "fotki.com",               # dead/legacy photo platform
    "gurushots.com",           # login gate for profiles
    "hackingwithswift.com",    # forum profile, status_code FP
    "forums.grandstream.com",  # VoIP forum, status_code FP
    "dlive.tv",                # streaming, login gate
    "beatstars.com",           # music, login gate for profiles
    "funnyjunk.com",           # meme site, status_code FP
    "lesswrong.com",           # rationalist forum, status_code FP
    "planetaexcel.ru",         # Russian Excel forum, param-based
    "tbank.ru",                # Russian bank invest social, login gate
    "pravda.me",               # Mastodon-like, status_code FP
    "social.bund.de",          # German govt Mastodon, status_code FP
    "hey.xyz",                 # web3 social, status_code FP
    "quitter.pl",              # GNU social, login gate
    "hackernoon.com",          # status_code FP for all usernames
    "refsheet.net",            # furry art, status_code FP
    "zmey.ru",                 # Russian, status_code FP
    "russian.fi",              # Russian community Finland, status_code FP
    "artstation.com",          # dots invalid in username (format mismatch)
    "ebay.com",                # JS soft-404
    "minecraftlist.com",       # player not found as 200
    "learn.microsoft.com",     # Microsoft Learn, status_code FP
    "yandex.ru",               # Yandex API endpoints
    "wego.social",             # parked/dead
    "ultrasdiary.pl",          # dead
    "guru.com",                # freelancer search, not profile
    "livetrack24.com",         # login gate
    "sports-tracker.com",      # login gate
    "google.com",              # Google Maps contributor — not a real profile URL
    "yelp.com",                # userid param — not a real profile
    "touristlink.com",         # false positive
    "anime-planet.com",        # returns page for any username
    "tvtropes.org",            # wiki — any username creates a page
    "carmasters.org",          # search page
    "nightbot.tv",             # no profile for non-existent users but 200
    "revolut.me",              # login/payment gate
    "soundgym.co",             # param-based, always 200
    "paltalk.com",             # login gate
    "fanscout.com",            # false positive
    "listography.com",         # false positive
    "linkkle.com",             # link-in-bio false positive
    "beacons.ai",              # link-in-bio false positive
    "otechie.com",             # false positive
    "airnfts.com",             # NFT platform false positive
    "freepo.st",               # old CGI false positive
    "bitpapa.com",             # crypto P2P false positive
    # Sherlock false positives — status_code only, dot/underscore usernames not supported
    "pr0gramm.com",            # German site, rejects non-ASCII-compatible usernames
    "anilist.co",              # username validation rejects dots
    "discussions.apple.com",   # Apple requires AppleID format
    "archive.org",             # soft-404 as 200 for invalid usernames
    "mercadolivre.com.br",     # soft-404 as 200
    "hashnode.com",            # @ usernames don't support dots+underscores
    "authorstream.com",        # dead/legacy platform
    "cssbattle.dev",           # status_code only, false positive
    "dailymotion.com",         # soft-404 as 200
    "forum.velomania.ru",      # Russian forum, CAPTCHA/login gate
    "kaskus.co.id",            # Indonesian forum, soft-404
    "kik.me",                  # Kik profiles not publicly accessible
    "codolio.com",             # status_code only, false positive
    "splice.com",              # status_code only, music platform false positive
    "academia.edu",            # login gate
    "pypi.org",                # already in dead hosts but ensure gate catches sherlock too
    "minds.com",               # Sherlock status_code FP
    "opennet.ru",              # Russian tech forum, login/CAPTCHA gate
    "duolingo.com",            # availability API (profile/ path still soft-404s)
    "hosted.weblate.org",      # already in dead hosts WMN, catch from Sherlock too
    "xhamster.com",            # adult platform, login gate for all profiles
    "gitlab.gnome.org",        # GNOME GitLab, soft-404 as 200 for missing users
    "gitlab.freedesktop.org",  # same pattern
    "patriots.win",            # "invalid user" served as 200 OK
}


def _is_gate_blocked_host(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return any(g in host for g in _GATE_BLOCKED_HOSTS)
    except Exception:
        return False

# ── Layer 6: Generic titles (existing verifier, keep) ────────────────────────
_GENERIC_TITLES = {
    "instagram","facebook","tiktok","twitter","x","linkedin","pinterest",
    "snapchat","reddit","tumblr","medium","youtube","twitch","patreon",
    "github","ko-fi","substack","spotify","soundcloud","replit","steam",
    "discord","telegram","vk","mastodon","bluesky","threads","quora",
    "bandcamp","vimeo","flickr","wattpad","lichess","chess.com",
    "keybase","gravatar","linktree","carrd","peerlist",
}

_GENERIC_SUBSTRINGS = [
    "where good ideas find you", "out of nothing, something",
    "medium – get smarter about what matters",
    "support the people and projects you love",
    "the only link you'll ever need",
    "discover recipes, home ideas, style inspiration",
    "log in to instagram", "log in • instagram",
    "log into facebook", "facebook – log in or sign up",
    "tiktok - make your day", "linkedin: log in or sign up", "join linkedin",
    "sign up for reddit", "reddit – dive into anything",
    "reddit - the front page of the internet",
    "download the app", "create an account",
    "we looked everywhere but couldn't find this page",
    "we're sorry. we couldn't find the page",
    "page not found", "404 not found", "this page doesn't exist",
    "this page isn't available", "something went wrong",
    "access denied", "403 forbidden",
    "account suspended", "account doesn't exist",
    "user not found", "profile not found", "no such user",
    "this account doesn't exist", "couldn't find this page",
    "sorry, that something isn", "replit – build software collaboratively",
    "spotify – web player: music for everyone",
    "create your snapchat today",
    "join the conversation",
    "something new is coming", "rip 2004", "parked by godaddy",
    "this domain is for sale", "domain is parked", "under construction",
]

_LOGIN_KEYWORDS = [
    "log in", "login", "sign in", "sign up", "register",
    "create account", "join now", "get started", "create your account",
]

_ERROR_KEYWORDS = [
    "not found", "doesn't exist", "does not exist",
    "no longer available", "has been removed", "was deleted",
    "suspended", "deactivated", "unavailable",
    "error 404", "http 404", "page 404",
]

# ── Layer 7: Per-platform username format rules ───────────────────────────────
# If the username fails a platform's own format rule, ANY result is impossible.
_PLATFORM_USERNAME_RULES: dict = {
    # pattern must FULLY match (re.fullmatch)
    "Twitter/X":              re.compile(r'^[A-Za-z0-9_]{1,15}$'),
    "WordPress.org (Forums)": re.compile(r'^[a-z0-9]{1,60}$'),
    "WordPress.org (Profiles)":re.compile(r'^[a-z0-9]{1,60}$'),
    "Scratch":                re.compile(r'^[a-zA-Z0-9_\-]{3,20}$'),
    "BoardGameGeek":          re.compile(r'^[a-zA-Z][a-zA-Z0-9_\-]{2,}$'),
    "ArtStation":             re.compile(r'^[a-zA-Z0-9_]{3,63}$'),  # dots invalid
    "PyPI":                   re.compile(r'^[A-Za-z0-9]([A-Za-z0-9._\-]*[A-Za-z0-9])?$'),
    "npm":                    re.compile(r'^[a-z0-9][a-z0-9._\-]{0,213}$'),
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_registration_api_url(url: str) -> bool:
    """Return True if this URL is a username-availability / registration check endpoint."""
    u = url.lower()
    return any(p in u for p in _REGISTRATION_API_PATTERNS)


def _has_soft_404_content(html_or_api: str) -> bool:
    """Return True if page body explicitly says the user doesn't exist."""
    if not html_or_api:
        return False
    t = html_or_api.lower()[:8000]
    return any(m in t for m in _SOFT_404_MARKERS)


def _has_waf_content(text: str) -> bool:
    if not text:
        return False
    t = text[:3000].lower()
    return any(sig in t for sig in _WAF_SIGNATURES)


def _is_dead_site(text: str) -> bool:
    if not text:
        return False
    t = text.lower()[:4000]
    return any(m in t for m in _DEAD_SITE_MARKERS)


def _is_bad_redirect(original_url: str, final_url: str) -> bool:
    """Return True if the final URL after redirect landed on a known bad path."""
    if not final_url or not original_url or final_url == original_url:
        return False
    try:
        r = urlparse(original_url)
        f = urlparse(final_url)
        # Cross-domain redirect → always suspicious
        if r.netloc and f.netloc and r.netloc != f.netloc:
            # Exception: CDN redirects for confirmed profiles (e.g. Instagram CDN)
            if "cdninstagram" in f.netloc or "fbcdn" in f.netloc:
                return False
            return True
        path = f.path.rstrip("/").lower() or "/"
        # Exact bad path match
        if path in _BAD_REDIRECT_PATHS:
            return True
        # Prefix match for paths like /auth/login/...
        for bad in _BAD_REDIRECT_PATHS:
            if bad and len(bad) > 1 and path.startswith(bad):
                return True
    except Exception:
        pass
    return False


def _username_valid_for_platform(username: str, platform_name: str) -> Tuple[bool, str]:
    """
    Check whether `username` satisfies `platform_name`'s own format rules.
    Returns (is_valid, reason_string).
    """
    rule = _PLATFORM_USERNAME_RULES.get(platform_name)
    if rule is None:
        return True, ""
    if rule.fullmatch(username):
        return True, ""
    return False, f"username '{username}' violates {platform_name} format rules — result impossible"


def _is_homepage_redirect(req: str, final: str) -> bool:
    if not final or not req or final == req:
        return False
    try:
        r = urlparse(req); f = urlparse(final)
        if r.netloc != f.netloc:
            return True
        home = {"", "/", "/home", "/index", "/index.html",
                "/login", "/signin", "/signup", "/register", "/join"}
        return f.path.rstrip("/").lower() in home
    except Exception:
        return False


# ── Core scoring ──────────────────────────────────────────────────────────────

def _compute_score(og_title: str, url: str, final_url: str,
                   confidence: str, source: str, username: str,
                   page_text: str = "",
                   skip_missing_title: bool = False) -> Tuple[int, List[str]]:
    """Pure scoring logic. Returns (score, reasons)."""
    score   = 0
    reasons: List[str] = []
    t = og_title.lower().strip()
    u = username.lower()

    # ── Layer 1: WAF / CAPTCHA ────────────────────────────────────────────────
    if _has_waf_content(page_text) or (t and any(w in t for w in _WAF_SIGNATURES)):
        score += _SCORE_WAF
        reasons.append("WAF/CAPTCHA page detected — bot-check served as 200 OK")
        return score, reasons   # no point scoring further

    # ── Layer 2: Registration API trap ────────────────────────────────────────
    if _is_registration_api_url(url):
        score += _SCORE_REG_API
        reasons.append(
            f"registration/availability API URL — HTTP 200 means username is FREE, "
            f"not that a profile exists ({url[:80]})"
        )
        return score, reasons

    # ── Layer 3: Soft-404 content ─────────────────────────────────────────────
    if page_text and _has_soft_404_content(page_text):
        score += _SCORE_SOFT_404
        reasons.append("page body contains explicit not-found / user-absent content")
        return score, reasons

    # ── Layer 4: Bad redirect path ────────────────────────────────────────────
    if _is_bad_redirect(url, final_url):
        score += _SCORE_BAD_REDIRECT
        reasons.append(f"redirected to bad path: {final_url[:80]}")

    # ── Layer 5b: Login-gated / CAPTCHA-blocked host ──────────────────────────
    if _is_gate_blocked_host(url):
        score += _SCORE_DEAD_SITE
        reasons.append("login-gate or CAPTCHA-blocked host — result unverifiable")
        return score, reasons

    # ── Layer 5: Dead / parked site ───────────────────────────────────────────
    if page_text and _is_dead_site(page_text):
        score += _SCORE_DEAD_SITE
        reasons.append("dead or parked domain")
        return score, reasons

    # ── Layer 6: Generic title / login / error detection (original logic) ─────
    if t and t in _GENERIC_TITLES:
        score += _SCORE_GENERIC
        reasons.append(f"platform-name title only: '{t}'")

    for sub in _GENERIC_SUBSTRINGS:
        if t and sub in t:
            score += _SCORE_SUBSTRING
            reasons.append(f"generic page text: '{t[:60]}'")
            break

    for kw in _LOGIN_KEYWORDS:
        if t and kw in t:
            score += _SCORE_LOGIN
            reasons.append(f"login page: '{t[:60]}'")
            break

    for kw in _ERROR_KEYWORDS:
        if t and kw in t:
            score += _SCORE_ERROR
            reasons.append(f"error page: '{t[:60]}'")
            break

    if not skip_missing_title and not t and confidence == "low":
        score += _SCORE_NO_TITLE_LOW
        reasons.append("no og:title on low-confidence result")

    if not skip_missing_title and t and u not in t and confidence == "low":
        score += _SCORE_USER_ABSENT

    if _is_homepage_redirect(url, final_url):
        score += _SCORE_ERROR
        reasons.append(f"redirected to homepage: {final_url[:60]}")

    if source in ("sherlock", "wmn") and confidence == "low":
        score += _SCORE_EXT_SOURCE

    if not og_title and source in ("sherlock", "wmn"):
        score += _SCORE_NO_TITLE_WMN
        if not skip_missing_title:
            reasons.append("no og:title on WMN/Sherlock result (likely API or dead page)")

    # API-pattern URL with confidence=low (body wasn't validated beyond status code)
    _api_pats = [
        "/api/", "?username=", "/wp-json/", "_json", "checkusername",
        "validate/username", "user/exist/", "/accounts/lookup",
        "username_available", "2017-06-30/users", "api-proxy", "check-username",
    ]
    if confidence == "low" and any(p in url for p in _api_pats):
        score += _SCORE_API_URL_LOW
        reasons.append("API-pattern URL with unvalidated status_code check")

    return score, reasons


def _score_result(result: dict, username: str) -> Tuple[bool, str, int]:
    og_title   = (result.get("og_title")  or "").lower().strip()
    confidence = result.get("confidence", "low")
    url        = result.get("url",        "") or ""
    final_url  = result.get("final_url",  "") or ""
    source     = result.get("source",     "builtin")
    page_text  = result.get("_page_text", "")  # populated by checker when available
    platform   = result.get("platform",   "")

    # ── Layer 7: username format pre-validation ───────────────────────────────
    valid, fmt_reason = _username_valid_for_platform(username, platform)
    if not valid:
        return True, fmt_reason, 100

    if confidence == "high":
        score, reasons = _compute_score(
            og_title, url, final_url, confidence, source, username,
            page_text=page_text,
            skip_missing_title=True,
        )
        is_fp  = score >= _THRESHOLD_HIGH
        reason = "; ".join(reasons) if reasons else ""
        return is_fp, reason, score

    score, reasons = _compute_score(
        og_title, url, final_url, confidence, source, username,
        page_text=page_text,
    )
    is_fp  = score >= _THRESHOLD_NORMAL
    reason = "; ".join(reasons) if reasons else ""
    return is_fp, reason, score


def run_local_verifier(results: List[dict], username: str) -> Tuple[List[dict], List[dict]]:
    """
    Run the 7-layer false-positive engine over all results.
    Modifies results in-place (found=False on purged entries).
    Returns (results, purge_log).
    """
    purge_log = []
    for r in results:
        if not r.get("found"):
            continue
        is_fp, reason, score = _score_result(r, username)
        if is_fp:
            r["found"]    = False
            r["error"]    = f"heuristic_purge: {reason}"
            r["fp_score"] = score
            purge_log.append({
                "platform": r["platform"],
                "reason":   reason,
                "score":    score,
            })
    return results, purge_log
