"""
Helix v2.0 — Platform Definitions
Detection methods: og_meta | text_not_present | text_present | status_code | api_json
check_url: separate URL for HTTP probe (API endpoint) vs url (display link)
"""

_BIO_PATTERNS_DEVELOPER = {
    "twitter":   r"(?:twitter|x)\.com/([a-zA-Z0-9_]{1,50})",
    "linkedin":  r"linkedin\.com/in/([a-zA-Z0-9_\-]{1,100})",
    "instagram": r"instagram\.com/([a-zA-Z0-9_.]{1,50})",
    "youtube":   r"youtube\.com/(?:@|c/|user/)?([a-zA-Z0-9_\-]{1,100})",
    "medium":    r"medium\.com/@([a-zA-Z0-9_\-]{1,50})",
    "devto":     r"dev\.to/([a-zA-Z0-9_\-]{1,50})",
    "website":   r"(https?://(?!github\.com|linkedin\.com|twitter\.com|x\.com)[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}[^\s\"\'<>]*)",
}

_BIO_PATTERNS_SOCIAL = {
    "github":   r"github\.com/([a-zA-Z0-9_\-]{1,100})",
    "linkedin": r"linkedin\.com/in/([a-zA-Z0-9_\-]{1,100})",
    "youtube":  r"youtube\.com/(?:@|c/|user/)?([a-zA-Z0-9_\-]{1,100})",
    "website":  r"(https?://(?!twitter\.com|x\.com|instagram\.com)[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}[^\s\"\'<>]*)",
}

PLATFORMS = {

    # ── Social ─────────────────────────────────────────────────────────────────
    "Twitter/X": {
        "url":             "https://x.com/{username}",
        "method":          "text_not_present",
        "not_found_text":  "This account doesn\u2019t exist",
        "tls_impersonate": True,
        "category": "social", "color": "#1DA1F2",
        "bio_patterns": _BIO_PATTERNS_SOCIAL, "bio_extract": True,
    },
    "Instagram": {
        "url": "https://www.instagram.com/{username}/",
        "method": "text_not_present", "not_found_text": "Page Not Found",
        "tls_impersonate": True, "requires_tls": True,
        "category": "social", "color": "#E1306C",
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{username}",
        "method": "text_not_present", "not_found_text": "Couldn\u2019t find this account",
        "tls_impersonate": True,
        "category": "social", "color": "#010101",
    },
    "Facebook": {
        "url": "https://www.facebook.com/{username}",
        "method": "text_not_present", "not_found_text": "The link you followed may be broken",
        "tls_impersonate": True, "requires_tls": True,
        "category": "social", "color": "#1877F2",
    },
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{username}",
        "method": "text_not_present", "not_found_text": "Page not found",
        "tls_impersonate": True,
        "category": "social", "color": "#0A66C2",
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{username}/",
        "method": "og_meta",
        "og_not_found": ["Page Not Found", "Pinterest – The world"],
        "category": "social", "color": "#E60023",
    },
    "Snapchat": {
        "url": "https://www.snapchat.com/add/{username}",
        "method": "og_meta", "og_found": ["{username}"],
        "category": "social", "color": "#FFFC00",
    },
    "Tumblr": {
        "url": "https://{username}.tumblr.com/",
        "method": "text_not_present", "not_found_text": "There\u2019s nothing here",
        "category": "social", "color": "#35465C",
    },
    "Mastodon": {
        "url": "https://mastodon.social/@{username}",
        "method": "og_meta", "og_not_found": ["Page not found", "Error 404"],
        "category": "social", "color": "#6364FF",
    },
    "Bluesky": {
        # SPA — static HTML never contains "Profile not found". Use AT Protocol API instead.
        "url":       "https://bsky.app/profile/{username}.bsky.social",
        "check_url": "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={username}.bsky.social",
        "method": "status_code", "found": [200],
        "category": "social", "color": "#0085FF",
    },
    "Threads": {
        "url": "https://www.threads.com/@{username}",
        "method": "text_not_present", "not_found_text": "isn\u2019t available",
        "tls_impersonate": True,
        "category": "social", "color": "#000000",
    },
    "VK": {
        "url": "https://vk.com/{username}",
        "method": "text_not_present", "not_found_text": "Page not found",
        "category": "social", "color": "#4C75A3",
    },
    "Telegram": {
        # Telegram og:title for existing = "Telegram: Contact @{username}"
        # For non-existent = "Telegram: Contact @{username}" BUT page body says "If you have Telegram, you can contact" — unreliable
        # Better: check for specific text that only appears on valid profiles
        "url": "https://t.me/{username}",
        "method": "text_present", "found_text": "tgme_page_extra",
        "category": "social", "color": "#26A5E4",
    },

    # ── Developer / Security ───────────────────────────────────────────────────
    "GitHub": {
        "url": "https://github.com/{username}",
        "method": "og_meta", "og_not_found": ["Page not found", "Not Found"],
        "category": "dev", "color": "#f0f6fc",
        "bio_extract": True, "bio_patterns": _BIO_PATTERNS_DEVELOPER,
    },
    "GitLab": {
        # Groups share the user URL space (gitlab.com/torvalds is a group), so
        # the profile page cannot tell them apart. The users API only returns
        # real user accounts — a group or a missing name returns [].
        "url": "https://gitlab.com/{username}",
        "check_url": "https://gitlab.com/api/v4/users?username={username}",
        "method": "text_present", "found_text": '"username":"{username}"',
        "category": "dev", "color": "#FC6D26",
    },
    "HackerNews": {
        "url": "https://news.ycombinator.com/user?id={username}",
        "method": "text_not_present", "not_found_text": "No such user",
        "category": "dev", "color": "#FF6600",
    },
    "HackerOne": {
        "url": "https://hackerone.com/{username}",
        "method": "og_meta", "og_not_found": ["Page Not Found", "404"],
        "category": "dev", "color": "#494649",
    },
    "Bugcrowd": {
        "url": "https://bugcrowd.com/{username}",
        "method": "og_meta", "og_not_found": ["Page not found"],
        "category": "dev", "color": "#F26822",
    },
    "Replit": {
        # Valid user og:title = "@username – Replit"
        # Invalid/homepage = "Replit" (caught by GENERIC_TITLES in verifier)
        # og_found check is the primary signal — title MUST contain @username
        "url": "https://replit.com/@{username}",
        "method": "og_meta",
        "og_found": ["@{username}"],  # only og_found — no og_not_found clash
        "category": "dev", "color": "#F26207",
    },
    "Codepen": {
        "url": "https://codepen.io/{username}",
        "method": "og_meta", "og_not_found": ["CodePen", "doesn't exist"],
        "category": "dev", "color": "#AEAEAE",
    },
    "Dev.to": {
        "url": "https://dev.to/{username}",
        "method": "og_meta", "og_not_found": ["Page not found", "404"],
        "category": "dev", "color": "#0A0A0A",
        "bio_extract": True, "bio_patterns": _BIO_PATTERNS_DEVELOPER,
    },
    "StackOverflow": {
        # SO user URLs use numeric IDs — username search is unreliable; skip or use search
        # Use SO's search API as proxy: if username exists in top results, mark found
        "url": "https://stackoverflow.com/users/{username}",
        "method": "text_not_present", "not_found_text": "Page Not Found",
        "category": "dev", "color": "#F58025",
    },
    "npm": {
        "url": "https://www.npmjs.com/~{username}",
        "method": "og_meta", "og_not_found": ["npm | Not found"],
        "category": "dev", "color": "#CB3837",
    },
    "PyPI": {
        # Only flag if user has actually published packages (text_present on project link).
        # Verifier catches "we looked everywhere" WAF/not-found pages automatically.
        "url":        "https://pypi.org/user/{username}/",
        "method":     "text_present",
        "found_text": "pypi.org/project/",
        "category": "dev", "color": "#3775A9",
    },
    "Bitbucket": {
        "url": "https://bitbucket.org/{username}",
        "method": "og_meta", "og_not_found": ["Page not found"],
        "category": "dev", "color": "#0052CC",
    },
    "Sourceforge": {
        "url": "https://sourceforge.net/u/{username}/profile/",
        "method": "text_not_present", "not_found_text": "Page Not Found",
        "category": "dev", "color": "#FF6600",
    },

    # ── Content / Creative ─────────────────────────────────────────────────────
    "YouTube": {
        "url": "https://www.youtube.com/@{username}",
        "method": "og_meta", "og_not_found": ["404", "This page isn"],
        "category": "content", "color": "#FF0000",
    },
    "Twitch": {
        "url": "https://www.twitch.tv/{username}",
        "method": "og_meta", "og_found": ["{username}"],
        "category": "content", "color": "#9146FF",
    },
    "Medium": {
        # Non-existent redirects to homepage: og:title = "Medium – Where good ideas find you"
        # Also catches: "Out of nothing, something" (older Medium 404)
        "url": "https://medium.com/@{username}",
        "method": "og_meta",
        "og_not_found": [
            "Where good ideas find you", "Out of nothing, something",
            "Page not found", "404", "Medium – Get smarter",
        ],
        "category": "content", "color": "#000000",
    },
    "Substack": {
        "url": "https://{username}.substack.com",
        "method": "text_not_present", "not_found_text": "This page does not exist",
        "category": "content", "color": "#FF6719",
    },
    "Patreon": {
        "url": "https://www.patreon.com/{username}",
        "method": "og_meta", "og_not_found": ["Page not found"],
        "tls_impersonate": True,
        "category": "content", "color": "#FF424D",
    },
    "Behance": {
        "url": "https://www.behance.net/{username}",
        "method": "og_meta", "og_not_found": ["Page Not Found"],
        "category": "content", "color": "#1769FF",
    },
    "Dribbble": {
        "url": "https://dribbble.com/{username}",
        "method": "og_meta", "og_not_found": ["Dribbble - Page Not Found"],
        "category": "content", "color": "#EA4C89",
    },
    "Flickr": {
        "url": "https://www.flickr.com/people/{username}",
        "method": "text_not_present", "not_found_text": "Page not found",
        "category": "content", "color": "#0063DC",
    },
    "Vimeo": {
        "url": "https://vimeo.com/{username}",
        "method": "og_meta", "og_not_found": ["Vimeo", "Page Not Found"],
        "category": "content", "color": "#1AB7EA",
    },
    "SoundCloud": {
        "url": "https://soundcloud.com/{username}",
        "method": "og_meta", "og_not_found": ["SoundCloud - 404"],
        "category": "content", "color": "#FF5500",
    },
    "Spotify": {
        # Spotify og:title for existing = "{username}'s profile" or display name
        # For non-existent: redirects to homepage or returns generic title
        "url": "https://open.spotify.com/user/{username}",
        "method": "og_meta", "og_not_found": ["Spotify – Web Player", "Page not found"],
        "category": "content", "color": "#1DB954",
    },
    "Bandcamp": {
        "url": "https://bandcamp.com/{username}",
        "method": "text_not_present", "not_found_text": "Sorry, that something isn",
        "category": "content", "color": "#1DA0C3",
    },
    "Wattpad": {
        "url": "https://www.wattpad.com/user/{username}",
        "method": "og_meta", "og_not_found": ["Wattpad | 404"],
        "category": "content", "color": "#FF5A00",
    },

    # ── Gaming ─────────────────────────────────────────────────────────────────
    "Steam": {
        "url": "https://steamcommunity.com/id/{username}",
        "method": "text_not_present", "not_found_text": "The specified profile could not be found",
        "category": "gaming", "color": "#1B2838",
    },
    "Chess.com": {
        # Use Chess.com's public API — returns 404 for non-existent users. Zero false positives.
        "url":       "https://www.chess.com/member/{username}",
        "check_url": "https://api.chess.com/pub/player/{username}",
        "method": "status_code", "found": [200],
        "category": "gaming", "color": "#81B64C",
    },
    "Lichess": {
        # Lichess API returns 404 for non-existent users
        "url":       "https://lichess.org/@/{username}",
        "check_url": "https://lichess.org/api/user/{username}",
        "method": "status_code", "found": [200],
        "category": "gaming", "color": "#FFFFFF",
    },
    "Roblox": {
        "url": "https://www.roblox.com/user.aspx?username={username}",
        "method": "text_not_present", "not_found_text": "Page cannot be found",
        "category": "gaming", "color": "#00A2FF",
    },
    "Itch.io": {
        "url": "https://{username}.itch.io",
        "method": "text_not_present", "not_found_text": "is not a valid",
        "category": "gaming", "color": "#FA5C5C",
    },

    # ── Forums / Community ─────────────────────────────────────────────────────
    "Reddit": {
        # JSON API: valid user returns {"kind":"t2","data":{"name":"...","is_employee":...}}
        # Invalid user returns HTTP 404. Text-present on "is_employee" is 100% reliable.
        "url":       "https://www.reddit.com/user/{username}",
        "check_url": "https://www.reddit.com/user/{username}/about.json",
        "method":    "text_present",
        "found_text": '"is_employee"',   # only present in valid user JSON
        "category": "forum", "color": "#FF4500",
        "bio_extract": True, "bio_patterns": _BIO_PATTERNS_SOCIAL,
    },
    "Quora": {
        "url": "https://www.quora.com/profile/{username}",
        "method": "og_meta", "og_not_found": ["Page Not Found", "Quora"],
        "category": "forum", "color": "#B92B27",
    },
    "ProductHunt": {
        "url": "https://www.producthunt.com/@{username}",
        "method": "og_meta", "og_not_found": ["Page not found"],
        "category": "forum", "color": "#DA552F",
    },
    "Lobsters": {
        "url": "https://lobste.rs/~{username}",
        "method": "text_not_present", "not_found_text": "Unknown user",
        "category": "forum", "color": "#AC130D",
    },

    # ── Professional / Other ───────────────────────────────────────────────────
    "Keybase": {
        "url": "https://keybase.io/{username}",
        "method": "og_meta", "og_not_found": ["Keybase - 404"],
        "category": "other", "color": "#33A0FF",
        "bio_extract": True, "bio_patterns": _BIO_PATTERNS_DEVELOPER,
    },
    "About.me": {
        "url": "https://about.me/{username}",
        "method": "og_meta", "og_not_found": ["about.me | 404"],
        "category": "other", "color": "#00ACED",
    },
    "Gravatar": {
        "url": "https://en.gravatar.com/{username}",
        "method": "text_not_present", "not_found_text": "Ooops",
        "category": "other", "color": "#1E8CBE",
    },
    "Linktree": {
        "url": "https://linktr.ee/{username}",
        "method": "og_meta", "og_not_found": ["Linktree. The Only Link You", "Page Not Found"],
        "category": "other", "color": "#43E55E",
        "bio_extract": True, "bio_patterns": _BIO_PATTERNS_SOCIAL,
    },
    "Ko-fi": {
        # og:title for real user: "Support {name} on Ko-fi!"
        # og:title for non-existent: generic "Ko-fi" (caught by verifier GENERIC_TITLES)
        # Use text_present on profile URL which only appears on real profile pages
        "url": "https://ko-fi.com/{username}",
        "method": "text_present", "found_text": "ko-fi.com/{username}",
        "category": "other", "color": "#FF5E5B",
    },
    "Buy Me a Coffee": {
        "url": "https://www.buymeacoffee.com/{username}",
        "method": "og_meta", "og_not_found": ["Page not found", "404"],
        "category": "other", "color": "#FFDD00",
    },
    "Carrd": {
        "url": "https://{username}.carrd.co",
        "method": "text_not_present", "not_found_text": "doesn't exist",
        "category": "other", "color": "#2AADD6",
    },
    "Peerlist": {
        "url": "https://peerlist.io/{username}",
        "method": "og_meta", "og_not_found": ["404", "Not Found"],
        "category": "other", "color": "#00AA45",
    },
}

CATEGORY_META = {
    "social":   {"label": "Social Media",   "node_color": "#e879f9"},
    "dev":      {"label": "Dev / Security", "node_color": "#34d399"},
    "content":  {"label": "Content",        "node_color": "#fb923c"},
    "gaming":   {"label": "Gaming",         "node_color": "#60a5fa"},
    "forum":    {"label": "Forums",         "node_color": "#fbbf24"},
    "other":    {"label": "Other",          "node_color": "#94a3b8"},
    "sherlock": {"label": "Sherlock",       "node_color": "#a78bfa"},
}
