"""
Helix v3.0 — Breach Intelligence Adapter
Uses XposedOrNot (free, no key) — returns breach metadata ONLY
(breach name, date, exposed data types). No credentials or passwords.
"""
import aiohttp
import hashlib
from typing import List, Dict

# XposedOrNot: free public API, returns only breach metadata
XON_URL  = "https://api.xposedornot.com/v1/check-email/{email}"

# HIBP pwned passwords (k-anonymity — checks password hashes, no email needed)
HIBP_PWD = "https://api.pwnedpasswords.com/range/{prefix}"


async def check_breaches(email: str) -> Dict:
    """
    Check email against XposedOrNot breach database.
    Returns breach names, dates, and data types exposed — NO credentials.
    """
    result = {
        "email":    email,
        "found":    False,
        "breaches": [],
        "count":    0,
        "error":    None,
    }

    headers = {"User-Agent": "Helix-OSINT/3.0 (security research)"}

    async with aiohttp.ClientSession() as session:
        try:
            url = XON_URL.format(email=email)
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False,
            ) as resp:

                if resp.status == 404:
                    # Not found in any breach — good news
                    result["found"] = False
                    return result

                if resp.status != 200:
                    result["error"] = f"HTTP {resp.status}"
                    return result

                data = await resp.json(content_type=None)

                # XON returns {"ExposedBreaches": {"breaches_details": [...], ...}}
                breaches_raw = (
                    data.get("ExposedBreaches", {})
                        .get("breaches_details", [])
                )

                parsed = []
                for b in breaches_raw:
                    parsed.append({
                        "name":     b.get("breach", "Unknown"),
                        "date":     b.get("xposed_date", "Unknown"),
                        "records":  b.get("xposed_records", "?"),
                        "types":    b.get("xposed_data", "Unknown"),
                        "industry": b.get("industry", ""),
                    })

                result["found"]    = len(parsed) > 0
                result["breaches"] = parsed
                result["count"]    = len(parsed)

        except aiohttp.ClientError as e:
            result["error"] = str(e)[:80]
        except Exception as e:
            result["error"] = f"unexpected: {str(e)[:60]}"

    return result


def format_breach_report(breach_data: Dict) -> List[str]:
    """Format breach results for terminal output."""
    lines = []
    if not breach_data.get("found"):
        lines.append("  No breaches found for this email.")
        return lines

    lines.append(f"  Found in {breach_data['count']} breach(es):\n")
    for b in breach_data["breaches"]:
        lines.append(f"  [!] {b['name']}")
        lines.append(f"      Date    : {b['date']}")
        lines.append(f"      Records : {b['records']}")
        lines.append(f"      Exposed : {b['types']}")
        if b["industry"]:
            lines.append(f"      Industry: {b['industry']}")
        lines.append("")
    return lines
