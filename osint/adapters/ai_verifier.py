"""
Helix — Multi-Provider AI Verification Layer  (async-native)
Providers: claude | openrouter | nvidia
--ai <provider>
"""
import os, json, asyncio
from typing import List, Dict

PROVIDERS = {
    "claude": {
        "lib":     "anthropic",
        "env_key": "ANTHROPIC_API_KEY",
        "model":   "claude-sonnet-4-20250514",
        "label":   "Claude (Anthropic)",
        "note":    "Get key at console.anthropic.com — export ANTHROPIC_API_KEY=your_key",
    },
    "openrouter": {
        "lib":      "openai",
        "env_key":  "OPENROUTER_API_KEY",
        "base_url": "https://openrouter.ai/api/v1",
        "model":    "meta-llama/llama-3.1-8b-instruct:free",
        "label":    "Llama 3.1 via OpenRouter (free)",
        "note":     "Get free key at openrouter.ai — export OPENROUTER_API_KEY=your_key",
    },
    "nvidia": {
        "lib":      "openai",
        "env_key":  "NVIDIA_API_KEY",
        "base_url": "https://integrate.api.nvidia.com/v1",
        "model":    "meta/llama-3.1-8b-instruct",
        "label":    "Llama 3.1 via NVIDIA NIM (free)",
        "note":     "Get free key at build.nvidia.com — export NVIDIA_API_KEY=nvapi-...",
    },
}

SYSTEM_PROMPT = """You are a strict OSINT verification gatekeeper for Helix.
Review profile metadata and decide: REAL profile or soft-404 / generic page.

Rules:
1. REJECT if og:title is just the platform name (e.g. "Instagram", "TikTok")
2. REJECT if og:title contains login/signup phrases
3. REJECT if og:title contains error phrases (404, not found, doesn't exist)
4. ACCEPT if og:title contains the username or a real personal name/bio
5. When uncertain → REJECT.

Return ONLY valid JSON, no markdown:
{"verified":[{"platform":"...","reason":"..."}],
 "purged":[{"platform":"...","reason":"..."}]}"""


async def complete(provider: str, system: str, user: str, max_tokens: int = 1000) -> Dict:
    """One chat completion → {"text", "model"} or {"error"}."""
    cfg = PROVIDERS.get(provider)
    if not cfg:
        return {"error": f"Unknown provider '{provider}'. Choose: {', '.join(PROVIDERS)}"}
    api_key = os.environ.get(cfg["env_key"], "")
    if not api_key:
        return {"error": f"Missing {cfg['env_key']} — {cfg['note']}"}
    try:
        if cfg["lib"] == "anthropic":
            from anthropic import AsyncAnthropic
            client = AsyncAnthropic(api_key=api_key)
            msg = await client.messages.create(
                model=cfg["model"], max_tokens=max_tokens, system=system,
                messages=[{"role": "user", "content": user}],
            )
            text = msg.content[0].text
        else:
            # OpenAI-compatible (OpenRouter / NVIDIA)
            from openai import AsyncOpenAI
            client = AsyncOpenAI(api_key=api_key, base_url=cfg["base_url"])
            resp = await client.chat.completions.create(
                model=cfg["model"], max_tokens=max_tokens,
                messages=[{"role": "system", "content": system},
                          {"role": "user",   "content": user}],
            )
            text = resp.choices[0].message.content or ""
    except ImportError:
        return {"error": f"pip install {cfg['lib']}"}
    except Exception as e:
        return {"error": str(e)[:120]}
    return {"text": text.strip(), "model": cfg["model"]}


async def verify_with_ai(results: List[dict], provider: str = "openrouter") -> Dict:
    cfg = PROVIDERS.get(provider)
    if not cfg:
        return {"error": f"Unknown provider '{provider}'. Choose: {', '.join(PROVIDERS)}"}

    api_key = os.environ.get(cfg["env_key"], "")
    if not api_key:
        return {"error": f"Missing {cfg['env_key']} — {cfg['note']}", "provider": provider}

    to_check = [r for r in results
                if r.get("found") and r.get("confidence") in ("low", "medium")]
    if not to_check:
        return {"verified":[], "purged":[], "skipped":"all results high-confidence",
                "provider": provider}

    payload = [
        {"platform": r["platform"], "url": r["url"],
         "og_title": r.get("og_title",""), "confidence": r.get("confidence","low")}
        for r in to_check
    ]

    out = await complete(provider, SYSTEM_PROMPT, json.dumps(payload, indent=2))
    if out.get("error"):
        return {"error": out["error"], "provider": provider}
    raw = out["text"]

    raw = raw.replace("```json","").replace("```","").strip()
    try:
        verdict = json.loads(raw)
        verdict["provider"] = provider
        verdict["model"]    = cfg["model"]
        return verdict
    except json.JSONDecodeError:
        return {"error": f"Bad JSON from model: {raw[:80]}", "provider": provider}


def apply_verdict(results: List[dict], verdict: Dict) -> List[dict]:
    purged = {p["platform"]: p.get("reason","AI purged")
              for p in verdict.get("purged", [])}
    for r in results:
        if r["platform"] in purged:
            r["found"] = False
            r["error"] = f"ai_purge({verdict.get('provider','?')}): {purged[r['platform']]}"
    return results


def provider_status() -> str:
    lines = []
    for name, cfg in PROVIDERS.items():
        key    = os.environ.get(cfg["env_key"], "")
        status = "✓ ready" if key else f"✗ set {cfg['env_key']}"
        lines.append(f"  {name:<12} {cfg['label']} — {status}")
    return "\n".join(lines)
