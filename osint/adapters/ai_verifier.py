"""
Helix: Multi-Provider AI Verification Layer  (async-native)
Providers: claude | openrouter | nvidia
--ai <provider>
"""
import os, json, re
from typing import List, Dict

_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)

# Providers retire models (Claude Sonnet 4, and both free Llama 3.1 8B
# endpoints, went in 2026), so HELIX_AI_MODEL overrides the defaults below.
MODEL_ENV = "HELIX_AI_MODEL"

PROVIDERS = {
    "claude": {
        "lib":     "anthropic",
        "env_key": "ANTHROPIC_API_KEY",
        "model":   "claude-sonnet-5-5",
        "label":   "Claude (Anthropic)",
        "note":    "get a key at console.anthropic.com, then export ANTHROPIC_API_KEY=your_key",
    },
    "openrouter": {
        "lib":      "openai",
        "env_key":  "OPENROUTER_API_KEY",
        "base_url": "https://openrouter.ai/api/v1",
        "model":    "nvidia/nemotron-3.5-super-vl:free",
        # Tried in order: the next one is used when a model is gone, busy or
        # returns no answer. Free models come and go.
        "models":   ["nvidia/nemotron-3.5-super-vl:free", "nvidia/nemotron-3.5-lightning:free"],
        "label":    "Nemotron 3.5 Super via OpenRouter (free)",
        "note":     "get a free key at openrouter.ai, then export OPENROUTER_API_KEY=your_key",
    },
    "nvidia": {
        "lib":      "openai",
        "env_key":  "NVIDIA_API_KEY",
        "base_url": "https://integrate.api.nvidia.com/v1",
        "model":    "nvidia/nemotron-3.5-super-vl-120b-a12b",
        # Measured 30 Oct 2026 with a free key on 20 labelled profiles: both
        # made no mistakes; Super answered in 1.5-2.4 s every time, Lightning
        # timed out 2 of 3. Most other listed models return 404 for free
        # accounts, are retired, or time out.
        "models":   ["nvidia/nemotron-3.5-super-vl-120b-a12b",
                     "nvidia/nemotron-3.5-lightning-30b-a3b"],
        "label":    "Nemotron 3.5 Super via NVIDIA NIM (free)",
        "note":     "get a free key at build.nvidia.com, then export NVIDIA_API_KEY=nvapi-...",
    },
}


def models_for(provider: str) -> List[str]:
    """Models to try, in order. HELIX_AI_MODEL means exactly that one."""
    cfg = PROVIDERS[provider]
    override = os.environ.get(MODEL_ENV, "").strip()
    return [override] if override else list(cfg.get("models") or [cfg["model"]])


def model_for(provider: str) -> str:
    return models_for(provider)[0]


# Nemotron 3 models reason before answering unless the chat template is told
# not to (NVIDIA NIM: chat_template_kwargs.enable_thinking). The reasoning
# shares max_tokens, so with it on a 1000-token budget can end with no answer.
_NO_THINKING = {"chat_template_kwargs": {"enable_thinking": False}}
_TIMEOUT_S = 60

# Worth trying the next model after these; a bad key (401/403) is not.
_NEXT_MODEL_STATUSES = {400, 404, 408, 410, 422, 429, 500, 502, 503, 504}


def _error_text(e: Exception, model: str) -> str:
    """The provider's own explanation, not just "Error code: 410".

    Both SDKs keep the parsed response body on the exception. NVIDIA puts the
    reason in "detail", OpenAI-style APIs in error.message, Anthropic in
    error.message too."""
    status = getattr(e, "status_code", None)
    body = getattr(e, "body", None)
    detail = ""
    if isinstance(body, dict):
        err = body.get("error")
        detail = (body.get("detail") or body.get("message")
                  or (err.get("message") if isinstance(err, dict) else err) or "")
    text = f"HTTP {status}: {detail}" if status else (str(e) or type(e).__name__)
    if not detail and status:
        text = str(e) or text
    if status in (404, 410):
        text += f" (model '{model}' may be retired: set {MODEL_ENV} to a current one)"
    return " ".join(str(text).split())[:300]

# Every profile sent here already passed Helix's control probe: the same URL
# with two made-up usernames gave a different answer. That is stronger than
# any page title, so the model may only overrule it when the title itself is
# a login wall or an error page. An older prompt ("platform name only ->
# reject", "uncertain -> reject") made models purge real Steam, TikTok, VK and
# Twitch accounts, whose titles are generic for every profile.
SYSTEM_PROMPT = """You review accounts that an OSINT tool reported as found.

Each one already passed a live check: the same URL with two made-up usernames
returned a different answer, so the account almost certainly exists.

Your only job is to catch pages that are not a profile at all. Purge an entry
only if its og_title itself shows one of these:
- a login, sign-up or "log in to continue" wall
- an error, 404, "not found", "doesn't exist", "suspended" or "removed" page
- a bot check or captcha ("just a moment", "access denied", "are you human")

Keep everything else. In particular, keep an entry when:
- the title is only the site's name or a generic slogan (many sites title
  every profile that way)
- the title shows a different name than the username (that is the account
  holder's display name)
- the title is empty or you are unsure

List only the entries you purge. Return ONLY valid JSON, no markdown:
{"purged":[{"platform":"...","reason":"..."}]}
If nothing should be purged, return {"purged":[]}."""


async def _openai_call(cfg: Dict, api_key: str, model: str, system: str, user: str,
                       max_tokens: int) -> Dict:
    from openai import AsyncOpenAI
    # No SDK retries: the next model in the list is the retry.
    client = AsyncOpenAI(api_key=api_key, base_url=cfg["base_url"],
                         timeout=_TIMEOUT_S, max_retries=0)
    # temperature 0: the same scan should get the same verdict.
    kwargs = dict(model=model, max_tokens=max(max_tokens, 4000), temperature=0,
                  messages=[{"role": "system", "content": system},
                            {"role": "user",   "content": user}])
    extra = _NO_THINKING if cfg.get("base_url", "").startswith("https://integrate.api.nvidia.com") \
        and "nemotron-3" in model else None
    try:
        resp = await client.chat.completions.create(**kwargs, **({"extra_body": extra} if extra else {}))
    except Exception as e:
        if extra and getattr(e, "status_code", None) == 400:
            # The flag is documented for Nemotron 3, not promised for every
            # variant: ask once more without it.
            resp = await client.chat.completions.create(**kwargs)
        else:
            raise
    choice = resp.choices[0]
    msg = choice.message
    text = _THINK.sub("", msg.content or "").strip()
    if not text:
        # With thinking off, some Nemotron 3 servers return the answer in the
        # reasoning field instead of content.
        extra_fields = getattr(msg, "model_extra", None) or {}
        text = str(extra_fields.get("reasoning_content") or extra_fields.get("reasoning") or "").strip()
    if not text:
        why = getattr(choice, "finish_reason", None) or "unknown"
        hint = ": it ran out of tokens while reasoning" if why == "length" else ""
        return {"error": f"{model} returned no answer (stopped: {why}){hint}", "next": True}
    return {"text": text, "model": model}


async def _anthropic_call(api_key: str, model: str, system: str, user: str, max_tokens: int) -> Dict:
    from anthropic import AsyncAnthropic
    client = AsyncAnthropic(api_key=api_key, timeout=_TIMEOUT_S, max_retries=1)
    # Current Claude models always think, and thinking shares max_tokens,
    # so leave room for it and keep the effort low.
    kwargs = dict(model=model, max_tokens=max(max_tokens, 4000), system=system,
                  messages=[{"role": "user", "content": user}])
    try:
        msg = await client.messages.create(**kwargs, output_config={"effort": "low"})
    except TypeError:
        # anthropic SDKs older than output_config: same request at default effort.
        msg = await client.messages.create(**kwargs)
    if msg.stop_reason == "refusal":
        return {"error": f"{model} declined the request", "next": True}
    text = "".join(b.text for b in msg.content if b.type == "text").strip()
    if not text:
        return {"error": f"{model} returned no answer (stopped: {msg.stop_reason})", "next": True}
    return {"text": text, "model": model}


async def complete(provider: str, system: str, user: str, max_tokens: int = 1000,
                   accept=None) -> Dict:
    """One chat completion -> {"text", "model"} or {"error"}.

    Tries the provider's models in order until one answers (and, with
    `accept`, until the answer passes that check)."""
    cfg = PROVIDERS.get(provider)
    if not cfg:
        return {"error": f"Unknown provider '{provider}'. Choose: {', '.join(PROVIDERS)}"}
    api_key = os.environ.get(cfg["env_key"], "")
    if not api_key:
        return {"error": f"{cfg['env_key']} is not set ({cfg['note']})"}
    errors = []
    for model in models_for(provider):
        try:
            if cfg["lib"] == "anthropic":
                out = await _anthropic_call(api_key, model, system, user, max_tokens)
            else:
                out = await _openai_call(cfg, api_key, model, system, user, max_tokens)
        except ImportError:
            return {"error": f"pip install {cfg['lib']}"}
        except Exception as e:
            status = getattr(e, "status_code", None)
            out = {"error": _error_text(e, model),
                   "next": status is None or status in _NEXT_MODEL_STATUSES}
        if out.get("text") and accept and not accept(out["text"]):
            snippet = " ".join(out["text"].split())[:80]
            out = {"error": f"{model} gave an unusable answer: {snippet}", "next": True}
        if out.get("text"):
            if errors:
                out["fallback_from"] = errors
            return out
        errors.append(out["error"])
        if not out.get("next"):
            break
    return {"error": "; ".join(errors)}


async def verify_with_ai(results: List[dict], provider: str = "openrouter") -> Dict:
    cfg = PROVIDERS.get(provider)
    if not cfg:
        return {"error": f"Unknown provider '{provider}'. Choose: {', '.join(PROVIDERS)}"}

    api_key = os.environ.get(cfg["env_key"], "")
    if not api_key:
        return {"error": f"{cfg['env_key']} is not set ({cfg['note']})", "provider": provider}

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

    out = await complete(provider, SYSTEM_PROMPT, json.dumps(payload, indent=2),
                         accept=lambda t: _parse_verdict(t) is not None)
    if out.get("error"):
        return {"error": out["error"], "provider": provider}
    verdict = _parse_verdict(out["text"])
    verdict["provider"] = provider
    verdict["model"]    = out["model"]
    if out.get("fallback_from"):
        verdict["fallback_from"] = out["fallback_from"]
    return verdict


def _parse_verdict(raw: str):
    """The model's JSON verdict, or None if the answer holds none."""
    raw = (raw or "").replace("```json", "").replace("```", "").strip()
    # Small models sometimes wrap the object in a sentence; keep the object.
    if "{" in raw and "}" in raw:
        raw = raw[raw.index("{"):raw.rindex("}") + 1]
    try:
        verdict = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return verdict if isinstance(verdict, dict) else None


def apply_verdict(results: List[dict], verdict: Dict) -> List[dict]:
    purged = {p["platform"]: p.get("reason","AI purged")
              for p in verdict.get("purged", []) if isinstance(p, dict) and p.get("platform")}
    for r in results:
        # Only what was sent for review: never a high-confidence hit the model
        # was not shown, whatever name it writes back.
        if r["platform"] in purged and r.get("found") and r.get("confidence") in ("low", "medium"):
            r["found"] = False
            r["error"] = f"ai_purge({verdict.get('provider','?')}): {purged[r['platform']]}"
    return results


def provider_status() -> str:
    lines = []
    for name, cfg in PROVIDERS.items():
        key    = os.environ.get(cfg["env_key"], "")
        status = "ready" if key else f"set {cfg['env_key']}"
        lines.append(f"  {name:<12} {cfg['label']} [{model_for(name)}]: {status}")
    lines.append(f"  (set {MODEL_ENV} to use another model)")
    return "\n".join(lines)
