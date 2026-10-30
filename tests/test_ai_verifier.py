"""--ai: current models, the HELIX_AI_MODEL override, readable provider errors.

In 2026 all three default models were retired (Claude Sonnet 4 and both
free Llama 3.1 8B endpoints), and Helix only printed "Error code: 410".
"""

import asyncio
import sys
import types

import pytest

from osint.adapters import ai_verifier as ai


class _StatusError(Exception):
    """Shaped like the SDKs' APIStatusError: status_code plus the parsed body."""

    def __init__(self, status, body):
        super().__init__(f"Error code: {status}")
        self.status_code = status
        self.body = body


def test_retired_models_are_gone():
    for cfg in ai.PROVIDERS.values():
        assert "llama-3.1-8b" not in cfg["model"]
        assert cfg["model"] != "claude-sonnet-4-20250514"


def test_model_override(monkeypatch):
    monkeypatch.delenv(ai.MODEL_ENV, raising=False)
    assert ai.model_for("nvidia") == ai.PROVIDERS["nvidia"]["model"]
    monkeypatch.setenv(ai.MODEL_ENV, "nvidia/some-new-model")
    assert ai.model_for("nvidia") == "nvidia/some-new-model"


def test_error_shows_the_providers_reason():
    e = _StatusError(410, {"title": "Gone", "status": 410,
                           "detail": "The model 'x' has reached its end of life on 2026-08-26."})
    text = ai._error_text(e, "x")
    assert "HTTP 410" in text and "end of life" in text
    assert ai.MODEL_ENV in text


def test_error_reads_openai_style_bodies():
    e = _StatusError(401, {"error": {"message": "Invalid API key", "code": 401}})
    assert ai._error_text(e, "m") == "HTTP 401: Invalid API key"


def test_error_without_a_status_keeps_the_message():
    assert ai._error_text(ValueError("boom"), "m") == "boom"


# Fake SDK clients, installed as the modules complete() imports.

def _fake_openai(monkeypatch, content, seen):
    class _Completions:
        async def create(self, **kw):
            seen.update(kw)
            msg = types.SimpleNamespace(content=content)
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)])

    class AsyncOpenAI:
        def __init__(self, **kw):
            self.chat = types.SimpleNamespace(completions=_Completions())

    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(AsyncOpenAI=AsyncOpenAI))


def _fake_anthropic(monkeypatch, blocks, stop_reason, seen):
    class _Messages:
        async def create(self, **kw):
            seen.update(kw)
            return types.SimpleNamespace(content=blocks, stop_reason=stop_reason)

    class AsyncAnthropic:
        def __init__(self, **kw):
            self.messages = _Messages()

    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(AsyncAnthropic=AsyncAnthropic))


def test_reasoning_text_is_stripped(monkeypatch):
    seen = {}
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    monkeypatch.delenv(ai.MODEL_ENV, raising=False)
    _fake_openai(monkeypatch, "<think>checking each one</think>\n{\"ok\": true}", seen)
    out = asyncio.run(ai.complete("nvidia", "sys", "user"))
    assert out == {"text": '{"ok": true}', "model": ai.PROVIDERS["nvidia"]["model"]}
    assert seen["model"] == ai.PROVIDERS["nvidia"]["model"]


def test_claude_reads_the_text_block_after_thinking(monkeypatch):
    seen = {}
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.delenv(ai.MODEL_ENV, raising=False)
    blocks = [types.SimpleNamespace(type="thinking", thinking=""),
              types.SimpleNamespace(type="text", text="{\"verified\": []}")]
    _fake_anthropic(monkeypatch, blocks, "end_turn", seen)
    out = asyncio.run(ai.complete("claude", "sys", "user", max_tokens=1000))
    assert out["text"] == '{"verified": []}'
    assert seen["max_tokens"] >= 4000          # room for thinking
    assert seen["output_config"] == {"effort": "low"}


def test_claude_refusal_is_an_error(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    _fake_anthropic(monkeypatch, [], "refusal", {})
    assert "declined" in asyncio.run(ai.complete("claude", "sys", "user"))["error"]


def test_provider_error_reaches_the_caller(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")

    class _Completions:
        async def create(self, **kw):
            raise _StatusError(410, {"detail": "The model has reached its end of life."})

    class AsyncOpenAI:
        def __init__(self, **kw):
            self.chat = types.SimpleNamespace(completions=_Completions())

    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(AsyncOpenAI=AsyncOpenAI))
    err = asyncio.run(ai.complete("nvidia", "s", "u"))["error"]
    assert "end of life" in err and ai.MODEL_ENV in err


@pytest.mark.parametrize("reply", [
    '{"verified": [], "purged": [{"platform": "X", "reason": "login page"}]}',
    'Here is the result:\n{"verified": [], "purged": [{"platform": "X", "reason": "login page"}]}\nDone.',
])
def test_verdict_json_is_found_inside_prose(monkeypatch, reply):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    _fake_openai(monkeypatch, reply, {})
    results = [{"platform": "X", "url": "https://x.example/u", "found": True, "confidence": "low"}]
    verdict = asyncio.run(ai.verify_with_ai(results, "nvidia"))
    assert verdict["purged"][0]["platform"] == "X"
    assert verdict["model"] == ai.PROVIDERS["nvidia"]["model"]


# Model fallback, reasoning off, and a prompt that cannot overrule the probe
# (measured with a free NVIDIA key, 30 Oct 2026).

def _openai_sequence(monkeypatch, answers, seen):
    """Each create() call returns the next answer: a string, an exception,
    or (content, finish_reason)."""
    answers = list(answers)

    class _Completions:
        async def create(self, **kw):
            seen.append(kw)
            a = answers.pop(0)
            if isinstance(a, Exception):
                raise a
            content, finish = a if isinstance(a, tuple) else (a, "stop")
            msg = types.SimpleNamespace(content=content, model_extra={})
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg, finish_reason=finish)])

    class AsyncOpenAI:
        def __init__(self, **kw):
            seen.append({"client": kw})
            self.chat = types.SimpleNamespace(completions=_Completions())

    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(AsyncOpenAI=AsyncOpenAI))


def _calls(seen):
    return [c for c in seen if "model" in c]


def test_nemotron_on_nvidia_runs_with_reasoning_off(monkeypatch):
    seen = []
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    monkeypatch.delenv(ai.MODEL_ENV, raising=False)
    _openai_sequence(monkeypatch, ['{"purged": []}'], seen)
    asyncio.run(ai.complete("nvidia", "s", "u"))
    call = _calls(seen)[0]
    assert call["extra_body"] == {"chat_template_kwargs": {"enable_thinking": False}}
    assert call["temperature"] == 0 and call["max_tokens"] >= 4000


def test_no_reasoning_flag_for_openrouter(monkeypatch):
    seen = []
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    _openai_sequence(monkeypatch, ['{"purged": []}'], seen)
    asyncio.run(ai.complete("openrouter", "s", "u"))
    assert "extra_body" not in _calls(seen)[0]


def test_flag_rejected_is_retried_without_it(monkeypatch):
    seen = []
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    monkeypatch.delenv(ai.MODEL_ENV, raising=False)
    _openai_sequence(monkeypatch, [_StatusError(400, {"detail": "unknown field"}), '{"purged": []}'], seen)
    out = asyncio.run(ai.complete("nvidia", "s", "u"))
    calls = _calls(seen)
    assert out["text"] == '{"purged": []}'
    assert "extra_body" in calls[0] and "extra_body" not in calls[1]
    assert calls[0]["model"] == calls[1]["model"]


def test_empty_answer_moves_to_the_next_model(monkeypatch):
    """The laptop failure: reasoning used the whole budget (finish=length)."""
    seen = []
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    monkeypatch.delenv(ai.MODEL_ENV, raising=False)
    _openai_sequence(monkeypatch, [("", "length"), '{"purged": []}'], seen)
    out = asyncio.run(ai.complete("nvidia", "s", "u"))
    first, second = ai.models_for("nvidia")[:2]
    assert out["model"] == second
    assert "ran out of tokens" in out["fallback_from"][0] and first in out["fallback_from"][0]


def test_unusable_answer_moves_to_the_next_model(monkeypatch):
    seen = []
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    monkeypatch.delenv(ai.MODEL_ENV, raising=False)
    _openai_sequence(monkeypatch, ['{"purged": [{"platform": "A"', '{"purged": []}'], seen)
    v = asyncio.run(ai.verify_with_ai(
        [{"platform": "A", "url": "u", "found": True, "confidence": "low"}], "nvidia"))
    assert v["purged"] == [] and v["model"] == ai.models_for("nvidia")[1]
    assert "unusable answer" in v["fallback_from"][0]


def test_bad_key_does_not_try_other_models(monkeypatch):
    seen = []
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-bad")
    monkeypatch.delenv(ai.MODEL_ENV, raising=False)
    _openai_sequence(monkeypatch, [_StatusError(401, {"detail": "Unauthorized"})], seen)
    out = asyncio.run(ai.complete("nvidia", "s", "u"))
    assert len(_calls(seen)) == 1 and "HTTP 401" in out["error"]


def test_every_model_failing_lists_each_reason(monkeypatch):
    seen = []
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    monkeypatch.delenv(ai.MODEL_ENV, raising=False)
    models = ai.models_for("nvidia")
    _openai_sequence(monkeypatch, [_StatusError(404, {"detail": "Not found for account"})] * len(models), seen)
    err = asyncio.run(ai.complete("nvidia", "s", "u"))["error"]
    assert all(m in err for m in models)


def test_client_has_a_timeout_and_no_hidden_retries(monkeypatch):
    seen = []
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    _openai_sequence(monkeypatch, ['{"purged": []}'], seen)
    asyncio.run(ai.complete("nvidia", "s", "u"))
    client = next(c["client"] for c in seen if "client" in c)
    assert client["timeout"] <= 60 and client["max_retries"] == 0


def test_prompt_keeps_generic_titles():
    p = ai.SYSTEM_PROMPT.lower()
    assert "uncertain -> reject" not in p and "just the platform name" not in p
    assert "only the site's name" in p and "keep everything else" in p


def test_verdict_cannot_purge_what_it_was_not_shown():
    results = [{"platform": "GitHub", "found": True, "confidence": "high"},
               {"platform": "Quora", "found": True, "confidence": "low"}]
    ai.apply_verdict(results, {"purged": [{"platform": "GitHub"}, {"platform": "Quora"}, "junk"]})
    assert results[0]["found"] is True
    assert results[1]["found"] is False


def test_old_anthropic_sdk_without_output_config(monkeypatch):
    """pyproject allows anthropic>=0.25, which has no output_config argument."""
    seen = []
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.delenv(ai.MODEL_ENV, raising=False)

    class _Messages:
        async def create(self, model, max_tokens, system, messages):
            seen.append(model)
            return types.SimpleNamespace(stop_reason="end_turn",
                                         content=[types.SimpleNamespace(type="text", text="{}")])

    class AsyncAnthropic:
        def __init__(self, **kw):
            self.messages = _Messages()

    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(AsyncAnthropic=AsyncAnthropic))
    assert asyncio.run(ai.complete("claude", "s", "u"))["text"] == "{}"
    assert seen == [ai.PROVIDERS["claude"]["model"]]
