"""The benchmark harness must keep working, and must score what it claims to."""

import asyncio

import pytest

import helix
from bench import benchmark, mockweb
from osint import checker


def test_manifest_is_reproducible_and_respects_fractions():
    a = mockweb.build_manifest(500, seed=7, catchall_frac=0.1, dead_frac=0.05)
    b = mockweb.build_manifest(500, seed=7, catchall_frac=0.1, dead_frac=0.05)
    assert a == b
    kinds = [m["kind"] for m in a.values()]
    assert 30 <= kinds.count("catchall") <= 70
    assert 10 <= kinds.count("dead") <= 40
    assert all(not m["has_subject"] for m in a.values() if m["kind"] != "normal")


def test_score_counts_catchalls_as_false_positives():
    manifest = {"sites": {"s0": {"kind": "normal", "has_subject": True},
                          "s1": {"kind": "catchall", "has_subject": False},
                          "s2": {"kind": "normal", "has_subject": False}}}
    results = [{"platform": "s0", "found": True}, {"platform": "s1", "found": True},
               {"platform": "s2", "found": False}]
    s = benchmark.score(results, manifest)
    assert s["true_positives"] == 1 and s["false_positives"] == 1 and s["false_negatives"] == 0
    assert s["precision"] == 0.5 and s["recall"] == 1.0
    assert s["catchall_reported"] == ["s1"]


def test_control_probe_removes_every_catchall_on_the_mock_web():
    report = benchmark.run(sites=40, seed=3, catchall_frac=0.15, latency_ms=0, control=True)
    best = report["best"]
    assert best["catchall_sites"] > 0
    assert best["false_positives"] == 0 and best["precision"] == 1.0
    assert best["recall"] == 1.0
    # short-name catch-alls are caught by the same-length control: unconfirmed
    assert best["control_discarded"] + best["unconfirmed"] == best["catchall_sites"]
    assert report["params"]["concurrency"] == checker._dynamic_concurrency(40)


def test_without_the_control_probe_catchalls_are_reported():
    report = benchmark.run(sites=40, seed=3, catchall_frac=0.15, latency_ms=0, control=False)
    assert report["best"]["false_positives"] == report["best"]["catchall_sites"] > 0


# --concurrency

@pytest.mark.parametrize("n,override,expected", [
    (10, None, 20), (100, None, 40), (5000, None, 60),
    (5000, 300, 300), (10, 300, 300),
    (5000, 0, 60), (5000, -5, 1), (5000, 10 ** 6, checker.MAX_CONCURRENCY),
])
def test_concurrency_override_is_clamped(n, override, expected):
    assert checker._dynamic_concurrency(n, override) == expected


def test_check_username_honours_concurrency(monkeypatch):
    seen = {}

    class Sem(asyncio.Semaphore):
        def __init__(self, value):
            seen.setdefault("sem", value)      # the first one is the sweep's
            super().__init__(value)

    monkeypatch.setattr(checker.asyncio, "Semaphore", Sem)

    async def fake_check(session, name, plat, username, sem, fast=False):
        return {"platform": name, "found": False}

    monkeypatch.setattr(checker, "check_platform", fake_check)
    asyncio.run(checker.check_username("janeroe", platforms={"A": {}}, control=False,
                                       concurrency=250))
    assert seen["sem"] == 250


def test_concurrency_warning_names_the_file_descriptor_limit():
    assert helix.concurrency_warning(None) == ""
    assert helix.concurrency_warning(60, fd_limit=1024) == ""
    assert "ulimit -n" in helix.concurrency_warning(800, fd_limit=1024)
    assert "capped" in helix.concurrency_warning(checker.MAX_CONCURRENCY + 1, fd_limit=10 ** 6)
