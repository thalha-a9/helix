"""
Helix benchmark runner: throughput and accuracy on a reproducible mock web.

    python -m bench.benchmark --sites 6000 --concurrency 300
    python -m bench.benchmark --sites 1000 --dead-frac 0.1          # the dead-host tax
    python -m bench.benchmark --sites 1000 --no-control             # what the probe costs/buys

The mock web (bench/mockweb.py) runs in a separate process. The run goes
through the same path a real scan does: check_username (with the control
probe unless --no-control) and then the local heuristic verifier. Results are
scored against the mock web's manifest, so precision and recall are exact.

Metrics (defined in bench/README.md):
  sites_per_second   platforms checked per wall-clock second, end to end
  precision          found & truly-has-subject / found
  recall             found & truly-has-subject / truly-has-subject
  false_positives    catch-all sites reported as accounts (should be 0)

Every run writes a JSON record (--json) with the engine version, git commit,
Python version, host and every parameter, so a number can be reproduced.
"""

import argparse
import asyncio
import json
import os
import platform as _platform
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from osint import __version__, checker                      # noqa: E402
from osint.verifier import run_local_verifier               # noqa: E402
from bench import mockweb                                   # noqa: E402


def _git_sha() -> str:
    try:
        return subprocess.check_output(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
                                       stderr=subprocess.DEVNULL, timeout=5).decode().strip()
    except Exception:
        return "unknown"


def start_mockweb(sites: int, seed: int, catchall_frac: float, dead_frac: float,
                  latency_ms: float, dead_seconds: float, short_catchall_frac: float = 0.0):
    """Launch the mock web in its own process; return (process, base_url, manifest)."""
    port = mockweb.free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "bench.mockweb", "--port", str(port), "--sites", str(sites),
         "--seed", str(seed), "--catchall-frac", str(catchall_frac), "--dead-frac", str(dead_frac),
         "--latency-ms", str(latency_ms), "--dead-seconds", str(dead_seconds),
         "--short-catchall-frac", str(short_catchall_frac)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base}/__manifest", timeout=2) as r:
                return proc, base, json.load(r)
        except Exception:
            if proc.poll() is not None:
                raise RuntimeError("mock web exited before it was ready") from None
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("mock web did not start in 15s")


def platforms_for(base: str, manifest: dict) -> dict:
    return {
        site: {"url": f"{base}/{site}/{{username}}", "method": "status_code", "found": [200],
               "category": "other", "color": "#94a3b8", "source": "bench"}
        for site in manifest["sites"]
    }


def score(results: list, manifest: dict) -> dict:
    sites = manifest["sites"]
    truth = {s for s, m in sites.items() if m["has_subject"]}
    found = {r["platform"] for r in results if r.get("found")}
    tp = found & truth
    fp = found - truth
    fn = truth - found
    errors = sum(1 for r in results if r.get("error") and not r.get("control_failed")
                 and not r.get("unconfirmed"))
    return {
        "truly_has_subject": len(truth),
        "found": len(found),
        "true_positives": len(tp),
        "false_positives": len(fp),
        "false_negatives": len(fn),
        "precision": (len(tp) / len(found)) if found else 1.0,
        "recall": (len(tp) / len(truth)) if truth else 1.0,
        "catchall_sites": sum(1 for m in sites.values() if m["kind"] in mockweb.CATCHALL_KINDS),
        "catchall_reported": sorted(s for s in fp if sites[s]["kind"] in mockweb.CATCHALL_KINDS),
        "unconfirmed": sum(1 for r in results if r.get("unconfirmed")),
        "control_discarded": sum(1 for r in results if r.get("control_failed")),
        "probe_errors": errors,
    }


async def run_once(base: str, manifest: dict, control: bool, concurrency) -> dict:
    plats = platforms_for(base, manifest)
    t0 = time.perf_counter()
    raw = await checker.check_username(mockweb.SUBJECT, platforms=plats, control=control,
                                       concurrency=concurrency)
    t_scan = time.perf_counter() - t0
    results, purged = run_local_verifier(raw, mockweb.SUBJECT)
    wall = time.perf_counter() - t0
    out = score(results, manifest)
    out.update({"wall_seconds": round(wall, 3), "scan_seconds": round(t_scan, 3),
                "sites_per_second": round(len(plats) / wall, 1),
                "verifier_purged": len(purged)})
    return out


def run(sites=1000, seed=1, catchall_frac=0.02, dead_frac=0.0, latency_ms=50.0,
        dead_seconds=30.0, control=True, concurrency=None, repeat=1,
        short_catchall_frac=0.02) -> dict:
    proc, base, manifest = start_mockweb(sites, seed, catchall_frac, dead_frac, latency_ms,
                                         dead_seconds, short_catchall_frac)
    try:
        runs = [asyncio.run(run_once(base, manifest, control, concurrency)) for _ in range(repeat)]
    finally:
        proc.kill()
        proc.wait()
    best = max(runs, key=lambda r: r["sites_per_second"])
    return {
        "benchmark": "helix.mockweb.v1",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "helix_version": __version__,
        "git_commit": _git_sha(),
        "python": _platform.python_version(),
        "host": {"system": _platform.system(), "machine": _platform.machine(),
                 "cpus": os.cpu_count()},
        "params": {"sites": sites, "seed": seed, "catchall_frac": catchall_frac,
                   "short_catchall_frac": short_catchall_frac,
                   "dead_frac": dead_frac, "latency_ms": latency_ms, "dead_seconds": dead_seconds,
                   "control_probe": control,
                   "concurrency": checker._dynamic_concurrency(sites, concurrency),
                   "repeat": repeat},
        "best": best,
        "runs": runs,
    }


def _print(report: dict):
    p, b = report["params"], report["best"]
    print(f"\nHelix {report['helix_version']} ({report['git_commit']}) | Python {report['python']} "
          f"| {report['host']['cpus']} CPUs")
    print(f"sites={p['sites']} concurrency={p['concurrency']} latency={p['latency_ms']}ms "
          f"catch-all={p['catchall_frac']:.0%} short catch-all={p.get('short_catchall_frac', 0):.0%} "
          f"dead={p['dead_frac']:.0%} "
          f"control={'on' if p['control_probe'] else 'off'} repeat={p['repeat']}\n")
    print(f"  throughput   {b['sites_per_second']:>8.1f} sites/s   ({b['wall_seconds']}s wall)")
    print(f"  precision    {b['precision']:>8.3f}          false positives: {b['false_positives']}"
          f"{'  <- ' + ', '.join(b['catchall_reported'][:5]) if b['catchall_reported'] else ''}")
    print(f"  recall       {b['recall']:>8.3f}          found {b['true_positives']}/{b['truly_has_subject']}")
    print(f"  control probe discarded {b['control_discarded']} | unconfirmed {b.get('unconfirmed', 0)} "
          f"| verifier purged {b['verifier_purged']} "
          f"| probe errors {b['probe_errors']}\n")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--sites", type=int, default=1000)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--catchall-frac", type=float, default=0.02)
    p.add_argument("--dead-frac", type=float, default=0.0)
    p.add_argument("--short-catchall-frac", type=float, default=0.02,
                   help="catch-alls that only accept short names (400 or 404 for longer ones)")
    p.add_argument("--latency-ms", type=float, default=50.0)
    p.add_argument("--dead-seconds", type=float, default=30.0,
                   help="how long a dead site hangs (longer than the engine's timeout)")
    p.add_argument("--concurrency", type=int, default=None)
    p.add_argument("--no-control", action="store_true")
    p.add_argument("--repeat", type=int, default=1, help="runs; the fastest is reported as 'best'")
    p.add_argument("--json", metavar="PATH", help="write the full report here")
    a = p.parse_args()

    report = run(a.sites, a.seed, a.catchall_frac, a.dead_frac, a.latency_ms, a.dead_seconds,
                 control=not a.no_control, concurrency=a.concurrency, repeat=a.repeat,
                 short_catchall_frac=a.short_catchall_frac)
    _print(report)
    if a.json:
        os.makedirs(os.path.dirname(os.path.abspath(a.json)), exist_ok=True)
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"  -> {a.json}")


if __name__ == "__main__":
    main()
