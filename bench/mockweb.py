"""
Mock web for benchmarking: N fake platforms with known ground truth.

Runs as its own process so the server's CPU time never counts against the
engine being measured. Every site is one of:

  normal    answers 200 + a page naming the user for the users it "has",
            404 for everyone else (the common well-behaved platform)
  catchall  answers 200 naming *any* user (login walls, search pages: the
            false-positive trap the control probe exists to catch)
  short400  a catch-all for names up to SHORT_LIMIT characters that rejects
            longer ones with 400 "invalid username"
  short404  the same, but longer names get a plain 404 (a route that only
            matches short names). Made-up names longer than the subject
            cannot catch these two: they never see the catch-all.
  dead      never answers (a host that is down; the engine's timeout tax)

Which sites have which kind, and which have the subject, is decided by a
seeded RNG, so a run is reproducible from (sites, seed, fractions).

    python -m bench.mockweb --port 8765 --sites 1000 --seed 1
    GET /__manifest  -> {"sites": {"s0": {"kind": "normal", "has_subject": true}, ...}}
    GET /s17/<user>  -> the site's answer for that user
"""

import argparse
import http.server
import json
import random
import socket
import threading
import time
from typing import Dict

SUBJECT = "janeroe"          # the one user the benchmark scans for
SUBJECT_EVERY = 10           # normal site i has the subject when i % 10 == 0
SHORT_LIMIT = 11             # longest name the short* catch-alls accept
CATCHALL_KINDS = ("catchall", "short400", "short404")

_NOT_FOUND = b"<html><head><title>Page not found</title></head><body>user not found</body></html>"


def build_manifest(sites: int, seed: int, catchall_frac: float, dead_frac: float,
                   short_catchall_frac: float = 0.0) -> Dict[str, dict]:
    rng = random.Random(seed)
    manifest = {}
    for i in range(sites):
        roll = rng.random()       # one draw per site, so other kinds stay where they were
        if roll < dead_frac:
            kind = "dead"
        elif roll < dead_frac + catchall_frac:
            kind = "catchall"
        elif roll < dead_frac + catchall_frac + short_catchall_frac:
            kind = "short400" if i % 2 else "short404"
        else:
            kind = "normal"
        manifest[f"s{i}"] = {"kind": kind, "has_subject": kind == "normal" and i % SUBJECT_EVERY == 0}
    return manifest


def _profile_page(user: str) -> bytes:
    return (f"<html><head><title>{user} | MockSite</title>"
            f'<meta property="og:title" content="{user}">'
            f"</head><body><h1>@{user}</h1><p>Profile of {user}.</p></body></html>").encode()


def make_handler(manifest: Dict[str, dict], latency_s: float, dead_s: float):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.path == "/__manifest":
                return self._send(200, json.dumps({"subject": SUBJECT, "sites": manifest}).encode(),
                                  "application/json")
            parts = self.path.strip("/").split("/")
            if len(parts) != 2 or parts[0] not in manifest:
                return self._send(404, _NOT_FOUND)
            site, user = parts
            kind = manifest[site]["kind"]
            if kind == "dead":
                time.sleep(dead_s)
                return self._send(504, b"gateway timeout")
            if latency_s:
                time.sleep(latency_s)
            if kind in ("short400", "short404") and len(user) > SHORT_LIMIT:
                if kind == "short400":
                    return self._send(400, b"<html><body>invalid username</body></html>")
                return self._send(404, _NOT_FOUND)
            if kind in CATCHALL_KINDS or (kind == "normal" and manifest[site]["has_subject"]
                                          and user == SUBJECT):
                return self._send(200, _profile_page(user))
            return self._send(404, _NOT_FOUND)

        def _send(self, status, body, ctype="text/html"):
            try:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                pass   # client gave up (its timeout): nothing to do

        def log_message(self, *args):
            pass

    return Handler


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def serve(port: int, sites: int, seed: int, catchall_frac: float, dead_frac: float,
          latency_ms: float, dead_seconds: float, block: bool = True,
          short_catchall_frac: float = 0.0):
    manifest = build_manifest(sites, seed, catchall_frac, dead_frac, short_catchall_frac)
    httpd = http.server.ThreadingHTTPServer(
        ("127.0.0.1", port), make_handler(manifest, latency_ms / 1000.0, dead_seconds))
    httpd.daemon_threads = True
    if block:
        httpd.serve_forever()
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--sites", type=int, default=1000)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--catchall-frac", type=float, default=0.02)
    p.add_argument("--dead-frac", type=float, default=0.0)
    p.add_argument("--short-catchall-frac", type=float, default=0.0)
    p.add_argument("--latency-ms", type=float, default=50.0)
    p.add_argument("--dead-seconds", type=float, default=30.0)
    a = p.parse_args()
    serve(a.port, a.sites, a.seed, a.catchall_frac, a.dead_frac, a.latency_ms, a.dead_seconds,
          short_catchall_frac=a.short_catchall_frac)


if __name__ == "__main__":
    main()
