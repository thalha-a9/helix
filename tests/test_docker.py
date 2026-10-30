"""The Docker image: built from an allow list, not root, published only on releases."""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


def _rules(text):
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def test_dockerignore_is_an_allow_list():
    rules = _rules(_read(".dockerignore"))
    assert rules[0] == "*"
    allowed = {r[1:].rstrip("/") for r in rules if r.startswith("!")}
    assert allowed == {"pyproject.toml", "README.md", "LICENSE", "MANIFEST.in", "helix.py", "osint"}


def test_dockerfile_copies_only_allowed_files():
    copied = []
    for line in _read("Dockerfile").splitlines():
        if line.startswith("COPY "):
            copied += line.split()[1:-1]
    assert copied
    allowed = {r[1:].rstrip("/") for r in _rules(_read(".dockerignore")) if r.startswith("!")}
    assert set(copied) <= allowed


def test_image_runs_helix_as_a_normal_user():
    text = _read("Dockerfile")
    users = re.findall(r"^USER\s+(\S+)", text, re.M)
    assert users and users[-1] not in ("root", "0")
    assert 'ENTRYPOINT ["helix-osint"]' in text


def test_image_is_published_only_for_releases():
    wf = _read(os.path.join(".github", "workflows", "docker.yml"))
    assert "PUBLISH: ${{ startsWith(github.ref, 'refs/tags/v') || github.event_name == 'workflow_dispatch' }}" in wf
    for step in ("docker/login-action", "Build for amd64 and arm64 and publish"):
        block = wf[wf.index(step):]
        assert "if: env.PUBLISH == 'true'" in block.split("\n\n")[0]
