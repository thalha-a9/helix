"""--phash decodes attacker-controlled pictures: only plain avatars get through."""

import io

import pytest

from helix_osint import phash

PIL = pytest.importorskip("PIL")
from PIL import Image  # noqa: E402


def _png(w=64, h=64, fmt="PNG"):
    buf = io.BytesIO()
    img = Image.new("RGB", (w, h))
    for x in range(w):                     # some structure so it is not "too plain"
        img.putpixel((x, x % h), (255, 0, 0))
    img.save(buf, format=fmt)
    return buf.getvalue()


def test_ordinary_avatars_open():
    for fmt in ("PNG", "JPEG", "GIF", "WEBP"):
        assert phash.open_avatar(_png(fmt=fmt)) is not None, fmt


@pytest.mark.parametrize("fmt", ["BMP", "TIFF", "ICO", "PPM"])
def test_unusual_formats_are_refused(fmt):
    assert phash.open_avatar(_png(fmt=fmt)) is None


def test_oversized_and_degenerate_images_are_refused():
    assert phash.open_avatar(_png(4100, 4100)) is None        # over the pixel cap
    assert phash.open_avatar(_png(4, 4)) is None              # not an avatar
    assert phash.open_avatar(b"x" * (phash.MAX_AVATAR_BYTES + 1)) is None
    assert phash.open_avatar(b"<html>not an image</html>") is None
    assert phash.open_avatar(b"") is None


def test_pillow_warning_tracks_the_safe_version(monkeypatch):
    monkeypatch.setattr(PIL, "__version__", "12.3.0")
    assert "known image-decoder vulnerabilities" in phash.pillow_warning()
    monkeypatch.setattr(PIL, "__version__", "13.0.0")
    assert phash.pillow_warning() == ""


@pytest.mark.parametrize("url", [
    "https://github.com/opengraph.png",                                   # every gist page
    "https://github.githubassets.com/images/modules/open_graph/github-logo.png",
    "https://dev-to-uploads.s3.amazonaws.com/uploads/articles/3ot.png",   # DEV's site card
    "https://example.com/static/default-avatar.png",
    "https://cdn.example.com/img/placeholder.jpg",
])
def test_site_wide_images_are_never_hashed_as_avatars(url):
    # Two people's pages carrying the same site image must not read as "same picture".
    assert phash.is_default_image(url)


@pytest.mark.parametrize("url", [
    "https://avatars.githubusercontent.com/u/177346026?v=4",
    "https://media.dev.to/cdn-cgi/image/width=320/https://dev-to-uploads.s3.amazonaws.com/uploads/user/profile_image/1/a.png",
    "https://pbs.twimg.com/profile_images/1/abc_400x400.jpg",
])
def test_real_profile_pictures_are_kept(url):
    assert not phash.is_default_image(url)
