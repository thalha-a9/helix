"""
Terminal-safe output: only Helix's own colour codes get through.

Text from scanned pages (bios, titles, domains, evidence files someone else
wrote) can carry escape sequences that clear the screen, erase or conceal a
warning line, or retitle the terminal. Wrapping stdout/stderr in TerminalSafe
removes every escape sequence and control character except Helix's colours,
tabs and line breaks, whatever module printed them.
"""

import re
import sys

SAFE_SGR = r"\x1b\[(?:0|1|2|9[1-6])m"
UNSAFE_OUTPUT = re.compile(rf"(?!{SAFE_SGR})\x1b|[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f-\x9f]")


def clean(text: str) -> str:
    return UNSAFE_OUTPUT.sub("", text)


class TerminalSafe:
    """stdout/stderr wrapper that lets only Helix's own escape codes through."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, text):
        return self._stream.write(clean(text) if isinstance(text, str) else text)

    def __getattr__(self, name):
        return getattr(self._stream, name)


def install():
    """Wrap sys.stdout and sys.stderr once."""
    if not isinstance(sys.stdout, TerminalSafe):
        sys.stdout = TerminalSafe(sys.stdout)
    if not isinstance(sys.stderr, TerminalSafe):
        sys.stderr = TerminalSafe(sys.stderr)
