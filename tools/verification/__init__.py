"""Compiler-backed verification of context-dependent return policies."""

from hashlib import sha256
from pathlib import Path

__version__ = "0.1.0"


def _source_hashes():
    return {p.name: sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob("*.py")}


_IMPORTED_SOURCES = _source_hashes()


def implementation_dependencies():
    current = _source_hashes()
    if current != _IMPORTED_SOURCES:
        raise ValueError("verification implementation changed after import; restart verification")
    return current
