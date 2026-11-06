"""Ascense platform package.

Applies the uuid7 compatibility shim for Python < 3.12 at import time
so every submodule can safely use `from uuid import uuid7`.
"""

from __future__ import annotations

import secrets
import time
import uuid as _uuid_mod

if not hasattr(_uuid_mod, "uuid7"):
    def _uuid7() -> _uuid_mod.UUID:
        timestamp_ms = int(time.time() * 1000)
        rand_a = secrets.randbits(12)
        rand_b = secrets.randbits(62)
        uuid_int = (timestamp_ms & 0xFFFFFFFFFFFF) << 80
        uuid_int |= 0x7 << 76
        uuid_int |= (rand_a & 0xFFF) << 64
        uuid_int |= 0b10 << 62
        uuid_int |= rand_b & 0x3FFFFFFFFFFFFFFF
        return _uuid_mod.UUID(int=uuid_int)

    _uuid_mod.uuid7 = _uuid7  # type: ignore[attr-defined]
