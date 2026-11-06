"""Pytest configuration and Python compatibility shims.

Provides uuid7 on Python < 3.12 (where it was added to the stdlib uuid module).
The project targets Python 3.12 in production; this shim enables local
development and testing on Python 3.11.
"""

from __future__ import annotations

import secrets
import time
import uuid as _uuid_mod

if not hasattr(_uuid_mod, "uuid7"):
    def _uuid7() -> _uuid_mod.UUID:
        """Generate a UUIDv7 (time-ordered, RFC 9562).

        Layout:
          - 48 bits: Unix timestamp in milliseconds
          - 4 bits: version (7)
          - 12 bits: random
          - 2 bits: variant (10)
          - 62 bits: random
        """
        timestamp_ms = int(time.time() * 1000)
        rand_a = secrets.randbits(12)
        rand_b = secrets.randbits(62)

        uuid_int = (timestamp_ms & 0xFFFFFFFFFFFF) << 80
        uuid_int |= 0x7 << 76          # version
        uuid_int |= (rand_a & 0xFFF) << 64
        uuid_int |= 0b10 << 62         # variant
        uuid_int |= rand_b & 0x3FFFFFFFFFFFFFFF

        return _uuid_mod.UUID(int=uuid_int)

    _uuid_mod.uuid7 = _uuid7
