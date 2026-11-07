"""Shared UUID7 utility.

Provides a uuid7() function that works on Python >= 3.11 by using
the standard library when available (3.12+) or a compatibility shim
for earlier versions.

Import this from anywhere in the codebase:
    from ascense.utils.uuid7 import uuid7

This avoids the fragile import-order dependency of the monkey-patching
approach in ascense/__init__.py.
"""

from __future__ import annotations

import secrets
import time
import uuid

if hasattr(uuid, "uuid7"):
    # Python 3.12+ has native uuid7
    uuid7 = uuid.uuid7
else:
    def uuid7() -> uuid.UUID:
        """Generate a UUIDv7 (time-ordered, RFC 4122 compliant).

        Uses current timestamp in milliseconds plus random bits.
        Works on Python < 3.12 where uuid7 is not in the standard library.
        """
        timestamp_ms = int(time.time() * 1000)
        rand_a = secrets.randbits(12)
        rand_b = secrets.randbits(62)
        uuid_int = (timestamp_ms & 0xFFFFFFFFFFFF) << 80
        uuid_int |= 0x7 << 76  # version 7
        uuid_int |= (rand_a & 0xFFF) << 64
        uuid_int |= 0b10 << 62  # variant 10 (RFC 4122)
        uuid_int |= rand_b & 0x3FFFFFFFFFFFFFFF
        return uuid.UUID(int=uuid_int)
