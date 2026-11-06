"""Migration runner that avoids the stdlib `platform` module name collision.

Usage:
    python migrate.py upgrade head
    python migrate.py downgrade -1
"""

import sys
import os
from pathlib import Path

# Insert project root at position 0 so our `platform/` package is found,
# but ONLY after stdlib modules are already cached. We do this by importing
# the stdlib `platform` module first under an alias, then inserting our path.
import platform as _stdlib_platform  # cache stdlib platform before path change

project_root = str(Path(__file__).resolve().parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Now run alembic programmatically
from alembic.config import Config, main as alembic_main

if __name__ == "__main__":
    alembic_main(argv=sys.argv[1:])
