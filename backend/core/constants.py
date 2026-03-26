"""Application constants."""

import os
from pathlib import Path

DIVIDER = "-" * 80

ALLOWED_TARGETS = os.getenv("ALLOWED_TARGETS", "target,localhost,127.0.0.1").split(",")

REPO_CLONE_ROOT = Path(os.getenv("REPO_CLONE_ROOT", "/tmp/lumina/repos")).resolve()
REPO_CLONE_TIMEOUT_SECONDS = int(os.getenv("REPO_CLONE_TIMEOUT_SECONDS", "180"))
REPO_CLONE_DEPTH = int(os.getenv("REPO_CLONE_DEPTH", "1"))
