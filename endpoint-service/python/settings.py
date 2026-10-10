"""Repository-local paths and target architecture, shared by guest drivers."""

from pathlib import Path
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(
    0, str(ROOT.parent if ROOT.name in ("module-free", "endpoint-service") else ROOT)
)
from shared.python.backend_settings import configure_backend

globals().update(configure_backend(ROOT))
