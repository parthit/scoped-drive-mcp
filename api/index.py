"""Vercel entry point (also works locally: `uv run uvicorn api.index:app`)."""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from scoped_drive_mcp.server import build_app  # noqa: E402

app = build_app()
