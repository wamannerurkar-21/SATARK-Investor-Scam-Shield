"""SATARK Streamlit entry point.

Run from the project root with:
    streamlit run app.py
"""

from __future__ import annotations

import runpy
from pathlib import Path


APP_FILE = Path(__file__).resolve().parent / "artifacts" / "satark" / "app.py"
runpy.run_path(str(APP_FILE), run_name="__main__")