"""Streamlit Community Cloud root entry point."""

import os
import sys

# Ensure repository root is on sys.path
root_dir = os.path.dirname(os.path.abspath(__file__))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Import and execute the dashboard app
import dashboard.app  # noqa: F401
