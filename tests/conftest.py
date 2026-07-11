"""Make the project root importable when running `pytest` from anywhere."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
