"""Allow running Siyarix via python -m siyarix"""
import sys
from siyarix.main import app

if __name__ == "__main__":
    sys.exit(app())
