# SPDX-License-Identifier: AGPL-3.0-or-later

"""Allow running Siyarix via python -m siyarix"""

import sys
from siyarix.cli import app

if __name__ == "__main__":
    sys.exit(app())
