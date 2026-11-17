"""Entry point of the packaged application (PyInstaller)."""

import sys

from coldperimeter.gui.app import main

if __name__ == "__main__":
    sys.exit(main())
