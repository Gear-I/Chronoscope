"""Entry point for Chronoscope.exe, the desktop app in the Windows build.

A case folder may be passed as the first argument (or dropped onto the .exe). With
``--smoke-test`` it builds the main window offscreen and exits 0, so CI can check that Qt and
every optional parser were bundled; a windowed .exe has no console to print to.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def smoke_test() -> int:
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PySide6.QtWidgets import QApplication

    from chronoscope.gui import MainWindow
    from chronoscope.parsers import discover

    app = QApplication(sys.argv[:1])
    window = MainWindow()
    window.close()
    app.processEvents()
    return 3 if discover().unavailable else 0


def main() -> int:
    if sys.argv[1:] == ["--smoke-test"]:
        return smoke_test()
    from chronoscope.gui import run

    return run(Path(sys.argv[1]) if len(sys.argv) > 1 else None)


if __name__ == "__main__":
    sys.exit(main())
