from __future__ import annotations

import sys
from pathlib import Path

# 允许 `python desktop/run_desktop.py` 直接启动，且不影响仓库原有导入路径。
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PyQt6.QtWidgets import QApplication

from desktop.main_window import MainWindow
from desktop.theme import DARK, stylesheet


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("CipherLab X")
    app.setStyleSheet(stylesheet(DARK))
    window = MainWindow()
    window.qapp = app
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
