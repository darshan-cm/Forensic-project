import sys

from PySide6.QtWidgets import QApplication

from gui.main_window import MainWindow

from gui.styles import DARK_STYLE


def start_gui():

    app = QApplication(sys.argv)

    app.setStyleSheet(DARK_STYLE)

    window = MainWindow()

    window.show()

    sys.exit(app.exec())