import sys

from PySide6.QtWidgets import QApplication

from auth.login_window import LoginWindow
from gui.main_window import MainWindow
from gui.styles import DARK_STYLE


def start_gui():

    app = QApplication(sys.argv)

    app.setStyleSheet(DARK_STYLE)

    login_window = LoginWindow()
    main_window = None

    def open_dashboard(user):
        nonlocal main_window
        login_window.hide()
        main_window = MainWindow(user)
        main_window.logout_requested.connect(show_login)
        main_window.show()

    def show_login():
        nonlocal main_window
        if main_window is not None:
            main_window.close()
            main_window.deleteLater()
            main_window = None
        login_window.show()
        login_window.raise_()
        login_window.activateWindow()

    login_window.authenticated.connect(open_dashboard)
    login_window.show()

    sys.exit(app.exec())