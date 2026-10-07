"""Login and signup window for Supabase authentication."""

import re

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from supabase.auth import get_current_user, sign_in, sign_up


class LoginWindow(QMainWindow):
    authenticated = Signal(object)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("ForensicGuard - Sign In")
        self.setFixedSize(460, 360)
        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(42, 34, 42, 34)
        layout.setSpacing(14)

        title = QLabel("FORENSICGUARD")
        title.setObjectName("Title")
        subtitle = QLabel("Sign in to your security dashboard")
        subtitle.setObjectName("Subtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        form = QFormLayout()
        form.setSpacing(10)
        self.email = QLineEdit()
        self.email.setPlaceholderText("name@example.com")
        self.password = QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.Password)
        form.addRow("Email", self.email)
        form.addRow("Password", self.password)
        layout.addLayout(form)

        self.show_password = QCheckBox("Show password")
        self.show_password.toggled.connect(self._toggle_password)
        layout.addWidget(self.show_password)

        buttons = QHBoxLayout()
        self.login_button = QPushButton("Sign In")
        self.signup_button = QPushButton("Create Account")
        self.login_button.clicked.connect(self._sign_in)
        self.signup_button.clicked.connect(self._sign_up)
        buttons.addWidget(self.login_button)
        buttons.addWidget(self.signup_button)
        layout.addLayout(buttons)

        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        layout.addStretch()

    def _toggle_password(self, visible):
        self.password.setEchoMode(
            QLineEdit.Normal if visible else QLineEdit.Password
        )

    def _credentials(self, require_valid_email=False):
        email = self.email.text().strip()
        password = self.password.text()
        if not email:
            self._show_status("Enter your email address.", error=True)
            return None
        if require_valid_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            self._show_status("Enter a valid email address.", error=True)
            return None
        if not password:
            self._show_status("Enter your password.", error=True)
            return None
        return email, password

    def _sign_in(self):
        credentials = self._credentials()
        if credentials is None:
            return
        email, password = credentials
        try:
            sign_in(email, password)
            user_response = get_current_user()
            if user_response.user is None:
                raise RuntimeError("No authenticated user was returned.")
        except Exception as error:
            self._show_status(str(error), error=True)
            return
        self._show_status("")
        self.authenticated.emit(user_response.user)

    def _sign_up(self):
        credentials = self._credentials(require_valid_email=True)
        if credentials is None:
            return
        email, password = credentials
        try:
            response = sign_up(email, password)
        except Exception as error:
            self._show_status(str(error), error=True)
            return
        if response.user is None:
            self._show_status("Account could not be created.", error=True)
            return
        self._show_status(
            "Account created successfully. Verify your email if confirmation is required."
        )

    def _show_status(self, message, error=False):
        self.status.setText(message)
        self.status.setStyleSheet("color: #F87171;" if error else "color: #4ADE80;")