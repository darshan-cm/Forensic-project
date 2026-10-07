from datetime import datetime


class AlertManager:
    """Tracks high-risk transitions and emits desktop notifications."""

    def __init__(self):
        self._last_risk_level = None

    @staticmethod
    def _normalize_risk(risk):
        if risk is None:
            return "LOW"

        return str(risk).upper().strip()

    def process_risk(self, risk, score, evidence=None):
        """Return True when a new high-risk notification should be sent."""

        current_risk = self._normalize_risk(risk)
        evidence = evidence or []

        if current_risk in ("LOW", "MEDIUM"):
            if self._last_risk_level in ("HIGH", "CRITICAL"):
                self._last_risk_level = current_risk
            elif self._last_risk_level is None:
                self._last_risk_level = current_risk
            return False

        if current_risk == "HIGH":
            if self._last_risk_level in (None, "LOW", "MEDIUM"):
                self._last_risk_level = current_risk
                self._notify("HIGH", score, evidence)
                return True

            if self._last_risk_level == "CRITICAL":
                self._last_risk_level = current_risk
                return False

            self._last_risk_level = current_risk
            return False

        if current_risk == "CRITICAL":
            if self._last_risk_level in (None, "LOW", "MEDIUM", "HIGH"):
                self._last_risk_level = current_risk
                self._notify("CRITICAL", score, evidence)
                return True

            self._last_risk_level = current_risk
            return False

        self._last_risk_level = current_risk
        return False

    def _notify(self, risk_level, score, evidence):
        try:
            description = self._build_description(risk_level, score, evidence)
            self._show_windows_notification(risk_level, score, description)
        except Exception as error:
            print(f"[Alert Manager] Notification failed: {error}")

    def _build_description(self, risk_level, score, evidence):
        evidence_text = evidence[0] if evidence else "No significant forensic indicators."
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return (
            f"ForensicGuard\n"
            f"{risk_level} risk detected\n"
            f"Risk Score: {score}/100\n"
            f"Timestamp: {timestamp}\n"
            f"Event: {evidence_text}"
        )

    def _show_windows_notification(self, risk_level, score, description):
        try:
            import win32api
            import win32con
        except ImportError:
            print("[Alert Manager] Windows notification dependencies unavailable.")
            return

        title = "ForensicGuard"
        body = (
            f"{risk_level} Risk Detected\n"
            f"Risk Score: {score}/100\n\n"
            f"{description}"
        )

        win32api.MessageBox(
            0,
            body,
            title,
            win32con.MB_OK | win32con.MB_ICONWARNING
        )
