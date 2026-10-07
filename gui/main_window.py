import csv
from datetime import datetime

from alerts.alert_manager import AlertManager
from database.database import get_all_events
from detection.risk_engine import assess_risk

from PySide6.QtCore import Qt, QTimer, Signal

from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QFrame,
    QFileDialog,
    QMessageBox,
    QAbstractItemView
)

from gui.controller import MonitorController
from reports.forensic_report import ForensicSession
from supabase.auth import sign_out


# ============================================================
# STAT CARD
# ============================================================

class StatCard(QFrame):

    def __init__(self, title, value="0", icon=""):

        super().__init__()

        self.setObjectName("StatCard")

        layout = QVBoxLayout(self)

        layout.setContentsMargins(
            18, 14, 18, 14
        )

        layout.setSpacing(4)

        # -------------------------------
        # Top row
        # -------------------------------

        top = QHBoxLayout()

        title_label = QLabel(
            f"{icon}  {title}"
        )

        title_label.setObjectName(
            "CardTitle"
        )

        top.addWidget(
            title_label
        )

        top.addStretch()

        layout.addLayout(
            top
        )

        # -------------------------------
        # Value
        # -------------------------------

        self.value_label = QLabel(
            str(value)
        )

        self.value_label.setObjectName(
            "CardValue"
        )

        layout.addWidget(
            self.value_label
        )


    def set_value(self, value):

        self.value_label.setText(
            str(value)
        )


# ============================================================
# MAIN WINDOW
# ============================================================

class MainWindow(QMainWindow):

    logout_requested = Signal()

    def __init__(self, current_user=None):

        super().__init__()

        self.setWindowTitle(
            "ForensicGuard - Digital Forensics Dashboard"
        )

        self.resize(
            1500,
            900
        )

        self.controller = MonitorController()
        self.alert_manager = AlertManager()
        self.current_user = current_user
        self.forensic_session = ForensicSession.start(current_user)

        self.build_ui()

        # ====================================================
        # REFRESH TIMER
        # ====================================================

        self.timer = QTimer()

        self.timer.timeout.connect(
            self.refresh_dashboard
        )

        self.timer.start(
            1000
        )

        self.refresh_dashboard()


    # ========================================================
    # BUILD UI
    # ========================================================

    def build_ui(self):

        central = QWidget()

        self.setCentralWidget(
            central
        )

        main_layout = QVBoxLayout(
            central
        )

        main_layout.setContentsMargins(
            20, 18, 20, 15
        )

        main_layout.setSpacing(
            12
        )


        # ====================================================
        # HEADER
        # ====================================================

        header = QHBoxLayout()

        header.setSpacing(
            15
        )


        # -------------------------------
        # Branding
        # -------------------------------

        brand_layout = QVBoxLayout()

        brand_layout.setSpacing(
            2
        )


        title = QLabel(
            "🛡  FORENSICGUARD"
        )

        title.setObjectName(
            "Title"
        )


        subtitle = QLabel(
            "Real-Time Endpoint Forensics & Security Monitoring"
        )

        subtitle.setObjectName(
            "Subtitle"
        )


        brand_layout.addWidget(
            title
        )

        brand_layout.addWidget(
            subtitle
        )


        header.addLayout(
            brand_layout
        )

        header.addStretch()


        # -------------------------------
        # Monitoring status
        # -------------------------------

        self.status = QLabel(
            "●  Monitoring Stopped"
        )

        self.status.setObjectName(
            "StatusStopped"
        )

        self.status.setAlignment(
            Qt.AlignCenter
        )


        header.addWidget(
            self.status
        )

        self.report_button = QPushButton("Generate Forensic Report")
        self.report_button.clicked.connect(self._generate_forensic_report)
        header.addWidget(self.report_button)

        self.logout_button = QPushButton("Generate Report & Logout")
        self.logout_button.clicked.connect(self._logout)
        header.addWidget(self.logout_button)


        main_layout.addLayout(
            header
        )


        # ====================================================
        # STATISTICS
        # ====================================================

        cards = QHBoxLayout()

        cards.setSpacing(
            10
        )


        self.total_card = StatCard(
            "Total Events",
            "0",
            "◉"
        )


        self.file_card = StatCard(
            "File Activity",
            "0",
            "▣"
        )


        self.usb_card = StatCard(
            "USB Activity",
            "0",
            "▤"
        )


        self.security_card = StatCard(
            "Security Events",
            "0",
            "⚠"
        )


        cards.addWidget(
            self.total_card
        )

        cards.addWidget(
            self.file_card
        )

        cards.addWidget(
            self.usb_card
        )

        cards.addWidget(
            self.security_card
        )


        main_layout.addLayout(
            cards
        )


        # ====================================================
        # RISK + ACTIVITY SUMMARY
        # ====================================================

        summary = QHBoxLayout()

        summary.setSpacing(
            10
        )


        # ====================================================
        # RISK CARD
        # ====================================================

        risk_frame = QFrame()

        risk_frame.setObjectName(
            "RiskCard"
        )


        risk_layout = QVBoxLayout(
            risk_frame
        )

        risk_layout.setContentsMargins(
            18, 14, 18, 14
        )

        risk_layout.setSpacing(
            6
        )


        # Header

        risk_header = QHBoxLayout()


        risk_title = QLabel(
            "🛡  FORENSIC RISK"
        )

        risk_title.setObjectName(
            "SectionTitle"
        )


        risk_header.addWidget(
            risk_title
        )

        risk_header.addStretch()


        self.risk_badge = QLabel(
            "LOW"
        )

        self.risk_badge.setObjectName(
            "RiskBadge"
        )

        self.risk_badge.setAlignment(
            Qt.AlignCenter
        )


        risk_header.addWidget(
            self.risk_badge
        )


        risk_layout.addLayout(
            risk_header
        )


        # Score

        score_row = QHBoxLayout()


        score_label = QLabel(
            "Risk Score"
        )

        score_label.setObjectName(
            "MutedText"
        )


        self.risk_score = QLabel(
            "0 / 100"
        )

        self.risk_score.setObjectName(
            "RiskScore"
        )


        score_row.addWidget(
            score_label
        )

        score_row.addStretch()

        score_row.addWidget(
            self.risk_score
        )


        risk_layout.addLayout(
            score_row
        )


        # Transfer status

        transfer_row = QHBoxLayout()


        transfer_label = QLabel(
            "Transfer Status"
        )

        transfer_label.setObjectName(
            "MutedText"
        )


        self.transfer_status = QLabel(
            "NO FILE TRANSFER DETECTED"
        )

        self.transfer_status.setObjectName(
            "TransferStatus"
        )


        transfer_row.addWidget(
            transfer_label
        )

        transfer_row.addStretch()

        transfer_row.addWidget(
            self.transfer_status
        )


        risk_layout.addLayout(
            transfer_row
        )


        summary.addWidget(
            risk_frame,
            1
        )


        # ====================================================
        # EVIDENCE CARD
        # ====================================================

        evidence_frame = QFrame()

        evidence_frame.setObjectName(
            "EvidenceCard"
        )


        evidence_layout = QVBoxLayout(
            evidence_frame
        )

        evidence_layout.setContentsMargins(
            18, 14, 18, 14
        )


        evidence_title = QLabel(
            "Evidence Summary"
        )

        evidence_title.setObjectName(
            "SectionTitle"
        )


        evidence_layout.addWidget(
            evidence_title
        )


        self.risk_details = QLabel(
            "No significant forensic indicators."
        )

        self.risk_details.setObjectName(
            "EvidenceText"
        )

        self.risk_details.setWordWrap(
            True
        )


        evidence_layout.addWidget(
            self.risk_details
        )


        summary.addWidget(
            evidence_frame,
            1
        )


        main_layout.addLayout(
            summary
        )


        # ====================================================
        # SEARCH BAR
        # ====================================================

        search_frame = QFrame()

        search_frame.setObjectName(
            "SearchFrame"
        )


        search_layout = QHBoxLayout(
            search_frame
        )

        search_layout.setContentsMargins(
            10, 5, 10, 5
        )


        search_icon = QLabel(
            "🔍"
        )


        self.search = QLineEdit()

        self.search.setPlaceholderText(
            "Search events by source, action, application, event ID..."
        )

        self.search.setObjectName(
            "SearchBox"
        )


        search_layout.addWidget(
            search_icon
        )

        search_layout.addWidget(
            self.search
        )


        self.search.textChanged.connect(
            self.refresh_dashboard
        )


        main_layout.addWidget(
            search_frame
        )


        # ====================================================
        # TABLE HEADER
        # ====================================================

        table_header = QHBoxLayout()


        activity_title = QLabel(
            "Recent Forensic Activity"
        )

        activity_title.setObjectName(
            "SectionTitle"
        )


        table_header.addWidget(
            activity_title
        )


        table_header.addStretch()


        self.event_count_label = QLabel(
            "0 events"
        )

        self.event_count_label.setObjectName(
            "MutedText"
        )


        table_header.addWidget(
            self.event_count_label
        )


        main_layout.addLayout(
            table_header
        )


        # ====================================================
        # EVENT TABLE
        # ====================================================

        self.table = QTableWidget()

        self.table.setColumnCount(
            6
        )


        self.table.setHorizontalHeaderLabels([
            "TIME",
            "SOURCE",
            "EVENT",
            "ACTION",
            "APPLICATION",
            "DETAILS"
        ])


        table_header_view = (
            self.table.horizontalHeader()
        )


        table_header_view.setSectionResizeMode(
            QHeaderView.Interactive
        )


        table_header_view.setStretchLastSection(
            True
        )


        # Better column widths

        self.table.setColumnWidth(
            0,
            160
        )

        self.table.setColumnWidth(
            1,
            150
        )

        self.table.setColumnWidth(
            2,
            150
        )

        self.table.setColumnWidth(
            3,
            190
        )

        self.table.setColumnWidth(
            4,
            320
        )


        self.table.setAlternatingRowColors(
            True
        )


        self.table.setSelectionBehavior(
            QAbstractItemView.SelectRows
        )


        self.table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )


        self.table.setWordWrap(
            False
        )


        self.table.verticalHeader().setDefaultSectionSize(
            34
        )


        main_layout.addWidget(
            self.table,
            1
        )


        # ====================================================
        # BOTTOM CONTROL BAR
        # ====================================================

        controls = QHBoxLayout()

        controls.setSpacing(
            8
        )


        self.start_btn = QPushButton(
            "▶  Start Monitoring"
        )

        self.start_btn.setObjectName(
            "PrimaryButton"
        )


        self.stop_btn = QPushButton(
            "■  Stop Monitoring"
        )

        self.stop_btn.setObjectName(
            "DangerButton"
        )


        self.export_btn = QPushButton(
            "⇩  Export CSV"
        )

        self.export_btn.setObjectName(
            "SecondaryButton"
        )


        self.start_btn.clicked.connect(
            self.start_monitoring
        )

        self.stop_btn.clicked.connect(
            self.stop_monitoring
        )

        self.export_btn.clicked.connect(
            self.export_csv
        )


        controls.addWidget(
            self.start_btn
        )

        controls.addWidget(
            self.stop_btn
        )

        controls.addStretch()

        controls.addWidget(
            self.export_btn
        )


        main_layout.addLayout(
            controls
        )


    # ========================================================
    # START MONITORING
    # ========================================================

    def start_monitoring(self):

        started = (
            self.controller.start()
        )


        if started or self.controller.is_running():

            self.status.setText(
                "●  Monitoring Active"
            )

            self.status.setObjectName(
                "StatusActive"
            )

        else:

            self.status.setText(
                "●  Monitoring Stopped"
            )

            self.status.setObjectName(
                "StatusStopped"
            )


        self.status.style().unpolish(
            self.status
        )

        self.status.style().polish(
            self.status
        )


        self.refresh_dashboard()


    # ========================================================
    # STOP MONITORING
    # ========================================================

    def stop_monitoring(self):

        self.controller.stop()


        self.status.setText(
            "●  Monitoring Stopped"
        )

        self.status.setObjectName(
            "StatusStopped"
        )


        self.status.style().unpolish(
            self.status
        )

        self.status.style().polish(
            self.status
        )


        self.refresh_dashboard()


    # ========================================================
    # REFRESH DASHBOARD
    # ========================================================

    def refresh_dashboard(self):

        try:

            events = get_all_events()


            # =================================================
            # SEARCH
            # =================================================

            search_text = (
                self.search.text()
                .lower()
                .strip()
            )


            if search_text:

                events = [

                    event

                    for event in events

                    if any(
                        search_text
                        in str(value).lower()

                        for value in event
                    )
                ]


            # =================================================
            # TABLE
            # =================================================

            self.table.setRowCount(
                len(events)
            )


            for row, event in enumerate(
                events
            ):

                for col, value in enumerate(
                    event
                ):

                    item = QTableWidgetItem(
                        str(value)
                    )

                    self.table.setItem(
                        row,
                        col,
                        item
                    )


            # =================================================
            # STATISTICS
            # =================================================

            total = len(events)


            file_events = sum(

                1

                for event in events

                if "FILE"
                in str(event[2]).upper()
            )


            usb_events = sum(

                1

                for event in events

                if "USB"
                in str(event[2]).upper()
            )


            security_events = sum(

                1

                for event in events

                if str(event[1]).lower()
                == "security monitor"
            )


            self.total_card.set_value(
                total
            )

            self.file_card.set_value(
                file_events
            )

            self.usb_card.set_value(
                usb_events
            )

            self.security_card.set_value(
                security_events
            )


            self.event_count_label.setText(
                f"{total} events shown"
            )


            # =================================================
            # MONITORING STATUS
            # =================================================

            if self.controller.is_running():

                self.status.setText(
                    "●  Monitoring Active"
                )

                self.status.setObjectName(
                    "StatusActive"
                )

            else:

                self.status.setText(
                    "●  Monitoring Stopped"
                )

                self.status.setObjectName(
                    "StatusStopped"
                )


            self.status.style().unpolish(
                self.status
            )

            self.status.style().polish(
                self.status
            )


            # =================================================
            # RISK ENGINE
            # =================================================

            self.refresh_risk()


        except Exception as error:

            print(
                f"[Dashboard] Refresh error: {error}"
            )


    # ========================================================
    # RISK ASSESSMENT
    # ========================================================

    def refresh_risk(self):

        try:

            result = assess_risk()


            risk = result.get(
                "risk",
                "LOW"
            )

            score = result.get(
                "score",
                0
            )


            usb_devices = result.get(
                "usb_connections",
                0
            )


            files_copied = result.get(
                "files_copied",
                0
            )


            security_events = result.get(
                "security_events",
                0
            )


            transfer_size = result.get(
                "total_copy_size_display",
                "0 KB"
            )


            transfer_status = result.get(
                "transfer_status",
                "NO FILE TRANSFER DETECTED"
            )


            evidence = result.get(
                "evidence",
                []
            )


            # =================================================
            # RISK BADGE
            # =================================================

            self.risk_badge.setText(
                risk
            )


            if risk == "HIGH":

                self.risk_badge.setObjectName(
                    "RiskHigh"
                )

            elif risk == "MEDIUM":

                self.risk_badge.setObjectName(
                    "RiskMedium"
                )

            else:

                self.risk_badge.setObjectName(
                    "RiskLow"
                )


            self.risk_badge.style().unpolish(
                self.risk_badge
            )

            self.risk_badge.style().polish(
                self.risk_badge
            )


            # =================================================
            # SCORE
            # =================================================

            self.risk_score.setText(
                f"{score} / 100"
            )


            # =================================================
            # TRANSFER STATUS
            # =================================================

            self.transfer_status.setText(
                transfer_status
            )


            # =================================================
            # TRANSFER SIZE + COUNTS
            # =================================================

            summary_text = (
                f"<b>USB:</b> {usb_devices}"
                f"&nbsp;&nbsp;&nbsp;"
                f"<b>Files:</b> {files_copied}"
                f"&nbsp;&nbsp;&nbsp;"
                f"<b>Volume:</b> {transfer_size}"
                f"&nbsp;&nbsp;&nbsp;"
                f"<b>Security:</b> {security_events}"
            )


            # =================================================
            # EVIDENCE
            # =================================================

            if evidence:

                evidence_lines = "<br>".join(

                    f"• {item}"

                    for item in evidence
                )

            else:

                evidence_lines = (
                    "• No significant forensic indicators."
                )


            self.risk_details.setText(
                summary_text
                + "<br><br>"
                + evidence_lines
            )


        except Exception as error:

            print(
                f"[Risk Engine] {error}"
            )

            self.risk_badge.setText(
                "ERROR"
            )

            self.risk_score.setText(
                "—"
            )

            self.risk_details.setText(
                "Risk assessment unavailable."
            )


    # ========================================================
    # EXPORT
    # ========================================================

    def export_csv(self):

        events = get_all_events()


        if not events:

            QMessageBox.information(
                self,
                "ForensicGuard",
                "No forensic events available."
            )

            return


        file_path, _ = (
            QFileDialog.getSaveFileName(
                self,
                "Export Forensic Report",
                "forensic_events.csv",
                "CSV Files (*.csv)"
            )
        )


        if not file_path:

            return


        try:

            with open(
                file_path,
                "w",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.writer(
                    file
                )


                writer.writerow([
                    "Time",
                    "Source",
                    "Event ID",
                    "Action",
                    "Application",
                    "Details"
                ])


                writer.writerows(
                    events
                )


            QMessageBox.information(
                self,
                "ForensicGuard",
                "Forensic event report exported successfully."
            )


        except Exception as error:

            QMessageBox.critical(
                self,
                "Export Error",
                f"Could not export report:\n{error}"
            )


    # ========================================================
    # CLOSE
    # ========================================================

    def _logout(self):
        report_path = self._create_forensic_report()
        if report_path is None:
            return
        QMessageBox.information(
            self,
            "Forensic report generated",
            str(report_path),
        )
        try:
            sign_out()
        except Exception as error:
            QMessageBox.warning(self, "Logout failed", str(error))
            return
        self.logout_requested.emit()

    def _generate_forensic_report(self):
        report_path = self._create_forensic_report()
        if report_path is not None:
            QMessageBox.information(
                self,
                "Forensic report generated",
                str(report_path),
            )

    def _create_forensic_report(self):
        end_time = datetime.now().astimezone()
        try:
            return self.forensic_session.generate_report(end_time)
        except Exception as error:
            QMessageBox.critical(
                self,
                "Forensic report failed",
                f"The report could not be generated. You remain signed in.\n{error}",
            )
            return None

    def closeEvent(self, event):

        try:

            self.timer.stop()

            self.controller.stop()

        except Exception:
            pass


        event.accept()