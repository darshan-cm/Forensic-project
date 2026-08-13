import csv
from database.database import get_all_events
from PySide6.QtCore import Qt, QTimer

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
    QFileDialog
)


class StatCard(QFrame):

    def __init__(self, title, value):

        super().__init__()

        self.setStyleSheet("""
            QFrame{
                background:#2D2D30;
                border-radius:10px;
            }

            QLabel{
                color:white;
            }
        """)

        layout = QVBoxLayout(self)

        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignCenter)

        value_label = QLabel(value)
        value_label.setAlignment(Qt.AlignCenter)
        value_label.setStyleSheet("""
            font-size:26px;
            font-weight:bold;
        """)

        layout.addWidget(title_label)
        layout.addWidget(value_label)


class MainWindow(QMainWindow):

    def __init__(self):

        super().__init__()

        self.setWindowTitle("ForensicGuard")

        self.resize(1400,800)

        central = QWidget()

        self.setCentralWidget(central)

        main_layout = QVBoxLayout()

        central.setLayout(main_layout)

        # ================= Header =================

        header = QHBoxLayout()

        title = QLabel("🛡 FORENSICGUARD")

        title.setStyleSheet("""
            font-size:28px;
            font-weight:bold;
        """)

        status = QLabel("🟢 Monitoring")

        status.setAlignment(Qt.AlignRight)

        status.setStyleSheet("""
            font-size:16px;
            color:#00FF7F;
        """)

        header.addWidget(title)

        header.addStretch()

        header.addWidget(status)

        main_layout.addLayout(header)

        # ================= Cards =================

        cards = QHBoxLayout()

        self.total_events = StatCard("Total Events", "0")
        self.processes = StatCard("Processes", "0")
        self.files = StatCard("File Events", "0")
        self.windows = StatCard("Active Window", "-")

        cards.addWidget(self.total_events)
        cards.addWidget(self.processes)
        cards.addWidget(self.files)
        cards.addWidget(self.windows)

        main_layout.addLayout(cards)

        # ================= Search =================

        self.search = QLineEdit()

        self.search.setPlaceholderText("Search...")

        self.search.setMinimumHeight(35)
        self.search.textChanged.connect(self.load_events)

        main_layout.addWidget(self.search)

        # ================= Table =================

        self.table = QTableWidget()

        self.table.setColumnCount(6)

        self.table.setHorizontalHeaderLabels(
            [
                "Time",
                "Source",
                "Event ID",
                "Action",
                "Application",
                "Details"
            ]
        )

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)

        main_layout.addWidget(self.table)

        # ================= Buttons =================

        buttons = QHBoxLayout()

        self.start_btn = QPushButton("▶ Start Monitoring")

        self.stop_btn = QPushButton("■ Stop Monitoring")

        self.export_btn = QPushButton("📤 Export CSV")
        self.export_btn.clicked.connect(self.export_csv)
        
        buttons.addWidget(self.start_btn)

        buttons.addWidget(self.stop_btn)

        buttons.addStretch()

        buttons.addWidget(self.export_btn)

        main_layout.addLayout(buttons)
        
        self.timer = QTimer()

        self.timer.timeout.connect(self.load_events)

        self.timer.start(1000)

        self.load_events()
        
    def load_events(self):

        events = get_all_events()

        search_text = self.search.text().lower().strip()

        if search_text:
            events = [
                event for event in events
                if any(search_text in str(value).lower() for value in event)
            ]

        self.table.setRowCount(len(events))

        for row, event in enumerate(events):

            for col, value in enumerate(event):

                self.table.setItem(
                    row,
                    col,
                    QTableWidgetItem(str(value))
                )

        # Update Total Events card
        labels = self.total_events.findChildren(QLabel)

        if len(labels) >= 2:
            labels[1].setText(str(len(events)))
            
            
    def export_csv(self):

        events = get_all_events()

        if not events:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Events",
            "forensic_events.csv",
            "CSV Files (*.csv)"
        )

        if not file_path:
            return

        with open(file_path, "w", newline="", encoding="utf-8") as file:

            writer = csv.writer(file)

            writer.writerow([
                "Time",
                "Source",
                "Event ID",
                "Action",
                "Application",
                "Details"
            ])

            writer.writerows(events)