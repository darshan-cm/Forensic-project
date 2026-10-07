import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from detection.rule_registry import get_rule
from detection.risk_engine import _detect_file_burst_rules
from gui.main_window import MainWindow
from monitors.file_monitor import FileMonitorHandler
from reports.forensic_report import ForensicSession


@contextmanager
def _connection(path):
    connection = sqlite3.connect(path)
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


class ForensicReportTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="forensic_report_test_")
        self.root = Path(self.temp_dir.name)
        self.forensic_db = self.root / "forensic.db"
        self.risk_db = self.root / "riskalert.db"
        self.report_dir = self.root / "reports"
        self._create_databases()
        self.user = SimpleNamespace(id="test-user-id", email="must-not-be-reported@example.invalid")
        self.session = ForensicSession.start(
            self.user,
            forensic_db_path=self.forensic_db,
            risk_db_path=self.risk_db,
            report_directory=self.report_dir,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_databases(self):
        with _connection(self.forensic_db) as connection:
            connection.execute(
                """
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    source TEXT,
                    event_id TEXT,
                    action TEXT,
                    application TEXT,
                    details TEXT
                )
                """
            )
            connection.execute(
                """
                INSERT INTO events
                    (timestamp, source, event_id, action, application, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "File Monitor",
                    "FILE_CREATE",
                    "Created before login",
                    "baseline.txt",
                    "Baseline event",
                ),
            )
        with _connection(self.risk_db) as connection:
            connection.executescript(
                """
                CREATE TABLE risk_assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    activity_type TEXT,
                    trigger_event_id TEXT,
                    trigger_event_source TEXT,
                    trigger_application TEXT,
                    trigger_details TEXT,
                    rule_id INTEGER,
                    rule_name TEXT,
                    evidence_summary TEXT,
                    alert_message TEXT
                );
                CREATE TABLE risk_evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    risk_id INTEGER NOT NULL,
                    evidence_text TEXT,
                    event_id TEXT,
                    event_source TEXT,
                    details TEXT,
                    file_path TEXT,
                    source_path TEXT,
                    destination_path TEXT,
                    usb_device TEXT
                );
                """
            )
            connection.execute(
                """
                INSERT INTO risk_assessments
                    (timestamp, risk_level, risk_score, activity_type)
                VALUES (?, 'LOW', 0, 'Forensic Risk Engine')
                """,
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),),
            )

    def _persist_file_event(self, source, event_id, action, application, details):
        with _connection(self.forensic_db) as connection:
            connection.execute(
                """
                INSERT INTO events
                    (timestamp, source, event_id, action, application, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    source,
                    event_id,
                    action,
                    application,
                    details,
                ),
            )

    def _perform_file_monitor_activity(self):
        test_folder = self.root / "monitored_test_files"
        test_folder.mkdir()
        handler = FileMonitorHandler()
        files = [test_folder / f"sample_{index}.txt" for index in range(5)]
        with patch(
            "monitors.file_monitor.log_event",
            side_effect=self._persist_file_event,
        ):
            for path in files:
                path.write_text("initial test content", encoding="utf-8")
                handler.on_created(
                    SimpleNamespace(is_directory=False, src_path=str(path))
                )
            for path in files:
                path.write_text("modified test content", encoding="utf-8")
                handler.on_modified(
                    SimpleNamespace(is_directory=False, src_path=str(path))
                )
            renamed = files[0].with_name("renamed_sample.txt")
            files[0].rename(renamed)
            handler.on_moved(
                SimpleNamespace(
                    is_directory=False,
                    src_path=str(files[0]),
                    dest_path=str(renamed),
                )
            )
            files[0] = renamed
            for path in files:
                path.unlink()
                handler.on_deleted(
                    SimpleNamespace(is_directory=False, src_path=str(path))
                )
        self.assertEqual(list(test_folder.iterdir()), [])
        test_folder.rmdir()

    def _insert_session_risks(self):
        with _connection(self.forensic_db) as connection:
            create_events = connection.execute(
                """
                SELECT id, timestamp, source, event_id, action, application, details
                FROM events
                WHERE event_id = 'FILE_CREATE'
                ORDER BY id
                """
            ).fetchall()
        trigger_row = create_events[-1]
        detected = _detect_file_burst_rules(
            create_events,
            {
                "timestamp": trigger_row[1],
                "source": trigger_row[2],
                "event_id": trigger_row[3],
                "action": trigger_row[4],
                "application": trigger_row[5],
                "details": trigger_row[6],
            },
        )
        rule = next(item for item in detected if item["rule_id"] == 47)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with _connection(self.risk_db) as connection:
            connection.execute(
                """
                INSERT INTO risk_assessments (
                    timestamp, risk_level, risk_score, activity_type,
                    trigger_event_id, trigger_event_source, trigger_application,
                    trigger_details, rule_id, rule_name, evidence_summary
                ) VALUES (?, 'MEDIUM', 57, 'File Activity', 'FILE_CREATE',
                          'File Monitor', 'sample_4.txt', ?, ?, ?, ?)
                """,
                (
                    now,
                    rule["evidence"],
                    rule["rule_id"],
                    rule["rule_name"],
                    "5 temporary text files created.",
                ),
            )
            risk_id = connection.execute(
                "SELECT MAX(id) FROM risk_assessments"
            ).fetchone()[0]
            connection.execute(
                """
                INSERT INTO risk_evidence
                    (risk_id, evidence_text, event_id, event_source, details, file_path)
                VALUES (?, ?, 'FILE_CREATE', 'File Monitor', ?, ?)
                """,
                (
                    risk_id,
                    "Five distinct temporary text-file paths.",
                    "Bulk creation observed in the test folder.",
                    str(self.root / "monitored_test_files"),
                ),
            )
            connection.execute(
                """
                INSERT INTO risk_assessments
                    (timestamp, risk_level, risk_score, activity_type)
                VALUES (?, 'LOW', 0, 'Forensic Risk Engine')
                """,
                (now,),
            )

    def test_report_contains_session_activity_and_only_triggered_assessments(self):
        self._perform_file_monitor_activity()
        self._insert_session_risks()
        report_time = datetime.now().astimezone()

        events = self.session._session_events(report_time)
        assessments = self.session._session_assessments(report_time)
        evidence = self.session._session_evidence(assessments)
        report_data = self.session._build_report_data(
            report_time, events, assessments, evidence
        )

        self.assertEqual(len(events), 16)
        self.assertEqual(len(assessments), 1)
        self.assertEqual(assessments[0]["rule_id"], 47)
        self.assertEqual(assessments[0]["rule_name"], get_rule(47).rule_name)
        self.assertEqual(report_data["risk_score"], 57)
        self.assertEqual(report_data["risk_level"], "MEDIUM")
        self.assertEqual(report_data["user_id"], "test-user-id")
        self.assertNotIn("must-not-be-reported", str(report_data))
        self.assertIn("11 observed event(s)", report_data["normal_summary"])
        self.assertIn("1 distinct rule(s)", report_data["analysis"])
        self.assertTrue(evidence[assessments[0]["id"]])

        output = self.session.generate_report(report_time)
        contents = output.read_bytes()
        self.assertTrue(contents.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", contents[-2048:])
        self.assertLess(len(contents), 100 * 1024)
        self.assertEqual(output.parent, self.report_dir)

    def test_session_does_not_include_pre_login_rows_or_generic_assessments(self):
        later = datetime.now().astimezone()
        events = self.session._session_events(later)
        assessments = self.session._session_assessments(later)
        self.assertEqual(events, [])
        self.assertEqual(assessments, [])

    def test_logout_requires_successful_report_and_generates_it_first(self):
        calls = []
        fake_window = SimpleNamespace(
            _create_forensic_report=lambda: calls.append("report") or self.root / "report.pdf",
            logout_requested=SimpleNamespace(emit=lambda: calls.append("logout")),
        )
        with (
            patch("gui.main_window.QMessageBox.information"),
            patch("gui.main_window.sign_out", side_effect=lambda: calls.append("sign_out")),
        ):
            MainWindow._logout(fake_window)
        self.assertEqual(calls, ["report", "sign_out", "logout"])

        calls.clear()
        fake_window._create_forensic_report = lambda: calls.append("report") or None
        with (
            patch("gui.main_window.QMessageBox.information"),
            patch("gui.main_window.sign_out") as sign_out,
        ):
            MainWindow._logout(fake_window)
        sign_out.assert_not_called()
        self.assertEqual(calls, ["report"])


if __name__ == "__main__":
    unittest.main()
