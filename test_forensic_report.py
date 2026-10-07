import base64
import re
import sqlite3
import tempfile
import unittest
import zlib
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from detection.rule_registry import get_rule
from detection.risk_engine import _detect_file_burst_rules
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
        self.user = SimpleNamespace(
            id="test-user-id",
            email="report-user@example.invalid",
        )
        self.session = ForensicSession.start(
            self.user,
            forensic_db_path=self.forensic_db,
            risk_db_path=self.risk_db,
            report_directory=self.report_dir,
        )

    def tearDown(self):
        self.session.finish()
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
            cursor = connection.execute(
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
            self.session.record_event_row_id(cursor.lastrowid)

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
                          'File Monitor', ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    trigger_row[5],
                    rule["evidence"],
                    rule["rule_id"],
                    rule["rule_name"],
                    "5 temporary text files created.",
                ),
            )
            risk_id = connection.execute(
                "SELECT MAX(id) FROM risk_assessments"
            ).fetchone()[0]
            self.session.record_assessment_row_id(risk_id)
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

        events = self.session._session_events()
        assessments = self.session._session_assessments()
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
        self.assertEqual(report_data["user_email"], "report-user@example.invalid")
        self.assertEqual(len(self.session._associated_row_ids("event")), 16)
        self.assertEqual(len(self.session._associated_row_ids("assessment")), 1)
        self.assertEqual(report_data["risk_level_counts"]["MEDIUM"], 1)
        self.assertEqual(report_data["activity_counts"]["file_created"], 5)
        self.assertEqual(report_data["activity_counts"]["file_modified"], 5)
        self.assertEqual(report_data["activity_counts"]["file_renamed"], 1)
        self.assertEqual(report_data["activity_counts"]["file_deleted"], 5)
        self.assertIn("15 observed event(s)", report_data["normal_summary"])
        self.assertIn("1 distinct rule(s)", report_data["analysis"])
        self.assertTrue(evidence[assessments[0]["id"]])

        with _connection(self.risk_db) as connection:
            counts_before = (
                connection.execute("SELECT COUNT(*) FROM risk_assessments").fetchone()[0],
                connection.execute("SELECT COUNT(*) FROM risk_evidence").fetchone()[0],
            )
        output = self.session.generate_report(report_time)
        contents = output.read_bytes()
        self.assertTrue(contents.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", contents[-2048:])
        self.assertLess(len(contents), 100 * 1024)
        self.assertEqual(output.parent, self.report_dir)
        self.assertIn("ForensicGuard_Report_", output.name)
        decoded_streams = [
            zlib.decompress(base64.a85decode(stream.strip(), adobe=True))
            for stream in re.findall(
                rb"/Filter \[ /ASCII85Decode /FlateDecode \].*?stream\n(.*?)endstream",
                contents,
                re.DOTALL,
            )
        ]
        pdf_text = b"\n".join(decoded_streams)
        for heading in (
            b"Forensic Monitoring Session Report",
            b"Session Information",
            b"Activity Summary",
            b"Risk Summary",
            b"Detected Suspicious Activity",
            b"Normal Activity Summary",
            b"Forensic Timeline",
            b"Forensic Evidence Summary",
            b"Forensic Analytical Summary",
            b"Final Assessment",
            b"Key Findings",
            b"Recommended Actions",
        ):
            self.assertIn(heading, pdf_text)
        self.assertIn(b"Mass File Creation", pdf_text)
        self.assertIn(b"report-user@example.invalid", pdf_text)
        self.assertIn(b"5", pdf_text)
        metadata = __import__("json").loads(self.session.metadata_path.read_text())
        self.assertFalse(metadata["historical_rows_associated"])
        self.assertEqual(metadata["last_report"], output.name)
        with _connection(self.risk_db) as connection:
            counts_after = (
                connection.execute("SELECT COUNT(*) FROM risk_assessments").fetchone()[0],
                connection.execute("SELECT COUNT(*) FROM risk_evidence").fetchone()[0],
            )
        self.assertEqual(counts_after, counts_before)

    def test_session_does_not_include_pre_login_rows_or_generic_assessments(self):
        events = self.session._session_events()
        assessments = self.session._session_assessments()
        self.assertEqual(events, [])
        self.assertEqual(assessments, [])

    def test_logger_persisted_event_is_associated_without_schema_migration(self):
        from utils.logger import log_event

        with (
            patch("database.database.DB_PATH", self.forensic_db),
            patch("event_engine.engine.publish"),
        ):
            log_event(
                "File Monitor",
                "FILE_CREATE",
                "File Created",
                str(self.root / "associated.txt"),
                "User created a test file",
            )

        row_ids = self.session._associated_row_ids("event")
        self.assertEqual(len(row_ids), 1)
        rows = self.session._session_events(row_ids)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_id"], "FILE_CREATE")

    def test_logout_requires_successful_report_and_generates_it_first(self):
        real_connect = sqlite3.connect
        with patch(
            "sqlite3.connect",
            side_effect=lambda *args, **kwargs: real_connect(
                self.risk_db, **kwargs
            ),
        ):
            from gui.main_window import MainWindow

        calls = []
        fake_window = SimpleNamespace(
            _create_forensic_report=lambda: calls.append("report") or self.root / "report.pdf",
            _offer_report_actions=lambda path: calls.append("offer_actions"),
            forensic_session=SimpleNamespace(finish=lambda: calls.append("finish")),
            logout_requested=SimpleNamespace(emit=lambda: calls.append("logout")),
        )
        with (
            patch("gui.main_window.QMessageBox.information"),
            patch("gui.main_window.sign_out", side_effect=lambda: calls.append("sign_out")),
        ):
            MainWindow._logout(fake_window)
        self.assertEqual(
            calls,
            ["report", "offer_actions", "sign_out", "finish", "logout"],
        )

        calls.clear()
        fake_window._create_forensic_report = lambda: calls.append("report") or None
        with (
            patch("gui.main_window.QMessageBox.information"),
            patch("gui.main_window.sign_out") as sign_out,
        ):
            MainWindow._logout(fake_window)
        sign_out.assert_not_called()
        self.assertEqual(calls, ["report"])

    def test_report_action_dialog_offers_open_and_save(self):
        from gui.main_window import MainWindow

        report_path = self.root / "generated.pdf"
        open_button = object()
        save_button = object()
        close_button = object()
        clicked = {"button": open_button}
        dialog = Mock()
        dialog.addButton.side_effect = [open_button, save_button, close_button]
        dialog.clickedButton.side_effect = lambda: clicked["button"]
        fake_window = SimpleNamespace(
            _open_report=Mock(),
            _save_report_copy=Mock(),
        )
        with (
            patch("gui.main_window.QMessageBox") as message_box,
        ):
            message_box.return_value = dialog
            MainWindow._offer_report_actions(fake_window, report_path)
            self.assertEqual(
                dialog.addButton.call_args_list[0].args[0],
                "Open Report",
            )
            self.assertEqual(
                dialog.addButton.call_args_list[1].args[0],
                "Save/Download Report",
            )
            fake_window._open_report.assert_called_once_with(report_path)
            clicked["button"] = save_button
            dialog.addButton.side_effect = [
                open_button,
                save_button,
                close_button,
            ]
            MainWindow._offer_report_actions(fake_window, report_path)

        fake_window._save_report_copy.assert_called_once_with(report_path)

    def test_open_report_uses_default_pdf_handler(self):
        from gui.main_window import MainWindow

        report_path = self.root / "generated.pdf"
        report_path.write_bytes(b"%PDF-1.4 test")
        with patch("gui.main_window.QDesktopServices.openUrl", return_value=True) as open_url:
            MainWindow._open_report(SimpleNamespace(), report_path)
        open_url.assert_called_once()
        self.assertEqual(
            Path(open_url.call_args.args[0].toLocalFile()),
            report_path,
        )

    def test_save_report_copy_preserves_original_pdf(self):
        from gui.main_window import MainWindow

        report_path = self.root / "generated.pdf"
        saved_path = self.root / "saved-copy.pdf"
        original_content = b"%PDF-1.4 safe report fixture"
        report_path.write_bytes(original_content)
        with (
            patch(
                "gui.main_window.QFileDialog.getSaveFileName",
                return_value=(str(saved_path), "PDF files (*.pdf)"),
            ) as save_dialog,
            patch("gui.main_window.QMessageBox.information"),
        ):
            MainWindow._save_report_copy(SimpleNamespace(), report_path)

        self.assertEqual(saved_path.read_bytes(), original_content)
        self.assertEqual(report_path.read_bytes(), original_content)
        self.assertEqual(save_dialog.call_args.args[2], str(report_path.name))

    def test_sensitive_values_are_redacted_in_report_text(self):
        from reports.forensic_report import _bounded_text

        self.assertEqual(
            _bounded_text("password=hunter2 token:abc123"),
            "password=[REDACTED] token=[REDACTED]",
        )


if __name__ == "__main__":
    unittest.main()
