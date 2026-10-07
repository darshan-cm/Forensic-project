import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import database.riskalert_db as risk_db
from detection import event_risk_handler, risk_engine


LARGE_FILE_SIZE = risk_engine.LARGE_TRANSFER_THRESHOLD_BYTES


def _copy_details(file_sizes):
    return (
        f"FileCount={len(file_sizes)} | "
        f"TotalSize={sum(file_sizes)} bytes | "
        f"FileSizes={','.join(str(size) for size in file_sizes)} | "
        f"Files=" + " | ".join(f"file-{index}.bin" for index in range(len(file_sizes)))
    )


def _event_row(timestamp, details, event_id="FILE_COPY"):
    return (
        None,
        timestamp,
        "File Transfer Monitor",
        event_id,
        "Files Copied",
        "Windows Explorer",
        details,
    )


class FileCopyRuleTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="forensicguard_copy_rules_")
        self.original_db_path = risk_db.DB_PATH
        self.original_forensic_db_path = risk_db.FORENSIC_DB_PATH
        risk_db.DB_PATH = Path(self.temp_dir.name) / "riskalert.db"
        risk_db.FORENSIC_DB_PATH = Path(self.temp_dir.name) / "forensic.db"
        with closing(sqlite3.connect(risk_db.FORENSIC_DB_PATH)) as conn:
            conn.execute(
                """
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    source TEXT,
                    event_id TEXT,
                    action TEXT,
                    application TEXT,
                    details TEXT
                )
                """
            )

    def tearDown(self):
        risk_db.DB_PATH = self.original_db_path
        risk_db.FORENSIC_DB_PATH = self.original_forensic_db_path
        self.temp_dir.cleanup()

    def _assess(self, file_sizes, previous_rows=(), event_id="FILE_COPY"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        details = _copy_details(file_sizes)
        row = _event_row(timestamp, details, event_id=event_id)
        trigger_event = {
            "timestamp": timestamp,
            "source": "File Transfer Monitor",
            "event_id": event_id,
            "details": details,
        }
        with patch.object(risk_engine, "get_recent_events", return_value=[*previous_rows, row]):
            return risk_engine.assess_risk(trigger_event), trigger_event, row

    def test_rule_1_detects_large_single_copy_at_existing_threshold(self):
        result, _, _ = self._assess([LARGE_FILE_SIZE])

        self.assertEqual(
            result["triggered_rules"],
            [{"rule_id": 1, "rule_name": "Large File Copy"}],
        )
        self.assertEqual(result["score"], 25)
        self.assertTrue(any("Large data transfer volume" in item for item in result["evidence"]))

    def test_rule_1_does_not_trigger_below_existing_threshold(self):
        result, _, _ = self._assess([LARGE_FILE_SIZE - 1])

        self.assertNotIn(1, [rule["rule_id"] for rule in result["triggered_rules"]])

    def test_rule_2_detects_multiple_large_files_in_ten_minute_window(self):
        previous_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        previous_details = _copy_details([LARGE_FILE_SIZE])
        previous_row = _event_row(previous_time, previous_details)
        result, _, _ = self._assess([LARGE_FILE_SIZE], previous_rows=[previous_row])

        self.assertEqual(
            result["triggered_rules"],
            [
                {"rule_id": 1, "rule_name": "Large File Copy"},
                {"rule_id": 2, "rule_name": "Multiple Large Files Copy"},
            ],
        )
        self.assertEqual(result["window_minutes"], risk_engine.WINDOW_MINUTES)

    def test_rule_3_uses_existing_three_file_bulk_threshold(self):
        result, _, _ = self._assess([1024, 2048, 4096])

        self.assertEqual(
            result["triggered_rules"],
            [{"rule_id": 3, "rule_name": "Bulk File Copy"}],
        )
        self.assertEqual(result["score"], 10)
        self.assertTrue(any("Bulk file-copy activity" in item for item in result["evidence"]))

    def test_non_triggering_copy_receives_no_rule(self):
        result, _, _ = self._assess([1024, 2048])

        self.assertEqual(result["triggered_rules"], [])
        self.assertEqual(result["score"], 5)

    def test_non_copy_event_receives_no_copy_rule(self):
        result, _, _ = self._assess([LARGE_FILE_SIZE] * 3, event_id="USB_CONNECTED")

        self.assertEqual(result["triggered_rules"], [])

    def test_all_matching_rules_are_persisted_as_separate_assessments(self):
        risk_db.initialize_riskalert_db()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        details = _copy_details([LARGE_FILE_SIZE] * 3)
        event = {
            "timestamp": timestamp,
            "source": "File Transfer Monitor",
            "event_id": "FILE_COPY",
            "action": "Files Copied",
            "application": "Windows Explorer",
            "details": details,
        }
        row = _event_row(timestamp, details)

        handler = event_risk_handler.EventRiskHandler.__new__(
            event_risk_handler.EventRiskHandler
        )
        handler.debounce_seconds = 0
        handler.last_assessment_time = 0
        handler.last_assessment_type = None
        handler.lock = threading.Lock()
        handler.trigger_events = {
            "FILE_COPY",
            "USB_FILE_TRANSFER",
            "MTP_TRANSFER_ATTEMPTED",
            "USB_CONNECTED",
        }
        handler.alert_manager = Mock()
        handler.alert_manager.process_risk.return_value = False

        with (
            patch.object(risk_engine, "get_recent_events", return_value=[row]),
            patch.object(
                event_risk_handler,
                "assess_risk",
                side_effect=lambda current_event: risk_engine.assess_risk(current_event),
            ),
        ):
            result = handler.handle_event(event)

        self.assertEqual(
            result["triggered_rules"],
            [
                {"rule_id": 1, "rule_name": "Large File Copy"},
                {"rule_id": 2, "rule_name": "Multiple Large Files Copy"},
                {"rule_id": 3, "rule_name": "Bulk File Copy"},
            ],
        )

        with closing(sqlite3.connect(risk_db.DB_PATH)) as conn:
            records = conn.execute(
                """
                SELECT rule_id, rule_name, risk_score, evidence_summary, trigger_event_id
                FROM risk_assessments
                ORDER BY rule_id
                """
            ).fetchall()

        self.assertEqual(
            [(record[0], record[1]) for record in records],
            [
                (1, "Large File Copy"),
                (2, "Multiple Large Files Copy"),
                (3, "Bulk File Copy"),
            ],
        )
        self.assertEqual(len({record[2] for record in records}), 1)
        self.assertEqual(len({record[3] for record in records}), 1)
        self.assertEqual({record[4] for record in records}, {"FILE_COPY"})

    def test_non_triggering_copy_persists_existing_generic_assessment(self):
        risk_db.initialize_riskalert_db()
        result, event, row = self._assess([1024])

        handler = event_risk_handler.EventRiskHandler.__new__(
            event_risk_handler.EventRiskHandler
        )
        handler.alert_manager = Mock()
        handler.alert_manager.process_risk.return_value = False

        with patch.object(risk_engine, "get_recent_events", return_value=[row]):
            handler._record_and_notify(result, event)

        with closing(sqlite3.connect(risk_db.DB_PATH)) as conn:
            record = conn.execute(
                "SELECT rule_id, rule_name, risk_score FROM risk_assessments"
            ).fetchone()

        self.assertEqual(record, (None, None, result["score"]))


if __name__ == "__main__":
    unittest.main()
