import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import database.riskalert_db as risk_db
from detection import event_risk_handler, risk_engine
from detection.rule_registry import get_rule


def _row(timestamp, event_id, path="", details="", source="File Monitor"):
    return (
        None,
        timestamp,
        source,
        event_id,
        event_id.replace("_", " ").title(),
        path,
        details,
    )


def _event(timestamp, event_id, path="", details="", source="File Monitor"):
    return {
        "timestamp": timestamp,
        "source": source,
        "event_id": event_id,
        "action": event_id.replace("_", " ").title(),
        "application": path,
        "details": details,
    }


class RulesSixToTwentyFiveTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="forensicguard_rules_6_25_")
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

    @staticmethod
    def _time(minutes_ago=0, hour=None):
        value = datetime.now() - timedelta(minutes=minutes_ago)
        if hour is not None:
            value = value.replace(hour=hour, minute=15, second=0)
        return value.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _rule_ids(result):
        return [rule["rule_id"] for rule in result["triggered_rules"]]

    def _assess(self, trigger, rows):
        with patch.object(risk_engine, "get_recent_events", return_value=rows):
            return risk_engine.assess_risk(trigger)

    def _handler(self):
        handler = event_risk_handler.EventRiskHandler.__new__(
            event_risk_handler.EventRiskHandler
        )
        handler.debounce_seconds = 2
        handler.last_assessment_time = 0
        handler.last_assessment_type = None
        handler.last_file_modification_rule_time = 0
        handler.lock = threading.Lock()
        handler.trigger_events = {
            "FILE_COPY",
            "USB_FILE_TRANSFER",
            "MTP_TRANSFER_ATTEMPTED",
            "USB_CONNECTED",
            "FILE_CREATE",
            "FILE_MODIFY",
            "FILE_DELETE",
            "FILE_RENAME",
        }
        handler.alert_manager = Mock()
        handler.alert_manager.process_risk.return_value = False
        return handler

    def test_rule_6_sensitive_file_modification_uses_path_only(self):
        timestamp = self._time()
        path = r"C:\Users\test\Documents\Finance\budget.xlsx"
        trigger = _event(timestamp, "FILE_MODIFY", path, "File content changed")
        result = self._assess(trigger, [_row(timestamp, "FILE_MODIFY", path)])

        self.assertIn(6, self._rule_ids(result))
        self.assertNotIn("contents", " ".join(result["evidence"]).casefold())

    def test_rule_6_non_sensitive_path_does_not_trigger(self):
        timestamp = self._time()
        path = r"C:\Users\test\Documents\notes.txt"
        result = self._assess(
            _event(timestamp, "FILE_MODIFY", path),
            [_row(timestamp, "FILE_MODIFY", path)],
        )
        self.assertNotIn(6, self._rule_ids(result))

    def test_rule_7_requires_five_distinct_deletions_within_one_minute(self):
        paths = [rf"C:\Users\test\Documents\old-{index}.txt" for index in range(5)]
        timestamp = self._time()
        rows = [_row(timestamp, "FILE_DELETE", path) for path in paths]
        result = self._assess(_event(timestamp, "FILE_DELETE", paths[-1]), rows)
        self.assertIn(7, self._rule_ids(result))

        below_threshold = self._assess(
            _event(timestamp, "FILE_DELETE", paths[-1]),
            rows[:-1],
        )
        self.assertNotIn(7, self._rule_ids(below_threshold))

    def test_rule_8_sensitive_deletion_and_rule_9_not_inferred(self):
        timestamp = self._time()
        path = r"C:\Users\test\Documents\Credentials\passwords.kdbx"
        result = self._assess(
            _event(timestamp, "FILE_DELETE", path, "User deleted a file"),
            [_row(timestamp, "FILE_DELETE", path, "User deleted a file")],
        )
        self.assertIn(8, self._rule_ids(result))
        self.assertNotIn(9, self._rule_ids(result))

    def test_rule_10_mass_rename_and_rule_11_extension_change(self):
        timestamp = self._time()
        rename_rows = []
        for index in range(5):
            source = rf"C:\Users\test\Documents\old-{index}.txt"
            destination = rf"C:\Users\test\Documents\new-{index}.txt"
            rename_rows.append(
                _row(timestamp, "FILE_RENAME", destination, f"Old Path : {source}")
            )
        result = self._assess(
            _event(timestamp, "FILE_RENAME", rename_rows[-1][5], rename_rows[-1][6]),
            rename_rows,
        )
        self.assertIn(10, self._rule_ids(result))
        self.assertNotIn(11, self._rule_ids(result))

        old_path = r"C:\Users\test\Documents\payload.txt"
        new_path = r"C:\Users\test\Documents\payload.locked"
        extension_result = self._assess(
            _event(timestamp, "FILE_RENAME", new_path, f"Old Path : {old_path}"),
            [_row(timestamp, "FILE_RENAME", new_path, f"Old Path : {old_path}")],
        )
        self.assertIn(11, self._rule_ids(extension_result))

    def test_rule_12_mass_cross_folder_move(self):
        timestamp = self._time()
        move_rows = []
        for index in range(5):
            source = rf"C:\Users\test\Documents\from\file-{index}.txt"
            destination = rf"C:\Users\test\Documents\to\file-{index}.txt"
            move_rows.append(
                _row(timestamp, "FILE_RENAME", destination, f"Old Path : {source}")
            )
        result = self._assess(
            _event(timestamp, "FILE_RENAME", move_rows[-1][5], move_rows[-1][6]),
            move_rows,
        )
        self.assertIn(12, self._rule_ids(result))
        self.assertNotIn(10, self._rule_ids(result))

    def test_rules_13_14_15_do_not_claim_unobserved_access(self):
        timestamp = self._time()
        event_types = ["FILE_ACCESS", "FILE_OPEN", "SENSITIVE_FOLDER_ACCESS"]
        rows = [
            _row(timestamp, event_id, r"C:\Users\test\Documents\Finance")
            for event_id in event_types
        ]
        result = self._assess(
            _event(timestamp, "FILE_ACCESS", r"C:\Users\test\Documents\Finance"),
            rows,
        )
        self.assertFalse({13, 14, 15} & set(self._rule_ids(result)))

    def test_rule_16_after_hours_and_daytime_behavior(self):
        timestamp = self._time(hour=23)
        path = r"C:\Users\test\Documents\notes.txt"
        after_hours = self._assess(
            _event(timestamp, "FILE_MODIFY", path),
            [_row(timestamp, "FILE_MODIFY", path)],
        )
        self.assertIn(16, self._rule_ids(after_hours))

        daytime_timestamp = self._time(hour=12)
        daytime = self._assess(
            _event(daytime_timestamp, "FILE_MODIFY", path),
            [_row(daytime_timestamp, "FILE_MODIFY", path)],
        )
        self.assertNotIn(16, self._rule_ids(daytime))

    def test_rules_17_and_18_require_successful_monitored_removable_transfer(self):
        timestamp = self._time()
        details = (
            r"Device=USB Drive | File=report.txt | Size=1024 bytes | "
            r"Source=C:\Users\test\report.txt | Destination=E:\report.txt | "
            "Status=SUCCESS"
        )
        result = self._assess(
            _event(
                timestamp,
                "USB_FILE_TRANSFER",
                "Windows Explorer",
                details,
                source="File Transfer Monitor",
            ),
            [_row(timestamp, "USB_FILE_TRANSFER", "Windows Explorer", details, "File Transfer Monitor")],
        )
        self.assertIn(17, self._rule_ids(result))
        self.assertIn(18, self._rule_ids(result))

        attempted = details.replace("Status=SUCCESS", "Status=ATTEMPTED")
        attempt_result = self._assess(
            _event(timestamp, "USB_FILE_TRANSFER", "Windows Explorer", attempted, "File Transfer Monitor"),
            [_row(timestamp, "USB_FILE_TRANSFER", "Windows Explorer", attempted, "File Transfer Monitor")],
        )
        self.assertNotIn(17, self._rule_ids(attempt_result))
        self.assertNotIn(18, self._rule_ids(attempt_result))

    def test_rules_17_and_18_persist_as_separate_evidence_preserving_rows(self):
        risk_db.initialize_riskalert_db()
        timestamp = self._time(hour=12)
        details = (
            r"Device=USB Drive | File=report.txt | Size=1024 bytes | "
            r"Source=C:\Users\test\report.txt | Destination=E:\report.txt | "
            "Status=SUCCESS"
        )
        event = _event(
            timestamp,
            "USB_FILE_TRANSFER",
            "Windows Explorer",
            details,
            source="File Transfer Monitor",
        )
        rows = [
            _row(
                timestamp,
                "USB_FILE_TRANSFER",
                "Windows Explorer",
                details,
                "File Transfer Monitor",
            )
        ]

        with (
            patch.object(risk_engine, "get_recent_events", return_value=rows),
            patch.object(
                event_risk_handler,
                "assess_risk",
                side_effect=lambda current_event: risk_engine.assess_risk(current_event),
            ),
        ):
            result = self._handler().handle_event(event)

        self.assertEqual(self._rule_ids(result), [17, 18])
        with closing(sqlite3.connect(risk_db.DB_PATH)) as conn:
            records = conn.execute(
                """
                SELECT rule_id, rule_name, risk_score, risk_level, evidence_summary,
                       timestamp, trigger_event_id, trigger_details
                FROM risk_assessments
                ORDER BY rule_id
                """
            ).fetchall()

        self.assertEqual(
            [(record[0], record[1]) for record in records],
            [(17, get_rule(17).rule_name), (18, get_rule(18).rule_name)],
        )
        self.assertEqual({record[2] for record in records}, {result["score"]})
        self.assertEqual({record[3] for record in records}, {result["risk"]})
        self.assertTrue(all(details in record[4] for record in records))
        self.assertTrue(all(record[5] for record in records))
        self.assertEqual({record[6] for record in records}, {"USB_FILE_TRANSFER"})
        self.assertEqual({record[7] for record in records}, {details})

    def test_rules_19_to_25_are_not_fabricated_without_required_telemetry(self):
        timestamp = self._time()
        path = r"C:\Users\test\Downloads\download.zip"
        cases = [
            ("FILE_COPY", r"FileCount=1 | TotalSize=100 bytes | Files=\\server\share\file"),
            ("FILE_CREATE", "User created a file"),
            ("FILE_MODIFY", "Permission changed"),
        ]
        for event_id, details in cases:
            with self.subTest(event_id=event_id, details=details):
                result = self._assess(
                    _event(timestamp, event_id, path, details),
                    [_row(timestamp, event_id, path, details)],
                )
                self.assertFalse({19, 20, 21, 22, 23, 24, 25} & set(self._rule_ids(result)))

    def test_supported_rules_persist_rule_metadata_score_evidence_and_trigger(self):
        risk_db.initialize_riskalert_db()
        timestamp = self._time(hour=23)
        path = r"C:\Users\test\Documents\Finance\budget.xlsx"
        event = _event(timestamp, "FILE_MODIFY", path, "File content changed")
        rows = [_row(timestamp, "FILE_MODIFY", path, "File content changed")]

        with (
            patch.object(risk_engine, "get_recent_events", return_value=rows),
            patch.object(
                event_risk_handler,
                "assess_risk",
                side_effect=lambda current_event: risk_engine.assess_risk(current_event),
            ),
        ):
            result = self._handler().handle_event(event)

        self.assertEqual(self._rule_ids(result), [6, 16])
        with closing(sqlite3.connect(risk_db.DB_PATH)) as conn:
            records = conn.execute(
                """
                SELECT rule_id, rule_name, risk_score, risk_level, evidence_summary,
                       timestamp, trigger_event_id, trigger_details
                FROM risk_assessments
                ORDER BY rule_id
                """
            ).fetchall()

        self.assertEqual(
            [(record[0], record[1]) for record in records],
            [(6, get_rule(6).rule_name), (16, get_rule(16).rule_name)],
        )
        self.assertEqual({record[2] for record in records}, {result["score"]})
        self.assertEqual({record[3] for record in records}, {result["risk"]})
        self.assertTrue(all(path in record[4] for record in records))
        self.assertTrue(all(record[5] for record in records))
        self.assertEqual({record[6] for record in records}, {"FILE_MODIFY"})
        self.assertEqual({record[7] for record in records}, {"File content changed"})

    def test_registry_status_reflects_supported_and_partial_rules(self):
        full_ids = {11, 17, 18}
        for rule_id in range(6, 26):
            expected = "FULL" if rule_id in full_ids else "PARTIAL"
            self.assertEqual(get_rule(rule_id).status, expected)


if __name__ == "__main__":
    unittest.main()
