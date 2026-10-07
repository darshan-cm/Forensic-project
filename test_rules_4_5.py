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


class RulesFourAndFiveTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="forensicguard_rules_4_5_")
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
    def _timestamp(seconds_ago=0):
        return (datetime.now() - timedelta(seconds=seconds_ago)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    @staticmethod
    def _modify_row(timestamp, path, event_id="FILE_MODIFY"):
        return (
            None,
            timestamp,
            "File Monitor",
            event_id,
            "File Modified",
            path,
            "File content changed",
        )

    def _modify_event(self, timestamp=None, path=r"C:\Users\test\Documents\file.txt"):
        return {
            "timestamp": timestamp or self._timestamp(),
            "source": "File Monitor",
            "event_id": "FILE_MODIFY",
            "action": "File Modified",
            "application": path,
            "details": "File content changed",
        }

    def _assess_modifications(self, paths, age_seconds=0):
        timestamp = self._timestamp(age_seconds)
        rows = [
            self._modify_row(timestamp, path)
            for path in paths
        ]
        trigger_event = self._modify_event(timestamp, paths[-1])
        with patch.object(risk_engine, "get_recent_events", return_value=rows):
            result = risk_engine.assess_risk(trigger_event)
        return result, trigger_event

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
            "FILE_MODIFY",
        }
        handler.alert_manager = Mock()
        handler.alert_manager.process_risk.return_value = False
        return handler

    def test_rule_4_unverified_mtp_attempt_is_not_mislabeled_as_paste(self):
        risk_db.initialize_riskalert_db()
        timestamp = self._timestamp()
        event = {
            "timestamp": timestamp,
            "source": "File Transfer Monitor",
            "event_id": "MTP_TRANSFER_ATTEMPTED",
            "action": "File Transfer Attempted",
            "application": "Windows Explorer",
            "details": (
                "Device=USB Device | Destination=Phone Internal Storage | "
                "FileCount=1 | TotalSize=100 bytes | "
                "Status=ATTEMPTED_UNVERIFIED | Files=report.txt"
            ),
        }
        row = (
            None,
            timestamp,
            event["source"],
            event["event_id"],
            event["action"],
            event["application"],
            event["details"],
        )
        with patch.object(risk_engine, "get_recent_events", return_value=[row]):
            result = risk_engine.assess_risk(event)

        self.assertNotIn(4, [rule["rule_id"] for rule in result["triggered_rules"]])
        self._handler()._record_and_notify(result, event)

        with closing(sqlite3.connect(risk_db.DB_PATH)) as conn:
            record = conn.execute(
                """
                SELECT rule_id, rule_name, trigger_event_id, trigger_details
                FROM risk_assessments
                """
            ).fetchone()

        self.assertEqual(record, (None, None, "MTP_TRANSFER_ATTEMPTED", event["details"]))

    def test_rule_5_triggers_for_five_distinct_files_within_one_minute(self):
        paths = [rf"C:\Users\test\Documents\file-{index}.txt" for index in range(5)]
        result, _ = self._assess_modifications(paths)

        self.assertEqual(
            result["triggered_rules"],
            [{
                "rule_id": 5,
                "rule_name": "Mass File Modification",
                "evidence": "5 distinct files modified within 1 minute.",
            }],
        )
        self.assertEqual(result["score"], 0)

    def test_rule_5_does_not_trigger_below_threshold_or_for_repeated_path(self):
        four_paths = [rf"C:\Users\test\Documents\file-{index}.txt" for index in range(4)]
        result, _ = self._assess_modifications(four_paths)
        self.assertEqual(result["triggered_rules"], [])

        repeated_path = r"C:\Users\test\Documents\same.txt"
        result, _ = self._assess_modifications([repeated_path] * 5)
        self.assertEqual(result["triggered_rules"], [])

    def test_rule_5_does_not_count_modifications_outside_one_minute(self):
        paths = [rf"C:\Users\test\Documents\file-{index}.txt" for index in range(5)]
        rows = [
            self._modify_row(self._timestamp(61), paths[0]),
            *[
                self._modify_row(self._timestamp(0), path)
                for path in paths[1:]
            ],
        ]
        trigger_event = self._modify_event(path=paths[-1])

        with patch.object(risk_engine, "get_recent_events", return_value=rows):
            result = risk_engine.assess_risk(trigger_event)

        self.assertEqual(result["triggered_rules"], [])

    def test_rule_5_persists_id_name_evidence_and_original_event_details(self):
        risk_db.initialize_riskalert_db()
        paths = [rf"C:\Users\test\Documents\file-{index}.txt" for index in range(5)]
        result, event = self._assess_modifications(paths)
        rows = [
            self._modify_row(event["timestamp"], path)
            for path in paths
        ]

        with (
            patch.object(risk_engine, "get_recent_events", return_value=rows),
            patch.object(
                event_risk_handler,
                "assess_risk",
                side_effect=lambda current_event: risk_engine.assess_risk(current_event),
            ),
        ):
            event_risk_handler_result = self._handler().handle_event(event)

        self.assertEqual(event_risk_handler_result["score"], result["score"])
        with closing(sqlite3.connect(risk_db.DB_PATH)) as conn:
            record = conn.execute(
                """
                SELECT rule_id, rule_name, risk_score, evidence_summary,
                       trigger_event_id, trigger_event_source, trigger_details
                FROM risk_assessments
                """
            ).fetchone()

        self.assertEqual(record[0:3], (5, "Mass File Modification", 0))
        self.assertIn("5 distinct files modified within 1 minute.", record[3])
        self.assertEqual(record[4:], ("FILE_MODIFY", "File Monitor", event["details"]))

    def test_non_triggering_modification_does_not_create_rule_assessment(self):
        risk_db.initialize_riskalert_db()
        event = self._modify_event()
        rows = [self._modify_row(event["timestamp"], event["application"])]

        with (
            patch.object(risk_engine, "get_recent_events", return_value=rows),
            patch.object(
                event_risk_handler,
                "assess_risk",
                side_effect=lambda current_event: risk_engine.assess_risk(current_event),
            ),
        ):
            self._handler().handle_event(event)

        with closing(sqlite3.connect(risk_db.DB_PATH)) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM risk_assessments"
            ).fetchone()[0]

        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
