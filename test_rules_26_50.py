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


class RulesTwentySixToFiftyTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="forensicguard_rules_26_50_")
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
    def _time(seconds_ago=0, hour=None):
        value = datetime.now() - timedelta(seconds=seconds_ago)
        if hour is not None:
            value = value.replace(hour=hour, minute=20, second=0)
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
        handler.last_new_rule_times = {}
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
            "FOLDER_CREATE",
            "FOLDER_DELETE",
        }
        handler.alert_manager = Mock()
        handler.alert_manager.process_risk.return_value = False
        return handler

    def test_rule_26_requires_observed_windows_hidden_attribute(self):
        timestamp = self._time()
        path = r"C:\Users\test\Documents\.hidden.txt"
        hidden = _event(timestamp, "FILE_CREATE", path, "User created a file | Hidden=True")
        result = self._assess(hidden, [_row(timestamp, "FILE_CREATE", path, hidden["details"])])
        self.assertIn(26, self._rule_ids(result))

        unknown = _event(timestamp, "FILE_CREATE", path, "User created a file")
        result = self._assess(unknown, [_row(timestamp, "FILE_CREATE", path, unknown["details"])])
        self.assertNotIn(26, self._rule_ids(result))

    def test_rules_27_28_classify_extensions_without_reading_contents(self):
        timestamp = self._time()
        for rule_id, path in (
            (27, r"C:\Users\test\Documents\script.PS1"),
            (28, r"C:\Users\test\Documents\settings.YAML"),
        ):
            with self.subTest(rule_id=rule_id):
                trigger = _event(timestamp, "FILE_MODIFY", path, "File content changed")
                result = self._assess(
                    trigger,
                    [_row(timestamp, "FILE_MODIFY", path, trigger["details"])],
                )
                self.assertIn(rule_id, self._rule_ids(result))

        plain = r"C:\Users\test\Documents\notes.txt"
        result = self._assess(
            _event(timestamp, "FILE_MODIFY", plain),
            [_row(timestamp, "FILE_MODIFY", plain)],
        )
        self.assertFalse({27, 28} & set(self._rule_ids(result)))

    def test_rule_29_identifiable_backup_file_delete_only(self):
        timestamp = self._time()
        backup = r"C:\Users\test\Documents\budget.backup"
        result = self._assess(
            _event(timestamp, "FILE_DELETE", backup),
            [_row(timestamp, "FILE_DELETE", backup)],
        )
        self.assertIn(29, self._rule_ids(result))

        regular = r"C:\Users\test\Documents\budget.xlsx"
        result = self._assess(
            _event(timestamp, "FILE_DELETE", regular),
            [_row(timestamp, "FILE_DELETE", regular)],
        )
        self.assertNotIn(29, self._rule_ids(result))

    def test_rule_30_snapshot_deletion_not_inferred(self):
        timestamp = self._time()
        trigger = _event(timestamp, "FILE_DELETE", r"C:\Users\test\Documents\file.txt")
        rows = [
            _row(timestamp, "VSS_DELETE", r"C:\System Volume Information"),
            _row(timestamp, "FILE_DELETE", trigger["application"]),
        ]
        self.assertNotIn(30, self._rule_ids(self._assess(trigger, rows)))

    def test_dashboard_style_assessment_without_trigger_event_does_not_fail(self):
        with patch.object(risk_engine, "get_recent_events", return_value=[]):
            result = risk_engine.assess_risk()

        self.assertEqual(result["triggered_rules"], [])

    def test_repeated_dashboard_refresh_does_not_persist_generic_assessments(self):
        from PySide6.QtWidgets import QApplication
        from gui.main_window import MainWindow

        app = QApplication.instance() or QApplication([])
        assessment = {
            "risk": "LOW",
            "score": 0,
            "evidence": ["No significant forensic indicators."],
            "triggered_rules": [],
        }
        with (
            patch("gui.main_window.get_all_events", return_value=[]),
            patch("gui.main_window.assess_risk", return_value=assessment),
            patch(
                "gui.main_window.record_risk_assessment",
                create=True,
            ) as persist_assessment,
            patch("gui.main_window.AlertManager") as alert_manager,
        ):
            window = MainWindow()
            window.refresh_dashboard()
            window.refresh_dashboard()
            window.timer.stop()
            window._session_finalized = True
            window.close()
            window.forensic_session.finish()

        persist_assessment.assert_not_called()
        alert_manager.return_value.process_risk.assert_not_called()
        app.processEvents()

    def test_rules_31_32_require_bursty_encryption_like_rename_and_modification(self):
        timestamp = self._time()
        rows = []
        for index in range(5):
            old_path = rf"C:\Users\test\Documents\file-{index}.txt"
            new_path = rf"C:\Users\test\Documents\file-{index}.locked"
            rows.append(_row(timestamp, "FILE_RENAME", new_path, f"Old Path : {old_path}"))
            rows.append(_row(timestamp, "FILE_MODIFY", new_path, "File content changed"))

        trigger = _event(
            timestamp,
            "FILE_MODIFY",
            rows[-1][5],
            rows[-1][6],
        )
        result = self._assess(trigger, rows)
        self.assertIn(32, self._rule_ids(result))
        self.assertNotIn(31, self._rule_ids(result))

        trigger = _event(timestamp, "FILE_RENAME", rows[-2][5], rows[-2][6])
        result = self._assess(trigger, rows[:-1])
        self.assertIn(31, self._rule_ids(result))
        self.assertNotIn(32, self._rule_ids(result))
        self.assertTrue(
            any("not proof of encryption" in rule["evidence"] for rule in result["triggered_rules"] if rule["rule_id"] in {31, 32})
        )

        ordinary = [
            _row(timestamp, "FILE_RENAME", rf"C:\Users\test\Documents\renamed-{index}.txt",
                 f"Old Path : C:\\Users\\test\\Documents\\old-{index}.txt")
            for index in range(5)
        ]
        result = self._assess(
            _event(timestamp, "FILE_RENAME", ordinary[-1][5], ordinary[-1][6]),
            ordinary,
        )
        self.assertFalse({31, 32} & set(self._rule_ids(result)))

    def test_rule_33_correlates_successful_usb_copy_then_exact_source_delete(self):
        copy_time = self._time(seconds_ago=30)
        delete_time = self._time()
        source_path = r"C:\Users\test\Documents\report.docx"
        transfer_details = (
            f"File=report.docx | Source={source_path} | "
            r"Destination=E:\report.docx | Status=SUCCESS"
        )
        trigger = _event(delete_time, "FILE_DELETE", source_path, "User deleted a file")
        rows = [
            _row(copy_time, "USB_FILE_TRANSFER", "Windows Explorer", transfer_details, "File Transfer Monitor"),
            _row(delete_time, "FILE_DELETE", source_path, trigger["details"]),
        ]
        result = self._assess(trigger, rows)
        self.assertIn(33, self._rule_ids(result))

        nonmatching = [
            rows[0],
            _row(delete_time, "FILE_DELETE", r"C:\Users\test\Documents\other.docx"),
        ]
        other_trigger = _event(delete_time, "FILE_DELETE", nonmatching[-1][5])
        self.assertNotIn(33, self._rule_ids(self._assess(other_trigger, nonmatching)))

        clipboard_only = [
            _row(copy_time, "FILE_COPY", "Windows Explorer", "Files=report.docx"),
            rows[1],
        ]
        self.assertNotIn(33, self._rule_ids(self._assess(trigger, clipboard_only)))

    def test_rule_34_access_plus_transfer_not_inferred(self):
        timestamp = self._time()
        trigger = _event(timestamp, "USB_FILE_TRANSFER", "Windows Explorer", "Status=SUCCESS")
        rows = [
            _row(timestamp, "FILE_ACCESS", r"C:\Users\test\Documents\secret.txt"),
            _row(timestamp, "USB_FILE_TRANSFER", "Windows Explorer", "Status=SUCCESS", "File Transfer Monitor"),
        ]
        self.assertNotIn(34, self._rule_ids(self._assess(trigger, rows)))

    def test_rule_35_privileged_security_event_correlates_with_file_activity(self):
        timestamp = self._time()
        path = r"C:\Users\test\Documents\notes.txt"
        trigger = _event(timestamp, "FILE_MODIFY", path)
        rows = [
            _row(timestamp, "4672", "Windows", "Special privileges assigned", "Security Log"),
            _row(timestamp, "FILE_MODIFY", path),
        ]
        self.assertIn(35, self._rule_ids(self._assess(trigger, rows)))

    def test_rule_36_new_usb_device_correlates_temporally_with_file_activity(self):
        device_time = self._time(seconds_ago=20)
        file_time = self._time()
        path = r"C:\Users\test\Documents\copy.txt"
        trigger = _event(file_time, "FILE_CREATE", path)
        rows = [
            _row(device_time, "USB_CONNECTED", "Windows", "Device=Test USB | VID=1234", "USB Monitor"),
            _row(file_time, "FILE_CREATE", path),
        ]
        result = self._assess(trigger, rows)
        self.assertIn(36, self._rule_ids(result))
        self.assertIn("temporally correlated", next(
            rule["evidence"] for rule in result["triggered_rules"] if rule["rule_id"] == 36
        ))

    def test_rule_37_unusual_location_not_inferred_without_baseline(self):
        timestamp = self._time()
        path = r"Z:\untrusted\file.txt"
        result = self._assess(
            _event(timestamp, "FILE_CREATE", path),
            [_row(timestamp, "FILE_CREATE", path)],
        )
        self.assertNotIn(37, self._rule_ids(result))

    def test_rule_38_dormancy_not_inferred_without_account_baseline(self):
        timestamp = self._time()
        path = r"C:\Users\test\Documents\file.txt"
        rows = [
            _row(timestamp, "4624", "Windows", "Successful Login", "Security Log"),
            _row(timestamp, "FILE_CREATE", path),
        ]
        result = self._assess(_event(timestamp, "FILE_CREATE", path), rows)
        self.assertNotIn(38, self._rule_ids(result))

    def test_rule_39_failed_login_followed_by_file_activity(self):
        failed_time = self._time(seconds_ago=30)
        file_time = self._time()
        path = r"C:\Users\test\Documents\file.txt"
        trigger = _event(file_time, "FILE_MODIFY", path)
        rows = [
            _row(failed_time, "4625", "Windows", "An account failed to log on", "Security Log"),
            _row(file_time, "FILE_MODIFY", path),
        ]
        self.assertIn(39, self._rule_ids(self._assess(trigger, rows)))

        rows[0] = _row(self._time(seconds_ago=-10), "4625", "Windows", "Failed", "Security Log")
        self.assertNotIn(39, self._rule_ids(self._assess(trigger, rows)))

    def test_rule_40_spike_threshold_is_ten_events_per_minute(self):
        timestamp = self._time()
        paths = [rf"C:\Users\test\Documents\file-{index}.txt" for index in range(10)]
        rows = [_row(timestamp, "FILE_MODIFY", path) for path in paths]
        result = self._assess(_event(timestamp, "FILE_MODIFY", paths[-1]), rows)
        self.assertIn(40, self._rule_ids(result))

        result = self._assess(_event(timestamp, "FILE_MODIFY", paths[-1]), rows[:-1])
        self.assertNotIn(40, self._rule_ids(result))

    def test_rules_41_and_50_correlate_distinct_real_detections(self):
        timestamp = self._time()
        events = [
            _event(timestamp, "FILE_MODIFY", r"C:\Users\test\Documents\app.exe", "File content changed"),
            _event(timestamp, "FILE_MODIFY", r"C:\Users\test\Documents\settings.json", "File content changed"),
            _event(timestamp, "FILE_MODIFY", r"C:\Users\test\Documents\Credentials\key.pem", "File content changed"),
        ]
        rows = [_row(
            event["timestamp"],
            event["event_id"],
            event["application"],
            event["details"],
        ) for event in events]
        result = self._assess(events[-1], rows)
        ids = self._rule_ids(result)
        self.assertIn(41, ids)
        self.assertIn(50, ids)
        self.assertTrue(any(
            "Rule 27" in rule["evidence"]
            and "Rule 28" in rule["evidence"]
            and "Rule 6" in rule["evidence"]
            for rule in result["triggered_rules"]
            if rule["rule_id"] == 50
        ))

        one_event = self._assess(
            events[0],
            [rows[0]],
        )
        self.assertFalse({41, 50} & set(self._rule_ids(one_event)))

    def test_rule_42_high_risk_process_cannot_be_linked_to_file_event(self):
        timestamp = self._time()
        process = _row(timestamp, "4688", "powershell.exe", "PID=100 | C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "Process Monitor")
        path = r"C:\Users\test\Documents\file.txt"
        result = self._assess(
            _event(timestamp, "FILE_MODIFY", path),
            [process, _row(timestamp, "FILE_MODIFY", path)],
        )
        self.assertNotIn(42, self._rule_ids(result))

    def test_rule_43_protected_file_access_not_confused_with_modification(self):
        timestamp = self._time()
        path = r"C:\Windows\System32\drivers\etc\hosts"
        result = self._assess(
            _event(timestamp, "FILE_MODIFY", path),
            [_row(timestamp, "FILE_MODIFY", path)],
        )
        self.assertNotIn(43, self._rule_ids(result))

    def test_rule_44_system_path_modification_is_classified(self):
        timestamp = self._time()
        path = r"C:\Windows\System32\drivers\example.sys"
        result = self._assess(
            _event(timestamp, "FILE_MODIFY", path),
            [_row(timestamp, "FILE_MODIFY", path)],
        )
        self.assertIn(44, self._rule_ids(result))

    def test_rules_45_46_require_folder_events_not_file_events(self):
        timestamp = self._time()
        folder_paths = [rf"C:\Users\test\Documents\folder-{index}" for index in range(5)]
        for event_id, rule_id in (("FOLDER_DELETE", 45), ("FOLDER_CREATE", 46)):
            rows = [_row(timestamp, event_id, path) for path in folder_paths]
            result = self._assess(
                _event(timestamp, event_id, folder_paths[-1]),
                rows,
            )
            self.assertIn(rule_id, self._rule_ids(result))

        file_rows = [_row(timestamp, "FILE_DELETE", path) for path in folder_paths]
        result = self._assess(
            _event(timestamp, "FILE_DELETE", folder_paths[-1]),
            file_rows,
        )
        self.assertNotIn(45, self._rule_ids(result))

    def test_rules_47_48_have_distinct_file_creation_and_activity_thresholds(self):
        timestamp = self._time()
        paths = [rf"C:\Users\test\Documents\file-{index}.txt" for index in range(5)]
        rows = [_row(timestamp, "FILE_CREATE", path) for path in paths]
        result = self._assess(_event(timestamp, "FILE_CREATE", paths[-1]), rows)
        self.assertIn(47, self._rule_ids(result))
        self.assertIn(48, self._rule_ids(result))

        mixed = [
            _row(timestamp, "FILE_CREATE", paths[0]),
            _row(timestamp, "FILE_MODIFY", paths[1]),
            _row(timestamp, "FILE_DELETE", paths[2]),
            _row(timestamp, "FILE_RENAME", paths[3]),
            _row(timestamp, "FILE_MODIFY", paths[4]),
        ]
        result = self._assess(_event(timestamp, "FILE_MODIFY", paths[-1]), mixed)
        self.assertIn(48, self._rule_ids(result))
        self.assertNotIn(47, self._rule_ids(result))

    def test_rule_49_unusual_type_not_inferred_without_type_baseline(self):
        timestamp = self._time()
        path = r"C:\Users\test\Documents\archive.xyz"
        result = self._assess(
            _event(timestamp, "FILE_CREATE", path),
            [_row(timestamp, "FILE_CREATE", path)],
        )
        self.assertNotIn(49, self._rule_ids(result))

    def test_sqlite_files_are_not_classified_as_user_activity(self):
        timestamp = self._time()
        path = r"C:\Users\test\Documents\riskalert.db"
        trigger = _event(timestamp, "FILE_MODIFY", path)
        result = self._assess(trigger, [_row(timestamp, "FILE_MODIFY", path)])
        self.assertFalse(set(range(26, 51)) & set(self._rule_ids(result)))

    def test_rule_persistence_keeps_exact_metadata_score_level_and_trigger(self):
        risk_db.initialize_riskalert_db()
        timestamp = self._time()
        path = r"C:\Users\test\Documents\settings.json"
        event = _event(timestamp, "FILE_MODIFY", path, "File content changed")
        rows = [_row(timestamp, "FILE_MODIFY", path, event["details"])]

        with (
            patch.object(risk_engine, "get_recent_events", return_value=rows),
            patch.object(
                event_risk_handler,
                "assess_risk",
                side_effect=lambda current_event: risk_engine.assess_risk(current_event),
            ),
        ):
            result = self._handler().handle_event(event)

        self.assertIn(28, self._rule_ids(result))
        with closing(sqlite3.connect(risk_db.DB_PATH)) as conn:
            record = conn.execute(
                """
                SELECT rule_id, rule_name, risk_score, risk_level, evidence_summary,
                       timestamp, trigger_event_id, trigger_event_source, trigger_details
                FROM risk_assessments
                WHERE rule_id = 28
                """
            ).fetchone()

        self.assertIsNotNone(record)
        self.assertEqual(record[:4], (28, get_rule(28).rule_name, result["score"], result["risk"]))
        self.assertIn(path, record[4])
        self.assertTrue(record[5])
        self.assertEqual(record[6:], ("FILE_MODIFY", "File Monitor", event["details"]))

    def test_rule_50_persists_separate_assessment_with_supporting_rules(self):
        risk_db.initialize_riskalert_db()
        timestamp = self._time()
        events = [
            _event(timestamp, "FILE_MODIFY", r"C:\Users\test\Documents\app.exe", "File content changed"),
            _event(timestamp, "FILE_MODIFY", r"C:\Users\test\Documents\settings.json", "File content changed"),
            _event(timestamp, "FILE_MODIFY", r"C:\Users\test\Documents\Credentials\key.pem", "File content changed"),
        ]
        rows = [
            _row(event["timestamp"], event["event_id"], event["application"], event["details"])
            for event in events
        ]
        with (
            patch.object(risk_engine, "get_recent_events", return_value=rows),
            patch.object(
                event_risk_handler,
                "assess_risk",
                side_effect=lambda current_event: risk_engine.assess_risk(current_event),
            ),
        ):
            result = self._handler().handle_event(events[-1])

        self.assertIn(50, self._rule_ids(result))
        with closing(sqlite3.connect(risk_db.DB_PATH)) as conn:
            record = conn.execute(
                """
                SELECT rule_id, rule_name, risk_score, risk_level, evidence_summary,
                       trigger_event_id
                FROM risk_assessments
                WHERE rule_id = 50
                """
            ).fetchone()

        self.assertIsNotNone(record)
        self.assertEqual(record[:2], (50, get_rule(50).rule_name))
        self.assertEqual(record[2:4], (result["score"], result["risk"]))
        self.assertIn("Rule 27", record[4])
        self.assertIn("Rule 28", record[4])
        self.assertIn("Rule 6", record[4])
        self.assertEqual(record[5], "FILE_MODIFY")

    def test_registry_definitions_keep_exact_official_names(self):
        expected = {
            26: "Hidden File Creation",
            27: "Executable File Modification",
            28: "Configuration File Modification",
            29: "Backup File Deletion",
            30: "Snapshot/Restore Point Deletion",
            31: "Mass Encryption",
            32: "Rapid Rename + Encryption",
            33: "Copy + Delete Original",
            34: "Access + External Transfer",
            35: "Privilege Change + File Activity",
            36: "New Device Activity",
            37: "Unusual Location Activity",
            38: "Dormant Account Activity",
            39: "Failed Login + File Activity",
            40: "Unusual Activity Spike",
            41: "Multiple Suspicious Operations",
            42: "High-Risk Process File Activity",
            43: "Protected File Access",
            44: "System File Modification",
            45: "Mass Folder Deletion",
            46: "Mass Folder Creation",
            47: "Mass File Creation",
            48: "File Activity Burst",
            49: "Unusual File Type Activity",
            50: "Combined Risk Detection",
        }
        self.assertEqual({rule_id: get_rule(rule_id).rule_name for rule_id in expected}, expected)


if __name__ == "__main__":
    unittest.main()
