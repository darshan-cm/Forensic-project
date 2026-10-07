import sqlite3
import tempfile
import unittest
from pathlib import Path

import database.riskalert_db as risk_db
from detection.rule_registry import OFFICIAL_50_RULES, get_rule, get_rule_name


class RiskRuleRegistryTests(unittest.TestCase):
    def _use_temp_db(self):
        temp_dir = tempfile.mkdtemp(prefix="forensicguard_rule_registry_")
        temp_path = Path(temp_dir)
        original_db_path = risk_db.DB_PATH
        original_forensic_path = risk_db.FORENSIC_DB_PATH
        risk_db.DB_PATH = temp_path / "riskalert.db"
        risk_db.FORENSIC_DB_PATH = temp_path / "forensic.db"
        return original_db_path, original_forensic_path, temp_path

    def _restore_db_paths(self, original_db_path, original_forensic_path, temp_path=None):
        risk_db.DB_PATH = original_db_path
        risk_db.FORENSIC_DB_PATH = original_forensic_path
        if temp_path is not None:
            try:
                for file_path in temp_path.iterdir():
                    if file_path.is_file():
                        try:
                            file_path.unlink()
                        except PermissionError:
                            pass
                temp_path.rmdir()
            except (FileNotFoundError, PermissionError, OSError):
                pass

    def test_official_registry_has_50_rules(self):
        self.assertEqual(len(OFFICIAL_50_RULES), 50)
        self.assertEqual(get_rule(1).rule_name, "Large File Copy")
        self.assertEqual(get_rule_name(1), "Large File Copy")
        self.assertEqual(get_rule(50).rule_name, "Combined Risk Detection")

    def test_can_save_risk_assessment_with_rule_metadata(self):
        original_db_path, original_forensic_path, temp_path = self._use_temp_db()

        try:
            risk_db.initialize_riskalert_db()
            risk_id = risk_db.record_risk_assessment(
                {"risk": "HIGH", "score": 88, "evidence": ["Large transfer detected."]},
                rule_id=1,
                rule_name="Large File Copy",
            )

            conn = sqlite3.connect(risk_db.DB_PATH)
            row = conn.execute(
                "SELECT rule_id, rule_name, risk_level, risk_score FROM risk_assessments WHERE id = ?",
                (risk_id,),
            ).fetchone()
            conn.close()

            self.assertEqual(row, (1, "Large File Copy", "HIGH", 88))
        finally:
            self._restore_db_paths(original_db_path, original_forensic_path, temp_path)

    def test_can_save_risk_assessment_without_rule_metadata(self):
        original_db_path, original_forensic_path, temp_path = self._use_temp_db()

        try:
            risk_db.initialize_riskalert_db()
            risk_id = risk_db.record_risk_assessment(
                {"risk": "LOW", "score": 12, "evidence": ["Routine activity."]}
            )

            conn = sqlite3.connect(risk_db.DB_PATH)
            row = conn.execute(
                "SELECT rule_id, rule_name, risk_level, risk_score FROM risk_assessments WHERE id = ?",
                (risk_id,),
            ).fetchone()
            conn.close()

            self.assertEqual(row, (None, None, "LOW", 12))
        finally:
            self._restore_db_paths(original_db_path, original_forensic_path, temp_path)

    def test_existing_risk_records_remain_readable(self):
        original_db_path, original_forensic_path, temp_path = self._use_temp_db()

        try:
            risk_db.initialize_riskalert_db()

            conn = sqlite3.connect(risk_db.DB_PATH)
            conn.execute(
                """
                INSERT INTO risk_assessments (
                    timestamp,
                    risk_level,
                    risk_score,
                    activity_type,
                    trigger_event_id,
                    trigger_event_source,
                    alert_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "2024-01-01 00:00:00",
                    "MEDIUM",
                    55,
                    "USB_TRANSFER",
                    "USB_CONNECTED",
                    "USB Monitor",
                    "Legacy risk record",
                ),
            )
            conn.commit()
            conn.close()

            rows = risk_db.get_recent_risk_history(5)
            self.assertTrue(any(row[2] == "MEDIUM" and row[3] == 55 for row in rows))
        finally:
            self._restore_db_paths(original_db_path, original_forensic_path, temp_path)

    def test_schema_migration_adds_rule_columns_to_existing_database(self):
        original_db_path, original_forensic_path, temp_path = self._use_temp_db()

        try:
            legacy_db = risk_db.DB_PATH
            conn = sqlite3.connect(legacy_db)
            conn.execute(
                """
                CREATE TABLE risk_assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    activity_type TEXT,
                    alert_message TEXT
                )
                """
            )
            conn.execute(
                """
                INSERT INTO risk_assessments (
                    timestamp,
                    risk_level,
                    risk_score,
                    activity_type,
                    alert_message
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "2024-02-02 10:10:10",
                    "HIGH",
                    75,
                    "FILE_COPY",
                    "Legacy row",
                ),
            )
            conn.commit()
            conn.close()

            risk_db.initialize_riskalert_db()

            conn = sqlite3.connect(legacy_db)
            columns = [row[1] for row in conn.execute("PRAGMA table_info(risk_assessments)").fetchall()]
            row = conn.execute(
                "SELECT rule_id, rule_name, risk_level, risk_score FROM risk_assessments WHERE alert_message = ?",
                ("Legacy row",),
            ).fetchone()
            conn.close()

            self.assertIn("rule_id", columns)
            self.assertIn("rule_name", columns)
            self.assertEqual(row, (None, None, "HIGH", 75))
        finally:
            self._restore_db_paths(original_db_path, original_forensic_path, temp_path)


if __name__ == "__main__":
    unittest.main()
