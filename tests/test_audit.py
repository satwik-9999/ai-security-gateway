"""Unit tests for SQLite AuditLogger privacy, hashing, and querying."""

import os
import sqlite3
import tempfile

from gateway.audit.logger import AuditLogger


class TestAuditLogger:
    def setup_method(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.logger = AuditLogger(db_path=self.temp_db.name, salt="test_audit_salt")

    def teardown_method(self):
        if os.path.exists(self.temp_db.name):
            try:
                os.remove(self.temp_db.name)
            except Exception:
                pass

    def test_prompt_hashing_is_salted_and_irreversible(self):
        prompt = "Confidential prompt with secret key sk-12345"
        hash_1 = self.logger.hash_prompt(prompt)
        hash_2 = self.logger.hash_prompt(prompt)
        assert hash_1 == hash_2
        assert len(hash_1) == 64

        logger_alt = AuditLogger(db_path=self.temp_db.name, salt="different_salt")
        assert logger_alt.hash_prompt(prompt) != hash_1

    def test_log_event_never_stores_raw_prompt_or_secrets(self):
        raw_secret_prompt = "My credit card is 4532-0151-1283-0366 and password is secret123"
        row_id = self.logger.log_event(
            user_id="alice",
            user_group="finance",
            policy_name="balanced",
            prompt=raw_secret_prompt,
            decision="BLOCK",
            decision_reason="Credit card detected",
            detections_by_type={"CREDIT_CARD": 1},
            injection_score=0.1,
            latency_ms=12.4,
            model="mock-model",
        )
        assert row_id > 0

        # Directly inspect the raw SQLite database table rows
        with sqlite3.connect(self.temp_db.name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs WHERE id = ?", (row_id,))
            row = cursor.fetchone()

            # Schema: id, timestamp, user_id, user_group, policy_name, prompt_hash,
            # decision, decision_reason, detections_json, injection_score, latency_ms, model
            row_str = str(row)
            # Ensure the raw credit card or password is NEVER stored anywhere in the row!
            assert "4532-0151-1283-0366" not in row_str
            assert "secret123" not in row_str

    def test_query_logs_and_summary_stats(self):
        self.logger.log_event(
            user_id="user1",
            user_group="dev",
            policy_name="balanced",
            prompt="Hello world",
            decision="ALLOW",
            decision_reason="Conforms to policy",
            detections_by_type={},
            injection_score=0.0,
            latency_ms=5.0,
            model="mock-model",
        )
        self.logger.log_event(
            user_id="user2",
            user_group="sales",
            policy_name="balanced",
            prompt="Contact me at test@example.com",
            decision="MASK",
            decision_reason="Masked PII",
            detections_by_type={"EMAIL": 1},
            injection_score=0.0,
            latency_ms=8.0,
            model="mock-model",
        )

        logs = self.logger.query_logs(limit=10)
        assert len(logs) == 2

        stats = self.logger.get_summary_statistics()
        assert stats["total_requests"] == 2
        assert stats["decisions"]["ALLOW"] == 1
        assert stats["decisions"]["MASK"] == 1
        assert stats["detections_breakdown"]["EMAIL"] == 1
