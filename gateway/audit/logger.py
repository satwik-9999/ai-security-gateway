"""Privacy-preserving SQLite audit logger storing salted hashes and aggregate detection counts."""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class AuditLogger:
    """Zero-raw-leak audit logger backed by SQLite."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        user_id TEXT NOT NULL,
        user_group TEXT NOT NULL,
        policy_name TEXT NOT NULL,
        prompt_hash TEXT NOT NULL,
        decision TEXT NOT NULL,
        decision_reason TEXT NOT NULL,
        detections_json TEXT NOT NULL,
        injection_score REAL NOT NULL,
        latency_ms REAL NOT NULL,
        model TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_logs(decision);
    CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
    """

    def __init__(self, db_path: str = "gateway.db", salt: Optional[str] = None):
        self.db_path = db_path
        self.salt = salt or "default_secret_salt_for_prompt_hashing"
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(self.SCHEMA)
            conn.commit()

    def hash_prompt(self, prompt: str) -> str:
        """Compute salted SHA-256 digest of prompt to prevent credential storage."""
        salted = f"{self.salt}:{prompt}".encode("utf-8")
        return hashlib.sha256(salted).hexdigest()

    def log_event(
        self,
        user_id: str,
        user_group: str,
        policy_name: str,
        prompt: str,
        decision: str,
        decision_reason: str,
        detections_by_type: Dict[str, int],
        injection_score: float,
        latency_ms: float,
        model: str,
        timestamp: Optional[str] = None,
    ) -> int:
        """Persist a privacy-preserving audit entry without storing raw sensitive data."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        prompt_hash = self.hash_prompt(prompt)
        detections_json = json.dumps(detections_by_type)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_logs (
                    timestamp, user_id, user_group, policy_name, prompt_hash,
                    decision, decision_reason, detections_json, injection_score,
                    latency_ms, model
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    user_id,
                    user_group,
                    policy_name,
                    prompt_hash,
                    decision,
                    decision_reason,
                    detections_json,
                    round(injection_score, 4),
                    round(latency_ms, 2),
                    model,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def query_logs(
        self,
        limit: int = 100,
        offset: int = 0,
        decision: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query audit log entries."""
        query = "SELECT * FROM audit_logs"
        params: List[Any] = []
        conditions = []

        if decision:
            conditions.append("decision = ?")
            params.append(decision)
        if user_id:
            conditions.append("user_id = ?")
            params.append(user_id)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

            result = []
            for row in rows:
                item = dict(row)
                try:
                    item["detections_by_type"] = json.loads(item["detections_json"])
                except Exception:
                    item["detections_by_type"] = {}
                result.append(item)
            return result

    def get_summary_statistics(self) -> Dict[str, Any]:
        """Aggregate metrics for dashboard and reporting."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*), AVG(latency_ms) FROM audit_logs")
            total_count, avg_latency = cursor.fetchone()

            cursor.execute("SELECT decision, COUNT(*) FROM audit_logs GROUP BY decision")
            decisions = dict(cursor.fetchall())

            cursor.execute("SELECT detections_json FROM audit_logs")
            all_dets = cursor.fetchall()

            detection_counts: Dict[str, int] = {}
            for (det_str,) in all_dets:
                try:
                    d = json.loads(det_str)
                    for k, v in d.items():
                        detection_counts[k] = detection_counts.get(k, 0) + v
                except Exception:
                    continue

            return {
                "total_requests": total_count or 0,
                "avg_latency_ms": round(avg_latency or 0.0, 2),
                "decisions": decisions,
                "detections_breakdown": detection_counts,
            }
