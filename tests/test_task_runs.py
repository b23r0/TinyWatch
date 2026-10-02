"""Task report regression coverage; all data belongs to the test directory."""

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import tinywatch


class TaskRunTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="tinywatch-task-runs-")
        self.addCleanup(self.directory.cleanup)
        self.store = tinywatch.JsonStore(Path(self.directory.name) / "data.json")
        self.token = "test-task-token"
        self.job = {"id": "job-test", "node": "local", "name": "Test task",
                    "interval": 3600, "grace": 60, "max_runtime": 60,
                    "token": self.token, "created_at": int(time.time()),
                    "last_success_at": None}
        self.store.data["heartbeats"] = [self.job]
        store_patch = patch.object(tinywatch, "STORE", self.store)
        store_patch.start()
        self.addCleanup(store_patch.stop)

    def report(self, event, identity, **fields):
        return tinywatch._receive_heartbeat(dict(event=event, run_id=identity, **fields), self.token)

    def run_record(self, identity):
        return next(row for row in self.store.data["job_runs"]["job-test"] if row["id"] == identity)

    def test_start_and_completion_reports_are_idempotent(self):
        self.assertTrue(self.report("start", "run-1"))
        self.assertTrue(self.report("start", "run-1"))
        self.assertEqual(len(self.store.data["job_runs"]["job-test"]), 1)
        self.assertTrue(self.report("success", "run-1", duration_ms=123))
        self.assertTrue(self.report("success", "run-1", duration_ms=123))
        self.assertEqual(self.run_record("run-1")["duration_ms"], 123)
        self.assertEqual(len(self.store.data["job_runs"]["job-test"]), 1)

    def test_failure_opens_incident_and_success_recovers(self):
        self.report("start", "run-1")
        self.report("fail", "run-1", message="Failed test execution")
        self.assertTrue(self.store.data["service_states"]["job-test"]["active_id"])
        self.report("success", "run-2", duration_ms=50)
        self.assertNotIn("active_id", self.store.data["service_states"]["job-test"])

    def test_timeout_marker_survives_late_success(self):
        self.report("start", "run-1")
        self.run_record("run-1")["started_at"] = int(time.time()) - 120
        tinywatch._check_heartbeats()
        self.assertEqual(self.run_record("run-1")["status"], "timeout")
        self.report("success", "run-1")
        self.assertEqual(self.run_record("run-1")["status"], "success")
        self.assertIn("timed_out_at", self.run_record("run-1"))

    def test_overlap_is_marked_and_concurrency_is_bounded(self):
        for index in range(4):
            self.report("start", "run-" + str(index))
        self.assertTrue(self.run_record("run-1")["overlap"])
        with self.assertRaisesRegex(ValueError, "four simultaneous"):
            self.report("start", "run-4")

    def test_failed_save_rolls_back_run_and_incident_changes(self):
        self.report("start", "run-1")
        with patch.object(self.store, "save", side_effect=OSError("test write failure")):
            with self.assertRaises(OSError):
                self.report("fail", "run-1")
        self.assertEqual(self.run_record("run-1")["status"], "running")
        self.assertFalse(self.store.data["incidents"])

    def test_invalid_token_is_rejected(self):
        self.assertFalse(tinywatch._receive_heartbeat({"event": "start", "run_id": "run-1"}, "wrong-token"))
        self.assertFalse(self.store.data["job_runs"])


if __name__ == "__main__":
    unittest.main()
