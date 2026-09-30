"""Standard-library regression tests for TinyWatch storage and asset safety."""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import tinywatch


class JsonStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="tinywatch-tests-")
        self.addCleanup(self.temp_dir.cleanup)
        self.path = Path(self.temp_dir.name) / "data.json"

    def test_save_keeps_a_known_good_backup(self):
        store = tinywatch.JsonStore(self.path)
        now = int(time.time())
        store.data["theme"] = "light"
        store.data["history_retention_days"] = 1
        store.data["history"] = {"local": {"cpu": [[now - 2 * 86400, 1], [now - 60, 2]]}}
        store.save()
        store.data["theme"] = "dark"
        store.save(backup_retention_days=1)

        backup = json.loads(self.path.with_name("data.json.bak").read_text(encoding="utf-8"))
        current = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(backup["theme"], "light")
        self.assertEqual(current["theme"], "dark")
        self.assertEqual(backup["history"]["local"]["cpu"], [[now - 60, 2]])

    def test_regular_save_copies_the_previous_database(self):
        store = tinywatch.JsonStore(self.path)
        store.data["theme"] = "light"
        store.save()
        store.data["theme"] = "dark"
        store.save()

        backup = json.loads(self.path.with_name("data.json.bak").read_text(encoding="utf-8"))
        self.assertEqual(backup["theme"], "light")

    def test_corrupt_primary_is_preserved_and_restored_from_backup(self):
        store = tinywatch.JsonStore(self.path)
        store.data["theme"] = "light"
        store.save()
        store.data["theme"] = "dark"
        store.save()
        self.path.write_text("{broken", encoding="utf-8")

        recovered = tinywatch.JsonStore(self.path)

        self.assertTrue(recovered.recovered_from_backup)
        self.assertEqual(recovered.data["theme"], "light")
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8"))["theme"], "light")
        self.assertTrue(list(self.path.parent.glob("data.json.corrupt-*")))

    def test_corrupt_database_without_backup_fails_without_overwriting_file(self):
        self.path.write_text("{broken", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "no valid backup"):
            tinywatch.JsonStore(self.path)

        self.assertEqual(self.path.read_text(encoding="utf-8"), "{broken")

    def test_sampler_prunes_samples_outside_retention(self):
        original_store = tinywatch.STORE
        original_last_write = tinywatch.HISTORY_LAST_WRITE
        store = tinywatch.JsonStore(self.path)
        tinywatch.STORE = store
        tinywatch.HISTORY_LAST_WRITE = 0
        now = int(time.time())
        store.data["history"] = {"local": {"cpu": [[now - 2 * 86400, 2.0]]}}
        store.data["history_retention_days"] = 1
        metrics = {
            "cpu": {"percent": 23},
            "memory": {"used": 20, "total": 100, "percent": 20},
            "disk": {"used": 30, "total": 100, "percent": 30},
            "network": {"interfaces": []},
            "load": [0.25],
        }
        self.addCleanup(setattr, tinywatch, "STORE", original_store)
        self.addCleanup(setattr, tinywatch, "HISTORY_LAST_WRITE", original_last_write)

        tinywatch._record_history({"local": {"online": True, "metrics": metrics}}, now=now)

        cpu_samples = tinywatch.STORE.data["history"]["local"]["cpu"]
        self.assertEqual(cpu_samples, [[now, 23.0]])

    def test_retention_change_prunes_primary_and_backup(self):
        store = tinywatch.JsonStore(self.path)
        now = int(time.time())
        store.data["history"] = {"local": {"cpu": [[now - 2 * 86400, 1], [now - 60, 2]]}}
        store.save()
        handler = object.__new__(tinywatch.TinyWatchHandler)
        value = {"assets": [], "widgets": [], "theme": "dark", "history_retention_days": 1}

        with patch.object(tinywatch, "STORE", store):
            handler._save_config(value)

        primary = json.loads(self.path.read_text(encoding="utf-8"))
        backup = json.loads(self.path.with_name("data.json.bak").read_text(encoding="utf-8"))
        expected = [[now - 60, 2]]
        self.assertEqual(primary["history"]["local"]["cpu"], expected)
        self.assertEqual(backup["history"]["local"]["cpu"], expected)


class RemoteAssetSafetyTests(unittest.TestCase):
    def test_https_is_required_for_non_loopback_assets(self):
        self.assertEqual(tinywatch._validate_asset_url("https://node.example:8765"), "https://node.example:8765")
        self.assertTrue(tinywatch._is_loopback_host("127.0.0.8"))
        self.assertTrue(tinywatch._is_loopback_host("::1"))
        self.assertTrue(tinywatch._is_loopback_host("host.localhost"))
        self.assertFalse(tinywatch._is_loopback_host("node.example"))

    def test_plain_http_remote_is_rejected_before_request(self):
        asset = {"id": "remote-1", "name": "Remote", "url": "http://10.0.0.12:8765", "password": "secret-token"}
        with patch.object(tinywatch.urllib.request, "build_opener") as build_opener:
            result = tinywatch._remote_snapshot(asset)

        self.assertFalse(result["online"])
        self.assertIsNone(result["metrics"])
        build_opener.assert_not_called()

    def test_new_plain_http_remote_is_rejected_from_configuration(self):
        with tempfile.TemporaryDirectory(prefix="tinywatch-config-tests-") as directory:
            store = tinywatch.JsonStore(Path(directory) / "data.json")
            handler = object.__new__(tinywatch.TinyWatchHandler)
            value = {
                "assets": [{"id": "remote-1", "name": "Remote", "url": "http://10.0.0.12:8765", "password": "secret-token"}],
                "widgets": [],
                "theme": "dark",
                "history_retention_days": 7,
            }
            with patch.object(tinywatch, "STORE", store):
                with self.assertRaisesRegex(ValueError, "必须使用 HTTPS"):
                    handler._save_config(value)

            self.assertEqual(store.data["assets"], [])

    def test_redirect_handler_never_returns_a_followup_request(self):
        handler = tinywatch._RejectRedirectHandler()

        request = handler.redirect_request(None, None, 302, "Found", {}, "https://other.example/")

        self.assertIsNone(request)

    def test_browser_config_never_discloses_remote_asset_token(self):
        with tempfile.TemporaryDirectory(prefix="tinywatch-public-config-") as directory:
            store = tinywatch.JsonStore(Path(directory) / "data.json")
            store.data["assets"] = [{
                "id": "remote-1",
                "name": "Remote",
                "url": "https://node.example:8765",
                "password": "secret-token",
            }]
            with patch.object(tinywatch, "STORE", store):
                config = tinywatch._config_for_browser()

        self.assertTrue(config["assets"][0]["secure_transport"])
        self.assertNotIn("secret-token", json.dumps(config))
        self.assertNotIn("password", config["assets"][0])


if __name__ == "__main__":
    unittest.main()
