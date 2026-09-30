"""Standard-library regression tests for TinyWatch storage and asset safety."""

import json
import sys
import tempfile
import threading
import time
import urllib.error
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

    def test_sampler_does_not_record_failed_or_unsupported_metrics_as_zero(self):
        original_store = tinywatch.STORE
        original_last_write = tinywatch.HISTORY_LAST_WRITE
        store = tinywatch.JsonStore(self.path)
        tinywatch.STORE = store
        tinywatch.HISTORY_LAST_WRITE = 0
        metrics = {
            "cpu": {"available": False},
            "memory": {"supported": False},
            "disk": {"supported": False},
            "network": {"supported": False},
            "load": [],
            "collector_errors": {"cpu": "counter read failed"},
        }
        self.addCleanup(setattr, tinywatch, "STORE", original_store)
        self.addCleanup(setattr, tinywatch, "HISTORY_LAST_WRITE", original_last_write)

        tinywatch._record_history({"local": {"online": True, "metrics": metrics}}, now=int(time.time()))

        self.assertEqual(store.data["history"]["local"], {})

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


class SnapshotReliabilityTests(unittest.TestCase):
    def test_cluster_snapshot_cache_avoids_repeated_remote_fanout(self):
        with tempfile.TemporaryDirectory(prefix="tinywatch-cluster-cache-") as directory:
            store = tinywatch.JsonStore(Path(directory) / "data.json")
            store.data["assets"] = [{"id": "remote-1", "name": "Remote",
                                     "url": "https://node.example", "password": "token"}]
            local_metrics = {"info": {"hostname": "local"}}
            remote_node = {"id": "remote-1", "name": "Remote", "online": True,
                           "metrics": {"cpu": {}, "info": {}}}
            with patch.object(tinywatch, "STORE", store), \
                    patch.object(tinywatch, "collect_snapshot", return_value=local_metrics), \
                    patch.object(tinywatch, "_remote_snapshot", return_value=remote_node) as remote_call, \
                    patch.object(tinywatch, "CLUSTER_SNAPSHOT_CACHE", {"sampled_at": 0.0, "data": None}):
                first = tinywatch.collect_cluster_snapshot(force_refresh=True)
                second = tinywatch.collect_cluster_snapshot()

                self.assertIs(first, second)
                self.assertEqual(second["nodes"]["remote-1"], remote_node)
                remote_call.assert_called_once()

    def test_concurrent_browser_poll_serves_stale_cache_during_refresh(self):
        with tempfile.TemporaryDirectory(prefix="tinywatch-stale-cache-") as directory:
            store = tinywatch.JsonStore(Path(directory) / "data.json")
            stale = {"nodes": {"local": {"online": True}}, "sampled_at": "old"}
            cache = {"sampled_at": time.monotonic() - tinywatch.CLUSTER_CACHE_SECONDS - 1,
                     "data": stale, "generation": 0}
            entered = threading.Event()
            release = threading.Event()

            def slow_local_sample():
                entered.set()
                if not release.wait(3):
                    raise TimeoutError("test refresh was not released")
                return {"info": {"hostname": "local"}}

            with patch.object(tinywatch, "STORE", store), \
                    patch.object(tinywatch, "CLUSTER_SNAPSHOT_CACHE", cache), \
                    patch.object(tinywatch, "collect_snapshot", side_effect=slow_local_sample):
                worker = threading.Thread(target=tinywatch.collect_cluster_snapshot, kwargs={"force_refresh": True})
                worker.start()
                try:
                    self.assertTrue(entered.wait(2))
                    response = tinywatch.collect_cluster_snapshot()
                    self.assertIs(response, stale)
                finally:
                    release.set()
                    worker.join(timeout=4)
                self.assertFalse(worker.is_alive())

    def test_collector_failure_does_not_fail_the_whole_snapshot(self):
        with patch.object(tinywatch, "_cpu_snapshot", side_effect=RuntimeError("cpu fixture failure")), \
                patch.object(tinywatch, "_memory_snapshot", return_value={"total": 100, "used": 40,
                                                                            "available": 60, "percent": 40,
                                                                            "supported": True}), \
                patch.object(tinywatch, "_disk_snapshot", return_value={"partitions": [], "total": 0,
                                                                          "used": 0, "percent": 0,
                                                                          "supported": False}), \
                patch.object(tinywatch, "_network_snapshot", return_value={"interfaces": [], "rx_rate": 0,
                                                                             "tx_rate": 0, "supported": False}), \
                patch.object(tinywatch, "_load_snapshot", return_value=[]), \
                patch.object(tinywatch, "_processes_linux", return_value=[]), \
                patch.object(tinywatch, "_login_events", return_value=[]), \
                patch.object(tinywatch, "_dns_cache", return_value={"source": "test", "count": 0,
                                                                      "entries": []}):
            with patch.object(tinywatch.platform, "system", return_value="Linux"):
                snapshot = tinywatch._collect_snapshot_now()

        self.assertFalse(snapshot["cpu"]["available"])
        self.assertEqual(snapshot["memory"]["total"], 100)
        self.assertIn("cpu", snapshot["collector_errors"])

    def test_remote_failure_reports_last_success_time(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, _limit):
                return (b'{"info":{},"cpu":{},"memory":{},"disk":{},"network":{"interfaces":[]},'
                        b'"load":[],"sampled_at":"2026-09-30T00:00:00+00:00"}')

        class Opener:
            def open(self, _request, timeout):
                return Response()

        asset = {"id": "remote-1", "name": "Remote", "url": "https://node.example",
                 "password": "token"}
        with patch.object(tinywatch, "REMOTE_LAST_SUCCESS", {}), \
                patch.object(tinywatch.urllib.request, "build_opener", return_value=Opener()):
            online = tinywatch._remote_snapshot(asset)
            self.assertTrue(online["online"])
            with patch.object(Opener, "open", side_effect=urllib.error.URLError("offline")):
                offline = tinywatch._remote_snapshot(asset)

        self.assertFalse(offline["online"])
        self.assertEqual(offline["last_success_at"], online["last_success_at"])

    def test_remote_failure_uses_persisted_history_after_restart(self):
        class Opener:
            def open(self, _request, timeout):
                raise urllib.error.URLError("offline")

        with tempfile.TemporaryDirectory(prefix="tinywatch-remote-history-") as directory:
            store = tinywatch.JsonStore(Path(directory) / "data.json")
            sampled_at = int(time.time()) - 180
            store.data["history"] = {"remote-1": {"cpu": [[sampled_at, 12.0]]}}
            asset = {"id": "remote-1", "name": "Remote", "url": "https://node.example",
                     "password": "token"}
            with patch.object(tinywatch, "STORE", store), \
                    patch.object(tinywatch, "REMOTE_LAST_SUCCESS", {}), \
                    patch.object(tinywatch.urllib.request, "build_opener", return_value=Opener()):
                result = tinywatch._remote_snapshot(asset)

        self.assertFalse(result["online"])
        self.assertEqual(result["last_success_at"],
                         tinywatch.datetime.fromtimestamp(sampled_at, tinywatch.timezone.utc).isoformat(timespec="seconds"))


class AuthenticationHardeningTests(unittest.TestCase):
    def test_expired_authentication_state_is_pruned(self):
        sessions = {"expired": 10, "active": 5000}
        failures = {"old-address": [10, 20], "recent-address": [999]}
        with patch.object(tinywatch, "SESSIONS", sessions), \
                patch.object(tinywatch, "LOGIN_FAILURES", failures), \
                patch.object(tinywatch, "AUTH_STATE_LAST_CLEANUP", 0):
            with tinywatch.STATE_LOCK:
                tinywatch._cleanup_auth_state(now=1000)

        self.assertEqual(sessions, {"active": 5000})
        self.assertEqual(failures, {"recent-address": [999]})

    def test_login_failure_address_map_has_a_hard_limit(self):
        failures = {}
        with patch.object(tinywatch, "LOGIN_FAILURES", failures):
            for index in range(tinywatch.MAX_LOGIN_FAILURE_ADDRESSES + 1):
                tinywatch._remember_login_failure("address-" + str(index), 1000)

        self.assertEqual(len(failures), tinywatch.MAX_LOGIN_FAILURE_ADDRESSES)
        self.assertNotIn("address-0", failures)

    def test_first_run_setup_requires_the_one_time_code(self):
        with patch.object(tinywatch, "SETUP_TOKEN", "one-time-secret"):
            self.assertTrue(tinywatch._setup_token_matches("one-time-secret"))
            self.assertFalse(tinywatch._setup_token_matches("wrong"))
            self.assertFalse(tinywatch._setup_token_matches(None))

    def test_setup_endpoint_requires_and_consumes_code(self):
        with tempfile.TemporaryDirectory(prefix="tinywatch-setup-code-") as directory:
            store = tinywatch.JsonStore(Path(directory) / "data.json")
            response = []
            handler = object.__new__(tinywatch.TinyWatchHandler)
            handler.path = "/api/setup"
            handler._read_json = lambda: {"password": "long-enough-password", "setup_token": "wrong"}
            handler._json = lambda status, value, headers=None: response.append((status, value))
            handler._create_session = lambda: response.append((tinywatch.HTTPStatus.OK, {"session": True}))
            with patch.object(tinywatch, "STORE", store), patch.object(tinywatch, "SETUP_TOKEN", "one-time-secret"):
                handler.do_POST()
                self.assertIsNone(store.data["password"])
                self.assertEqual(response[-1][0], tinywatch.HTTPStatus.FORBIDDEN)

                handler._read_json = lambda: {"password": "long-enough-password", "setup_token": "one-time-secret"}
                with patch.object(tinywatch, "_password_hash", return_value={"hash": "test"}):
                    handler.do_POST()

                self.assertEqual(store.data["password"], {"hash": "test"})
                self.assertFalse(tinywatch._setup_token_matches("one-time-secret"))

    def test_secure_cookie_flag_is_opt_in(self):
        with patch.object(tinywatch, "SECURE_COOKIE", False):
            self.assertNotIn("; Secure", tinywatch._session_cookie("token", 100))
        with patch.object(tinywatch, "SECURE_COOKIE", True):
            self.assertIn("; Secure", tinywatch._session_cookie("token", 100))


if __name__ == "__main__":
    unittest.main()
