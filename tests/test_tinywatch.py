"""Standard-library regression tests for TinyWatch storage and asset safety."""

import json
import copy
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
        restored_backup, error = tinywatch.JsonStore._read_database(self.path.with_name("data.json.bak"))
        self.assertIsNone(error)
        self.assertEqual(restored_backup["history"]["local"]["cpu"], [[now - 60, 2]])

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

        series = store.data["history"]["local"]
        self.assertFalse(set(series) & {"cpu", "memory", "disk", "network", "load"})
        self.assertEqual(series["observations"][0][1]["collector_errors"], metrics["collector_errors"])

    def test_retention_change_prunes_primary_and_backup(self):
        store = tinywatch.JsonStore(self.path)
        now = int(time.time())
        store.data["history"] = {"local": {"cpu": [[now - 2 * 86400, 1], [now - 60, 2]]}}
        store.save()
        handler = object.__new__(tinywatch.TinyWatchHandler)
        value = {"assets": [], "widgets": [], "theme": "dark", "history_retention_days": 1}

        with patch.object(tinywatch, "STORE", store):
            handler._save_config(value)

        primary, primary_error = tinywatch.JsonStore._read_database(self.path)
        backup, backup_error = tinywatch.JsonStore._read_database(self.path.with_name("data.json.bak"))
        self.assertIsNone(primary_error)
        self.assertIsNone(backup_error)
        expected = [[now - 60, 2]]
        self.assertEqual(primary["history"]["local"]["cpu"], expected)
        self.assertEqual(backup["history"]["local"]["cpu"], expected)


class RemoteAssetSafetyTests(unittest.TestCase):
    def test_ip_and_port_normalizes_to_http_and_https_is_optional(self):
        self.assertEqual(tinywatch._validate_asset_url("10.0.0.12:8765"), "http://10.0.0.12:8765")
        self.assertEqual(tinywatch._validate_asset_url("[::1]:8765"), "http://[::1]:8765")
        self.assertEqual(tinywatch._validate_asset_url("https://node.example:8765"), "https://node.example:8765")
        self.assertTrue(tinywatch._is_loopback_host("127.0.0.8"))
        self.assertTrue(tinywatch._is_loopback_host("::1"))
        self.assertTrue(tinywatch._is_loopback_host("host.localhost"))
        self.assertFalse(tinywatch._is_loopback_host("node.example"))

    def test_plain_http_remote_uses_the_same_simple_token_request(self):
        asset = {"id": "remote-1", "name": "Remote", "url": "http://10.0.0.12:8765", "password": "secret-token"}
        with patch.object(tinywatch.urllib.request, "build_opener") as build_opener:
            build_opener.return_value.open.side_effect = urllib.error.URLError("fixture offline")
            result = tinywatch._remote_snapshot_direct(asset)

        self.assertFalse(result["online"])
        self.assertIsNone(result["metrics"])
        request = build_opener.return_value.open.call_args.args[0]
        self.assertEqual(request.full_url, "http://10.0.0.12:8765/api/agent/metrics")
        self.assertEqual(request.get_header("X-tinywatch-token"), "secret-token")
        self.assertIn("fixture offline", result["error"])

    def test_plain_http_remote_can_be_saved_without_a_certificate(self):
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
                handler._save_config(value)

            self.assertEqual(store.data["assets"][0]["url"], "http://10.0.0.12:8765")

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
    def test_cluster_snapshot_reads_asset_cache_without_remote_fanout(self):
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
                    patch.object(tinywatch, "CLUSTER_SNAPSHOT_CACHE", {"sampled_at": 0.0, "data": None, "generation": 0}), \
                    patch.object(tinywatch, "ASSET_CACHE", {"remote-1": {
                        "configuration": store.data["assets"][0], "result": remote_node}}):
                first = tinywatch.collect_cluster_snapshot(force_refresh=True)
                second = tinywatch.collect_cluster_snapshot()

                self.assertIs(first, second)
                self.assertEqual(second["nodes"]["remote-1"]["metrics"], remote_node["metrics"])
                self.assertTrue(second["nodes"]["remote-1"]["online"])
                remote_call.assert_not_called()

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

    def test_refresh_failure_releases_lock_and_can_retry(self):
        with tempfile.TemporaryDirectory(prefix="tinywatch-refresh-failure-") as directory:
            store = tinywatch.JsonStore(Path(directory) / "data.json")
            cache = {"sampled_at": 0.0, "data": None, "generation": 0}
            lock = threading.Lock()
            with patch.object(tinywatch, "STORE", store), \
                    patch.object(tinywatch, "CLUSTER_SNAPSHOT_CACHE", cache), \
                    patch.object(tinywatch, "CLUSTER_REFRESH_LOCK", lock), \
                    patch.object(tinywatch, "collect_snapshot", side_effect=[OSError("fixture failure"), {"info": {}}]):
                with self.assertRaises(OSError):
                    tinywatch.collect_cluster_snapshot()
                self.assertFalse(lock.locked())
                self.assertTrue(tinywatch.collect_cluster_snapshot()["nodes"]["local"]["online"])
                self.assertFalse(lock.locked())

    def test_invalidation_during_refresh_does_not_publish_old_generation(self):
        with tempfile.TemporaryDirectory(prefix="tinywatch-refresh-generation-") as directory:
            store = tinywatch.JsonStore(Path(directory) / "data.json")
            cache = {"sampled_at": 0.0, "data": None, "generation": 0}

            def sample():
                tinywatch._invalidate_cluster_snapshot()
                return {"info": {}}

            with patch.object(tinywatch, "STORE", store), \
                    patch.object(tinywatch, "CLUSTER_SNAPSHOT_CACHE", cache), \
                    patch.object(tinywatch, "collect_snapshot", side_effect=sample):
                tinywatch.collect_cluster_snapshot()
                self.assertIsNone(cache["data"])
                self.assertEqual(cache["generation"], 1)

    def test_unsampled_asset_is_pending_without_synchronous_probe(self):
        with tempfile.TemporaryDirectory(prefix="tinywatch-pending-asset-") as directory:
            store = tinywatch.JsonStore(Path(directory) / "data.json")
            store.data["assets"] = [{"id": "remote-1", "name": "Remote", "url": "http://node.example", "password": "token"}]
            with patch.object(tinywatch, "STORE", store), \
                    patch.object(tinywatch, "ASSET_CACHE", {}), \
                    patch.object(tinywatch, "CLUSTER_SNAPSHOT_CACHE", {"sampled_at": 0.0, "data": None, "generation": 0}), \
                    patch.object(tinywatch, "collect_snapshot", return_value={"info": {}}), \
                    patch.object(tinywatch, "_remote_snapshot") as probe:
                result = tinywatch.collect_cluster_snapshot()
                node = result["nodes"]["remote-1"]
                self.assertTrue(node["pending"])
                self.assertEqual(node["status"], "initializing")
                self.assertIsNone(node["metrics"])
                probe.assert_not_called()

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
                                                                      "entries": []}), \
                patch.object(tinywatch, "_host_profile", return_value={"hostname": "fixture"}):
            with patch.object(tinywatch.platform, "system", return_value="Linux"):
                snapshot = tinywatch._collect_snapshot_now()

        self.assertFalse(snapshot["cpu"]["available"])
        self.assertEqual(snapshot["memory"]["total"], 100)
        self.assertIn("cpu", snapshot["collector_errors"])

    def test_remote_failure_reports_last_success_time(self):
        asset = {"id": "remote-1", "name": "Remote", "url": "https://node.example", "password": "token"}
        sampled_at = "2026-09-30T00:00:00+00:00"
        online_result = dict(id=asset["id"], name=asset["name"], online=True,
                             metrics={}, last_success_at=sampled_at)
        offline_result = dict(id=asset["id"], name=asset["name"], online=False,
                              metrics=None, error="offline")
        with patch.object(tinywatch, "REMOTE_LAST_SUCCESS", {}), \
                patch.object(tinywatch, "_bounded_network_probe", side_effect=[online_result, offline_result]) as probe:
            online = tinywatch._remote_snapshot(asset)
            offline = tinywatch._remote_snapshot(asset)
        self.assertTrue(online["online"])
        self.assertFalse(offline["online"])
        self.assertEqual(offline["last_success_at"], sampled_at)
        self.assertEqual(probe.call_count, 2)
        probe.assert_called_with("asset", asset, 12)

    def test_remote_failure_uses_persisted_history_after_restart(self):
        with tempfile.TemporaryDirectory(prefix="tinywatch-remote-history-") as directory:
            store = tinywatch.JsonStore(Path(directory) / "data.json")
            sampled_at = int(time.time()) - 180
            store.data["history"] = {"remote-1": {"cpu": [[sampled_at, 12.0]]}}
            asset = {"id": "remote-1", "name": "Remote", "url": "https://node.example",
                     "password": "token"}
            with patch.object(tinywatch, "STORE", store), \
                    patch.object(tinywatch, "REMOTE_LAST_SUCCESS", {}), \
                    patch.object(tinywatch, "_bounded_network_probe", side_effect=OSError("offline")):
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


class AlertLifecycleTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="tinywatch-alerts-")
        self.addCleanup(directory.cleanup)
        self.store = tinywatch.JsonStore(Path(directory.name) / "data.json")
        self.now = int(time.time())
        self.rule = {"id": "cpu-rule", "name": "CPU high", "node": "local", "metric": "cpu",
                     "mode": "threshold", "threshold": 90, "recovery": 85,
                     "duration": 120, "cooldown": 300, "enabled": True}
        self.store.data["alert_rules"] = [self.rule]
        patcher = patch.object(tinywatch, "STORE", self.store)
        patcher.start()
        self.addCleanup(patcher.stop)

    def node(self, value, offset=0):
        stamp = tinywatch.datetime.fromtimestamp(self.now + offset, tinywatch.timezone.utc).isoformat()
        return {"name": "Local", "online": True, "metrics": {
            "sampled_at": stamp, "cpu": {"percent": value, "available": True},
            "processes": [{"pid": 123, "name": "fixture-worker", "cpu": value, "memory": 100}],
            "logins": [{"kind": "SSH", "message": "fixture event"}],
            "dns": {"count": 3, "source": "fixture"}}}

    def evaluate(self, value, offset):
        tinywatch._evaluate_alerts({"local": self.node(value, offset)}, self.now + offset)

    def test_duration_deduplication_hysteresis_and_cooldown(self):
        for offset in (0, 60, 120, 180):
            self.evaluate(95, offset)
        self.assertEqual(len(self.store.data["incidents"]), 1)
        incident = self.store.data["incidents"][0]
        self.assertEqual(incident["triggered_at"], self.now + 120)
        self.assertEqual(incident["context"]["processes"][0]["name"], "fixture-worker")
        self.evaluate(88, 240)
        self.assertEqual(incident["status"], "active")
        self.evaluate(84, 300)
        self.assertEqual(incident["status"], "resolved")
        for offset in (360, 420, 480, 540, 600, 660):
            self.evaluate(95, offset)
        self.assertEqual(len(self.store.data["incidents"]), 1)
        self.evaluate(95, 720)
        self.assertEqual(len(self.store.data["incidents"]), 2)

    def test_unknown_metrics_reset_pending_and_never_resolve_an_incident(self):
        self.evaluate(95, 0)
        broken = self.node(0, 60)
        broken["metrics"]["collector_errors"] = {"cpu": "fixture failure"}
        tinywatch._evaluate_alerts({"local": broken}, self.now + 60)
        self.evaluate(95, 120)
        self.evaluate(95, 180)
        self.assertEqual(self.store.data["incidents"], [])
        self.evaluate(95, 240)
        self.assertEqual(self.store.data["incidents"][0]["status"], "active")
        broken["metrics"]["sampled_at"] = self.node(0, 300)["metrics"]["sampled_at"]
        tinywatch._evaluate_alerts({"local": broken}, self.now + 300)
        self.assertEqual(self.store.data["incidents"][0]["status"], "active")

    def test_sampler_pause_does_not_count_as_continuous_breach(self):
        self.evaluate(95, 0)
        self.evaluate(95, 300)
        self.evaluate(95, 360)
        self.assertEqual(self.store.data["incidents"], [])
        self.evaluate(95, 420)
        self.assertEqual(len(self.store.data["incidents"]), 1)

    def test_baseline_warmup_and_frozen_explainable_threshold(self):
        self.rule.update(mode="baseline", threshold=10, recovery=0, duration=60)
        self.evaluate(50, 0)
        self.assertEqual(self.store.data["alert_states"]["cpu-rule:local"]["evaluation"], "warming_up")
        self.store.data["history"] = {"local": {"cpu": [
            [self.now - (index + 11) * 60, 15.25] for index in range(60)
        ]}}
        self.evaluate(50, 60)
        self.evaluate(50, 120)
        incident = self.store.data["incidents"][0]
        self.assertEqual(incident["baseline"]["median"], 15.25)
        self.assertEqual(incident["baseline"]["samples"], 60)
        self.assertEqual(incident["threshold"], 25.25)
        self.store.data["history"]["local"]["cpu"] = [[self.now - 1000, 99]] * 60
        self.evaluate(50, 180)
        self.assertEqual(incident["status"], "active")
        self.evaluate(20, 240)
        self.assertEqual(incident["status"], "resolved")

    def test_acknowledgement_is_idempotent_and_does_not_end_monitoring(self):
        self.rule["duration"] = 0
        self.evaluate(95, 0)
        incident = self.store.data["incidents"][0]
        self.assertTrue(tinywatch._acknowledge_incident(incident["id"]))
        acknowledged_at = incident["acknowledged_at"]
        self.assertTrue(tinywatch._acknowledge_incident(incident["id"]))
        self.assertEqual(incident["acknowledged_at"], acknowledged_at)
        self.assertEqual(incident["status"], "active")
        self.assertEqual(tinywatch._alert_counts()["unacknowledged_count"], 0)
        self.evaluate(80, 60)
        self.assertEqual(incident["status"], "resolved")

    def test_open_incident_survives_restart_without_duplicate(self):
        self.rule["duration"] = 0
        self.evaluate(95, 0)
        self.store.save()
        reopened = tinywatch.JsonStore(self.store.path)
        with patch.object(tinywatch, "STORE", reopened):
            self.evaluate(95, 60)
        self.assertEqual(len(reopened.data["incidents"]), 1)
        self.assertEqual(reopened.data["incidents"][0]["status"], "active")

    def test_rule_edit_resolves_old_incident_and_clears_pending_state(self):
        self.rule["duration"] = 0
        self.evaluate(95, 0)
        changed = dict(self.rule, threshold=98)
        tinywatch._save_alert_rules([changed])
        self.assertEqual(self.store.data["incidents"][0]["resolution_reason"], "rule_changed")
        self.assertEqual(self.store.data["alert_states"], {})
        self.evaluate(95, 60)
        self.assertEqual(len(self.store.data["incidents"]), 1)

    def test_invalid_rule_config_is_rejected_without_mutation(self):
        original = copy.deepcopy(self.store.data["alert_rules"])
        for change in ({"threshold": float("nan")}, {"recovery": 95}, {"duration": -1},
                       {"cooldown": float("inf")}, {"node": []}, {"node": "missing"},
                       {"metric": "invalid"}, {"metric": "offline", "threshold": 1},
                       {"mode": "baseline", "threshold": 0}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                tinywatch._save_alert_rules([dict(self.rule, **change)])
            self.assertEqual(self.store.data["alert_rules"], original)

    def test_offline_rule_applies_to_each_asset_and_recovers(self):
        self.rule.update(node="*", metric="offline", threshold=0, recovery=0, duration=60)
        nodes = {"local": self.node(0), "remote-1": {"name": "Remote", "online": False, "error": "fixture"}}
        tinywatch._evaluate_alerts(nodes, self.now)
        tinywatch._evaluate_alerts(nodes, self.now + 60)
        incident = self.store.data["incidents"][0]
        self.assertEqual(incident["node"], "remote-1")
        nodes["remote-1"]["online"] = True
        tinywatch._evaluate_alerts(nodes, self.now + 120)
        self.assertEqual(incident["status"], "resolved")

    def test_removed_asset_closes_incident_and_removes_targeted_rules(self):
        self.store.data["assets"] = [{"id": "remote-1", "name": "Remote", "url": "http://node:8765", "password": "token"}]
        self.rule.update(node="remote-1", metric="offline", threshold=0, recovery=0, duration=0)
        tinywatch._evaluate_alerts({"remote-1": {"online": False}}, self.now)
        handler = object.__new__(tinywatch.TinyWatchHandler)
        handler._save_config({"assets": [], "widgets": []})
        self.assertEqual(self.store.data["incidents"][0]["resolution_reason"], "asset_removed")
        self.assertEqual(self.store.data["alert_rules"], [])
        self.assertEqual(self.store.data["alert_states"], {})

    def test_retention_prunes_closed_incidents_but_keeps_open_ones(self):
        cutoff = self.now - 86400
        self.store.data["incidents"] = [
            {"status": "active", "resolved_at": None, "triggered_at": cutoff - 100},
            {"status": "resolved", "resolved_at": cutoff - 1},
            {"status": "resolved", "resolved_at": self.now}]
        tinywatch._prune_history_database(self.store.data, cutoff)
        self.assertEqual(len(self.store.data["incidents"]), 2)
        self.assertEqual(self.store.data["incidents"][0]["status"], "active")

    def test_incident_capacity_evicts_closed_incidents_and_preserves_active(self):
        self.rule["duration"] = 0
        self.evaluate(95, 0)
        active_id = self.store.data["incidents"][0]["id"]
        self.store.data["incidents"].extend({"id": "closed-" + str(index), "status": "resolved",
                                             "triggered_at": self.now + index}
                                            for index in range(tinywatch.MAX_INCIDENTS + 10))
        self.evaluate(95, 60)
        self.assertEqual(len(self.store.data["incidents"]), tinywatch.MAX_INCIDENTS)
        self.assertTrue(any(item["id"] == active_id for item in self.store.data["incidents"]))


class HistoryCompactionTests(unittest.TestCase):
    def test_compaction_preserves_peaks_real_gaps_and_is_idempotent(self):
        now = int(time.time())
        base = (now - 2 * 86400) // 300 * 300
        points = [[base + index * 60, 99 if index == 5 else 12]
                  for index in range(30) if not 8 <= index < 12]
        data = {"history": {"local": {"cpu": points}}}
        self.assertTrue(tinywatch._compact_history_database(data, now))
        compacted = data["history"]["local"]["cpu"]
        self.assertLess(len(compacted), len(points))
        self.assertTrue(any(point[0] == base + 5 * 60 and point[1] == 99 for point in compacted))
        gaps = [point[0] for point in compacted if tinywatch._point_metadata(point).get("gap_before")]
        self.assertEqual(gaps, [base + 12 * 60])
        self.assertFalse(tinywatch._compact_history_database(data, now))

    def test_recent_samples_keep_fractional_precision_and_resolution(self):
        now = int(time.time())
        points = [[now - 120, 12.25], [now - 60, 13.75]]
        data = {"history": {"local": {"cpu": copy.deepcopy(points)}}}
        self.assertFalse(tinywatch._compact_history_database(data, now))
        self.assertEqual(data["history"]["local"]["cpu"], points)

    def test_hourly_network_compaction_preserves_each_interface_extreme(self):
        now = int(time.time())
        base = (now - 8 * 86400) // 3600 * 3600
        points = [[base + index * 60, {"eth0": [99 if index == 10 else 1, 0],
                                     "eth1": [1 if index == 10 else 99, 0]}] for index in range(60)]
        data = {"history": {"local": {"network": points}}}
        tinywatch._compact_history_database(data, now)
        compacted = data["history"]["local"]["network"]
        self.assertLessEqual(len(compacted), 6)
        self.assertTrue(any(point[1]["eth0"][0] == 99 for point in compacted))
        self.assertTrue(any(point[1]["eth1"][0] == 99 for point in compacted))
        self.assertTrue(all(tinywatch._point_metadata(point)["resolution"] == 3600 for point in compacted))

    def test_history_response_preserves_only_real_gap_markers(self):
        with tempfile.TemporaryDirectory(prefix="tinywatch-history-response-") as directory:
            store = tinywatch.JsonStore(Path(directory) / "data.json")
            now = int(time.time())
            base = (now - 2 * 86400) // 300 * 300
            store.data["history"] = {"local": {"cpu": [[base + i * 60, i % 7]
                                                       for i in range(100) if not 20 <= i < 30]}}
            tinywatch._compact_history_database(store.data, now)
            with patch.object(tinywatch, "STORE", store):
                response = tinywatch._history_response("local", "cpu", "3d")
            self.assertEqual(len(response["points"]), len(response["gaps"]))
            self.assertEqual(sum(response["gaps"]), 1)
            gap = response["gaps"].index(True)
            self.assertEqual(response["points"][gap][0], base + 30 * 60)
            self.assertTrue(all(len(point) == 2 for point in response["points"]))

    def test_large_history_response_is_bounded_and_preserves_peak_and_gap(self):
        rows = [[index * 60, 100 if index == 2345 else 12] for index in range(5000)]
        gaps = [index == 3478 for index in range(5000)]
        limited, flags = tinywatch._limit_history_points(rows, gaps, "cpu")
        self.assertLessEqual(len(limited), 1200)
        self.assertIn([2345 * 60, 100], limited)
        self.assertEqual(sum(flags), 1)
        self.assertEqual(limited[flags.index(True)][0], 3478 * 60)

    def test_interface_absence_is_a_gap_instead_of_zero_bandwidth(self):
        with tempfile.TemporaryDirectory(prefix="tinywatch-interface-gap-") as directory:
            store = tinywatch.JsonStore(Path(directory) / "data.json")
            now = int(time.time())
            store.data["history"] = {"local": {"network": [
                [now - 180, {"eth0": [10, 20]}], [now - 120, {"eth1": [30, 40]}],
                [now - 60, {"eth0": [50, 60]}]]}}
            with patch.object(tinywatch, "STORE", store):
                response = tinywatch._history_response("local", "network", "1h", "eth0")
            self.assertEqual(response["points"], [[now - 180, 10, 20], [now - 60, 50, 60]])
            self.assertEqual(response["gaps"], [False, True])

    def test_minute_sampling_keeps_fractional_load_and_cpu(self):
        with tempfile.TemporaryDirectory(prefix="tinywatch-precision-") as directory:
            store = tinywatch.JsonStore(Path(directory) / "data.json")
            store.data["alert_rules"] = []
            node = {"online": True, "metrics": {"cpu": {"percent": 12.75}, "load": [0.25, 1.5, 2.75]}}
            with patch.object(tinywatch, "STORE", store), patch.object(tinywatch, "HISTORY_LAST_WRITE", 0):
                tinywatch._record_history({"local": node}, now=int(time.time()))
            self.assertEqual(store.data["history"]["local"]["cpu"][0][1], 12.75)
            self.assertEqual(store.data["history"]["local"]["load"][0][1:], [0.25, 1.5, 2.75])


class MonitoringApiTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="tinywatch-api-tests-")
        self.addCleanup(directory.cleanup)
        store_patch = patch.object(tinywatch, "STORE", tinywatch.JsonStore(Path(directory.name) / "data.json"))
        store_patch.start()
        self.addCleanup(store_patch.stop)

    def test_rule_configuration_and_incident_acknowledgement_through_handler(self):
        with tempfile.TemporaryDirectory(prefix="tinywatch-alert-api-") as directory:
            store = tinywatch.JsonStore(Path(directory) / "data.json")
            response = []
            handler = object.__new__(tinywatch.TinyWatchHandler)
            handler.path = "/api/alerts"
            handler._json = lambda status, value, headers=None: response.append((status, value))
            rule = {"id": "offline", "name": "Unavailable", "node": "local", "metric": "offline",
                    "mode": "threshold", "threshold": 0, "recovery": 0, "duration": 0,
                    "cooldown": 300, "enabled": True}
            handler._read_json = lambda: {"action": "save_rules", "rules": [rule]}
            with patch.object(tinywatch, "STORE", store), \
                    patch.object(tinywatch, "_session_from_request", return_value=True):
                handler.do_POST()
                self.assertEqual(response[-1][0], tinywatch.HTTPStatus.OK)
                self.assertEqual(response[-1][1]["rules"][0]["id"], "offline")
                tinywatch._evaluate_alerts({"local": {"online": False}}, time.time())
                handler.do_GET()
                incident_id = response[-1][1]["incidents"][0]["id"]
                self.assertEqual(response[-1][1]["active_count"], 1)
                handler._read_json = lambda: {"action": "ack", "id": incident_id}
                handler.do_POST()
                self.assertEqual(response[-1][1]["unacknowledged_count"], 0)
                handler._read_json = lambda: {"action": "save_rules", "rules": [dict(rule, threshold=-1)]}
                handler.do_POST()
                self.assertEqual(response[-1][0], tinywatch.HTTPStatus.BAD_REQUEST)
                self.assertEqual(store.data["alert_rules"][0]["threshold"], 0)
                handler._read_json = lambda: {"action": "ack", "id": "missing"}
                handler.do_POST()
                self.assertEqual(response[-1][0], tinywatch.HTTPStatus.NOT_FOUND)

    def test_alert_response_is_a_snapshot_not_a_mutable_store_reference(self):
        with tempfile.TemporaryDirectory(prefix="tinywatch-alert-response-") as directory:
            store = tinywatch.JsonStore(Path(directory) / "data.json")
            with patch.object(tinywatch, "STORE", store):
                response = tinywatch._alerts_response()
            response["rules"][0]["enabled"] = False
            self.assertTrue(store.data["alert_rules"][0]["enabled"])

    def test_diagnostics_distinguish_offline_stale_partial_and_healthy(self):
        now = int(time.time())
        metrics = {"sampled_at": tinywatch.datetime.fromtimestamp(now, tinywatch.timezone.utc).isoformat(),
                   "cpu": {"available": True}, "memory": {"supported": True},
                   "disk": {"supported": True}, "network": {"supported": True}, "load": [0.1]}
        stale = dict(metrics, sampled_at=tinywatch.datetime.fromtimestamp(now - 121, tinywatch.timezone.utc).isoformat())
        partial = dict(metrics, collector_errors={"memory": "fixture denied"})
        report = tinywatch._diagnostics_response({"nodes": {
            "ok": {"online": True, "metrics": metrics},
            "old": {"online": True, "metrics": stale},
            "partial": {"online": True, "metrics": partial},
            "off": {"online": False, "error": "fixture offline"}}}, now=now)
        self.assertEqual([node["status"] for node in report["nodes"]], ["healthy", "stale", "partial", "connection_failed"])
        self.assertEqual(report["nodes"][2]["issues"][0]["message"], "fixture denied")

    def test_missing_timestamp_and_future_node_clock_are_reported(self):
        now = int(time.time())
        future = tinywatch.datetime.fromtimestamp(now + 300, tinywatch.timezone.utc).isoformat()
        report = tinywatch._diagnostics_response({"nodes": {
            "unknown": {"online": True, "metrics": {}},
            "future": {"online": True, "metrics": {"sampled_at": future}}}}, now=now)
        self.assertEqual(report["nodes"][0]["status"], "stale")
        self.assertTrue(any(issue["kind"] == "clock_skew" for issue in report["nodes"][1]["issues"]))

    def test_new_endpoints_require_login_without_opening_any_network_socket(self):
        for path, method in (("/api/alerts", "GET"), ("/api/diagnostics", "GET"), ("/api/alerts", "POST")):
            with self.subTest(path=path, method=method):
                response = []
                handler = object.__new__(tinywatch.TinyWatchHandler)
                handler.path = path
                handler._json = lambda status, value, headers=None: response.append((status, value))
                handler._read_json = lambda: {"action": "ack", "id": "missing"}
                with patch.object(tinywatch, "_session_from_request", return_value=False), \
                        patch.object(tinywatch, "collect_cluster_snapshot") as collect:
                    (handler.do_GET if method == "GET" else handler.do_POST)()
                self.assertEqual(response[-1][0], tinywatch.HTTPStatus.UNAUTHORIZED)
                collect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
