import importlib.util
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.core import DEFAULT_CONFIG, load_config, validate_config

SPEC = importlib.util.spec_from_file_location("runner_billing", Path(__file__).parents[1] / "runner/glacier-runner.py")
runner = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(runner)


class SigV4Tests(unittest.TestCase):
    def test_matches_published_aws_get_vanilla_vector(self):
        auth = runner.sign_v4("GET", "/", "", {"Host": "example.amazonaws.com", "X-Amz-Date": "20150830T123600Z"}, b"",
                              "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "service", "20150830T123600Z")
        self.assertIn("Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31", auth)
        self.assertIn("SignedHeaders=host;x-amz-date", auth)


class StorageSizeTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(); self.data = Path(self.td.name)
        (self.data / "config.json").write_text(json.dumps(DEFAULT_CONFIG))

    def tearDown(self): self.td.cleanup()

    def test_size_is_measured_read_only_and_cached(self):
        completed = SimpleNamespace(returncode=0, stdout=json.dumps({"count": 42, "bytes": 123456789, "sizeless": 0}), stderr="")
        with patch.object(runner.subprocess, "run", return_value=completed) as run:
            result = runner.size_s3(self.data, "rclone")
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["rclone", "size", "--json"])
        for forbidden in ("delete", "purge", "sync", "move"):
            self.assertNotIn(forbidden, command)
        self.assertEqual((result["bytes"], result["count"]), (123456789, 42))
        self.assertEqual(json.loads((self.data / "s3-size.json").read_text())["bytes"], 123456789)

    def test_size_failure_is_reported_without_caching(self):
        completed = SimpleNamespace(returncode=1, stdout="", stderr="AccessDenied token=SECRET123")
        with patch.object(runner.subprocess, "run", return_value=completed):
            with self.assertRaises(ValueError) as caught:
                runner.size_s3(self.data, "rclone")
        self.assertNotIn("SECRET123", str(caught.exception))
        self.assertFalse((self.data / "s3-size.json").exists())


class BillingTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(); self.data = Path(self.td.name)
        self.creds = self.data / "aws-billing.json"
        self.creds.write_text(json.dumps({"access_key_id": "AKIAEXAMPLEEXAMPLE", "secret_access_key": "x" * 40})); os.chmod(self.creds, 0o600)
        self.patcher = patch.object(runner, "BILLING_CREDENTIALS", str(self.creds)); self.patcher.start()

    def tearDown(self): self.patcher.stop(); self.td.cleanup()

    def test_refresh_reads_months_and_caches(self):
        reply = {"ResultsByTime": [
            {"TimePeriod": {"Start": "2026-10-01", "End": "2026-11-01"}, "Total": {"UnblendedCost": {"Amount": "1.2345", "Unit": "USD"}}, "Estimated": False},
            {"TimePeriod": {"Start": "2026-11-01", "End": "2026-11-15"}, "Total": {"UnblendedCost": {"Amount": "0.5", "Unit": "USD"}}, "Estimated": True}]}
        with patch.object(runner, "post_cost_explorer", return_value=reply) as post:
            result = runner.refresh_billing(self.data, datetime(2026, 11, 14, 1, 0, tzinfo=timezone.utc))
        self.assertEqual(result["last_month"]["amount"], 1.23)
        self.assertEqual(result["this_month"], {"amount": 0.5, "unit": "USD", "estimated": True})
        body = json.loads(post.call_args.args[0]); headers = post.call_args.args[1]
        self.assertEqual(body["TimePeriod"], {"Start": "2026-10-01", "End": "2026-11-15"})
        self.assertTrue(headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLEEXAMPLE/20261114/us-east-1/ce/"))
        self.assertNotIn("x" * 40, json.dumps(headers))  # the secret key is never sent, only the signature
        self.assertTrue((self.data / "billing.json").exists())

    def test_credentials_must_be_private(self):
        os.chmod(self.creds, 0o644)
        with self.assertRaises(ValueError) as caught: runner.read_billing_credentials()
        self.assertIn("chmod 600", str(caught.exception))

    def test_missing_credentials_give_setup_hint(self):
        self.creds.unlink()
        with self.assertRaises(ValueError) as caught: runner.read_billing_credentials()
        self.assertIn("not configured", str(caught.exception))


class CostConfigTests(unittest.TestCase):
    def test_old_configs_get_default_cost_settings(self):
        with tempfile.TemporaryDirectory() as td:
            old = json.loads(json.dumps(DEFAULT_CONFIG)); old.pop("cost")
            (Path(td) / "config.json").write_text(json.dumps(old))
            self.assertEqual(load_config(Path(td))["cost"]["usd_per_gb_month"], 0.00099)

    def test_invalid_rates_rejected(self):
        for rate in (0, -1, 2, "1", True):
            config = json.loads(json.dumps(DEFAULT_CONFIG)); config["cost"]["usd_per_gb_month"] = rate
            with self.assertRaises(ValueError, msg=repr(rate)): validate_config(config)


class IndexCatchUpTests(unittest.TestCase):
    NOW = 1_000_000.0

    def test_brief_gap_keeps_index_without_catch_up(self):
        self.assertEqual(runner.index_action(self.NOW - 60, self.NOW)[0], "keep")

    def test_hours_long_gap_catches_up_instead_of_rebuilding(self):
        self.assertEqual(runner.index_action(self.NOW - 5 * 3600, self.NOW)[0], "catchup")

    def test_very_long_gap_rebuilds(self):
        self.assertEqual(runner.index_action(self.NOW - 40 * 86400, self.NOW)[0], "rebuild")

    def test_catch_up_reads_only_folders_touched_since_the_runner_left(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "src"); (root / "touched").mkdir(parents=True); (root / "quiet").mkdir()
            (root / "touched" / "new.txt").write_text("x")
            (root / "quiet" / "unrelated.txt").write_text("y")
            old = self.NOW_OLD = os.stat(root).st_mtime - 3600
            os.utime(root / "quiet", (old, old)); os.utime(root, (old, old))
            data = Path(tmp, "data"); data.mkdir()
            index = runner.ChangeIndex(data)
            mapping = {"id": "m1", "source": str(root)}
            with patch.object(runner, "validate_source", lambda p: p), patch.object(runner, "wait_for_safe_temperature", lambda *a: None):
                index.catch_up(mapping, {}, since=old + 60)
            found = {row[0] for row in index.db.execute("SELECT relative FROM changes WHERE mapping_id='m1'")}
            self.assertEqual(found, {"touched/new.txt"})
            self.assertEqual(len(index.db.execute("SELECT path FROM directories WHERE mapping_id='m1'").fetchall()), 3)


class UploadFlagTests(unittest.TestCase):
    def test_timestamp_only_differences_do_not_force_reuploads(self):
        with patch.object(runner, "validate_source", lambda p: p), patch.object(runner, "validate_prefix", lambda p: p):
            command = runner.build_command({"source": "/volume3/Alice", "destination": "Alice"}, json.loads(json.dumps(DEFAULT_CONFIG)), False, "/tmp/list", "rclone")
        self.assertIn("--no-update-modtime", command)


class FullScanIntervalTests(unittest.TestCase):
    def _index(self, reconciled_ago):
        import sqlite3, threading
        index = object.__new__(runner.ChangeIndex); index.lock = threading.RLock(); index.unwatched = set()
        index.db = sqlite3.connect(":memory:")
        index.db.execute("CREATE TABLE mappings (id TEXT PRIMARY KEY, signature TEXT, initialized INTEGER, reconciled_at REAL)")
        mapping = {"id": "m1", "source": "/volume3/Test", "exclusions": []}
        config = json.loads(json.dumps(DEFAULT_CONFIG))
        index.db.execute("INSERT INTO mappings VALUES('m1',?,1,?)", (index.signature(mapping, config), runner.time.time() - reconciled_ago))
        return index, mapping, config

    def test_due_full_scan_rebuilds_the_index(self):
        index, mapping, config = self._index(8 * 86400); config["schedule"]["full_scan_days"] = 7
        with patch.object(index, "baseline", return_value=("list", 1)) as baseline:
            index.ensure_mapping(mapping, config)
        baseline.assert_called_once()

    def test_not_yet_due_or_off_does_not_rebuild(self):
        for days, ago in ((7, 3 * 86400), (0, 90 * 86400)):
            index, mapping, config = self._index(ago); config["schedule"]["full_scan_days"] = days
            with patch.object(index, "baseline") as baseline, patch.object(index, "candidates", return_value=("l", 0)):
                index.ensure_mapping(mapping, config)
            baseline.assert_not_called()

    def test_interval_must_be_a_known_choice(self):
        config = json.loads(json.dumps(DEFAULT_CONFIG)); config["schedule"]["full_scan_days"] = 5
        with self.assertRaises(ValueError): validate_config(config)
        for ok in (0, 1, 7, 30):
            config["schedule"]["full_scan_days"] = ok; validate_config(config)


if __name__ == "__main__":
    unittest.main()
