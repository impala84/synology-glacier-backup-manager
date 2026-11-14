import http.client
import importlib
import importlib.util
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from datetime import datetime
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

_TMP = tempfile.TemporaryDirectory()
os.environ.update({
    "GBM_DATA_DIR": _TMP.name, "GBM_BUCKET": "test-bucket", "GBM_BROWSE_ROOTS": "/volume1:/volume3",
    "GBM_SOURCE_MOUNTS": "/volume1=/sources/volume1,/volume3=/sources/volume3", "GBM_UPDATE_CHECK": "false",
})
from app import core, server  # noqa: E402

SPEC = importlib.util.spec_from_file_location("runner_parity", Path(__file__).parents[1] / "runner/glacier-runner.py")
runner = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(runner)

PASSWORD = "Correct-Horse-42!"


class Client:
    def __init__(self, port):
        self.port, self.cookie, self.csrf = port, "", ""

    def request(self, method, path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Content-Type": "application/json"}
        if self.cookie: headers["Cookie"] = self.cookie
        if self.csrf: headers["X-CSRF-Token"] = self.csrf
        # http.client sends the path verbatim, so '/../' sequences reach the handler unmodified.
        connection.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        cookie = response.getheader("Set-Cookie")
        if cookie: self.cookie = cookie.split(";", 1)[0]
        connection.close()
        return response, raw


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.port = cls.httpd.server_address[1]
        cls.admin = Client(cls.port)
        response, raw = cls.admin.request("POST", "/api/auth/setup", {"username": "archive-admin", "password": PASSWORD})
        assert response.status == 201, raw
        cls.admin.csrf = json.loads(raw)["csrf"]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close()

    def test_static_path_traversal_is_blocked(self):
        anonymous = Client(self.port)
        for path in ("/../server.py", "/../../app/server.py", "/../../../../../../etc/passwd",
                     "/static/../../auth.json", "/%2e%2e/server.py"):
            response, raw = anonymous.request("GET", path)
            self.assertEqual(response.status, 404, path)
            self.assertNotIn(b"import json", raw, path)

    def test_static_files_still_served_with_security_headers(self):
        response, raw = Client(self.port).request("GET", "/app.js")
        self.assertEqual(response.status, 200)
        self.assertIn("script-src 'self'", response.getheader("Content-Security-Policy"))
        self.assertEqual(response.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")

    def test_state_exposes_server_clock_for_schedule_view(self):
        response, raw = self.admin.request("GET", "/api/state")
        self.assertEqual(response.status, 200)
        status = json.loads(raw)["schedule_status"]
        self.assertRegex(status["now"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")

    def test_api_requires_authentication(self):
        response, _ = Client(self.port).request("GET", "/api/state")
        self.assertEqual(response.status, 401)

    def test_state_changes_require_csrf_token(self):
        forged = Client(self.port); forged.cookie = self.admin.cookie
        response, _ = forged.request("POST", "/api/mappings/replace", {"mappings": []})
        self.assertEqual(response.status, 403)

    def test_mapping_sources_must_be_safe_and_inside_browse_roots(self):
        for source in ("/volume1/@rclone", "/volume1/@appstore/x", "/volume1/../etc", "/etc",
                       "/volume1/docker/synology-glacier-backup-manager/data", "/volume9/Other", "/volume1"):
            response, _ = self.admin.request("POST", "/api/mappings/replace",
                                             {"mappings": [{"source": source, "destination": "x"}]})
            self.assertEqual(response.status, 400, source)

    def test_valid_mapping_is_accepted(self):
        response, raw = self.admin.request("POST", "/api/mappings/replace",
                                           {"mappings": [{"source": "/volume3/Music", "destination": "Music"}]})
        self.assertEqual(response.status, 200, raw)

    def test_unexpected_errors_do_not_leak_internals(self):
        with patch.object(server, "state", side_effect=RuntimeError("secret internal detail")):
            response, raw = self.admin.request("GET", "/api/state")
        self.assertEqual(response.status, 500)
        self.assertNotIn(b"secret internal detail", raw)

    def test_invalid_content_length_is_rejected(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.putrequest("POST", "/api/auth/login"); connection.putheader("Content-Length", "-5")
        connection.endheaders()
        self.assertEqual(connection.getresponse().status, 400)
        connection.close()


class ValidationParityTests(unittest.TestCase):
    CASES = ["/volume1/Music", "/volume3/a/b", "/volume1", "/volume1/", "/volume1/../etc", "/etc", "/volume1x/foo",
             "/volume12/ok", "//volume1/x", "/volume1/@rclone", "/volume1/#recycle", "/volume1/@appstore/a",
             "/volume1/docker/synology-glacier-backup-manager/data", "volume1/x", "/volume1/a/../../etc", "/volume1/x\x00y"]

    def test_web_and_runner_validators_agree(self):
        for case in self.CASES:
            try: web = core.validate_source(case)
            except ValueError: web = "REJECT"
            try: host = runner.validate_source(case)
            except ValueError: host = "REJECT"
            self.assertEqual(web, host, case)

    def test_dangerous_sources_are_rejected(self):
        for case in ("/volume1/../etc", "/etc", "/volume1x/foo", "/volume1/@rclone", "/volume1", "//volume1/x"):
            with self.assertRaises(ValueError, msg=case): core.validate_source(case)


class ScheduleTests(unittest.TestCase):
    def test_due_only_once_per_day_with_catch_up_grace(self):
        at = lambda h, m: datetime(2026, 11, 14, h, m)
        self.assertFalse(server.schedule_due(at(1, 59), "02:00", None))
        self.assertTrue(server.schedule_due(at(2, 0), "02:00", None))
        self.assertTrue(server.schedule_due(at(4, 30), "02:00", "2026-11-13"))   # missed minute, caught up
        self.assertFalse(server.schedule_due(at(4, 30), "02:00", "2026-11-14"))  # already ran today
        self.assertFalse(server.schedule_due(at(9, 0), "02:00", None))           # grace expired


class IndexWindowTests(unittest.TestCase):
    def test_unuploaded_changes_outlive_the_modification_window(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / "late.bin").write_bytes(b"x")
            index = object.__new__(runner.ChangeIndex); index.lock = runner.threading.RLock()
            index.db = sqlite3.connect(":memory:")
            index.db.execute("CREATE TABLE changes (mapping_id TEXT, relative TEXT, mtime REAL, size INTEGER, observed_at REAL, PRIMARY KEY(mapping_id,relative))")
            ten_days_ago = time.time() - 10 * 86400
            index.db.execute("INSERT INTO changes VALUES(?,?,?,?,?)", ("m1", "late.bin", ten_days_ago, 1, ten_days_ago)); index.db.commit()
            cfg = json.loads(json.dumps(core.DEFAULT_CONFIG))  # window is 48 hours
            filename, count = index.candidates({"id": "m1", "source": str(root), "exclusions": []}, cfg)
            try:
                self.assertEqual(count, 1)
            finally:
                os.unlink(filename)


if __name__ == "__main__":
    unittest.main()
