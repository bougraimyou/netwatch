"""The dashboard server.

Four routes and no framework, so the test can simply start it on an ephemeral
port and talk to it over HTTP the way the browser does.
"""

from __future__ import annotations

import json
import unittest
import urllib.error
import urllib.request

from helpers import report_for
from netwatch.serve import serve_in_thread


class TestDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = report_for("mixed")
        cls.server, cls.thread, cls.url = serve_in_thread(cls.report, host="127.0.0.1", port=0)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def get(self, path: str):
        return urllib.request.urlopen(self.url.rstrip("/") + path, timeout=5)

    def test_index_is_html(self):
        response = self.get("/")
        self.assertEqual(response.status, 200)
        self.assertIn("text/html", response.headers["Content-Type"])
        self.assertIn(b"NetWatch", response.read())

    def test_static_assets(self):
        css = self.get("/style.css")
        self.assertIn(b"--accent", css.read())
        script = self.get("/app.js")
        self.assertIn(b"__NETWATCH_REPORT__", script.read())

    def test_report_api(self):
        response = self.get("/api/report")
        payload = json.loads(response.read())
        self.assertEqual(payload["alert_count"], self.report["alert_count"])

    def test_report_json_alias(self):
        # The static dashboard fetches report.json; the server answers the same
        # document at that path so the page needs no special case.
        payload = json.loads(self.get("/report.json").read())
        self.assertEqual(payload["capture"]["name"], self.report["capture"]["name"])

    def test_health(self):
        payload = json.loads(self.get("/health").read())
        self.assertEqual(payload, {"status": "ok"})

    def test_unknown_path_is_404_json(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.get("/nope")
        self.assertEqual(caught.exception.code, 404)
        payload = json.loads(caught.exception.read())
        self.assertEqual(payload["error"], "not found")

    def test_head_returns_headers_without_a_body(self):
        request = urllib.request.Request(self.url.rstrip("/") + "/api/report", method="HEAD")
        response = urllib.request.urlopen(request, timeout=5)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"")


if __name__ == "__main__":
    unittest.main()
