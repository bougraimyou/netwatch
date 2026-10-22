"""Live dashboard.

A small HTTP server on the standard library. It serves the same static assets
as the standalone report and exposes the report as JSON, so the page behaves
identically whether you opened a file, the demo site, or this server.

Deliberately not a framework: the whole surface is four routes, and pulling in
FastAPI for four routes would mean the tool cannot run on a machine with no
package index access.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .render import read_asset

__all__ = ["serve", "serve_in_thread", "make_handler"]


def make_handler(report: dict[str, Any]) -> type[BaseHTTPRequestHandler]:
    """Build a request handler bound to one report document."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "NetWatch"
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            # Quiet by default: the CLI prints its own line, and a dashboard
            # should not fill a terminal with one line per asset request.
            return

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, payload: Any, status: int = 200) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8")

        def do_HEAD(self) -> None:  # noqa: N802
            self.do_GET()

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                self._send(200, read_asset("index.html").encode("utf-8"), "text/html; charset=utf-8")
            elif path == "/style.css":
                self._send(200, read_asset("style.css").encode("utf-8"), "text/css; charset=utf-8")
            elif path == "/app.js":
                self._send(200, read_asset("app.js").encode("utf-8"), "application/javascript; charset=utf-8")
            elif path in ("/api/report", "/report.json"):
                self._json(report)
            elif path == "/health":
                self._json({"status": "ok"})
            else:
                self._json({"error": "not found", "path": path}, 404)

    return Handler


def serve(report: dict[str, Any], host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    """Create (but do not start) a server for a report."""
    server = ThreadingHTTPServer((host, port), make_handler(report))
    server.daemon_threads = True
    return server


def serve_in_thread(report: dict[str, Any], host: str = "127.0.0.1", port: int = 0) -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    """Start a server on a background thread. Returns (server, thread, url)."""
    server = serve(report, host=host, port=port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    bound_host, bound_port = server.server_address[:2]
    return server, thread, f"http://{bound_host}:{bound_port}/"
