import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


def load_fixture(name: str) -> str:
    return (FIXTURES / "pages" / name).read_text("utf-8")


@pytest.fixture(scope="session")
def labels():
    return json.loads((FIXTURES / "labels.json").read_text("utf-8"))


class LocalSite:
    """Tiny local HTTP server. routes: path -> callable(handler) -> (status, headers, body)."""

    def __init__(self):
        self.routes = {}
        self.requests = []  # (path, user-agent, time)
        site = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                import time

                site.requests.append((self.path, self.headers.get("User-Agent", ""), time.monotonic()))
                fn = site.routes.get(self.path.split("?")[0])
                if fn is None:
                    status, headers, body = 404, {"Content-Type": "text/plain"}, "not found"
                else:
                    status, headers, body = fn(self)
                data = body.encode("utf-8")
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def html(self, path, body, status=200, headers=None):
        h = {"Content-Type": "text/html; charset=utf-8", **(headers or {})}
        self.routes[path] = lambda req: (status, h, body)

    def close(self):
        self.httpd.shutdown()


@pytest.fixture
def site():
    s = LocalSite()
    yield s
    s.close()


@pytest.fixture(autouse=True)
def _no_proxy_for_localhost(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
