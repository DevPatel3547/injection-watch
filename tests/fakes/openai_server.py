"""A real HTTP server speaking the OpenAI-compatible ``/v1/chat/completions`` format (what Ollama, llama.cpp
server, vLLM and LM Studio expose). Scripted steps reproduce 429/503 with ``retry-after``, slow answers and
malformed output."""
from __future__ import annotations

import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .anthropic_server import _SNIPPET_RE, toy_classify


class FakeOpenAI:
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.script: list[Any] = []
        self.requests: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a: Any) -> None:
                pass

            def handle(self) -> None:
                try:
                    super().handle()
                except (BrokenPipeError, ConnectionResetError):  # client gave up (timeout tests)
                    pass

            def _send(self, status: int, body: Any, headers: dict[str, str] | None = None) -> None:
                data = (body if isinstance(body, str) else json.dumps(body)).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                with fake.lock:
                    step = fake.script.pop(0) if fake.script else "ok"
                    fake.requests.append({"t": time.monotonic(), "body": body, "step": step,
                                          "headers": {k.lower(): v for k, v in self.headers.items()}})
                if self.path.rstrip("/") != "/v1/chat/completions":
                    self._send(404, {"error": {"message": "not found", "type": "invalid_request_error"}})
                    return
                if isinstance(step, dict):
                    if step.get("delay"):
                        time.sleep(float(step["delay"]))
                    if step.get("status"):
                        h = {"retry-after": str(step["retry_after"])} if step.get("retry_after") is not None else {}
                        self._send(int(step["status"]), {"error": {"message": "scripted error",
                                                                   "type": step.get("type", "server_error")}}, h)
                        return
                    if step.get("content") is not None:
                        content = step["content"]
                    else:
                        content = None
                else:
                    content = None
                if content is None:
                    user = body["messages"][-1]["content"]
                    m = _SNIPPET_RE.search(user)
                    content = json.dumps(toy_classify(m.group(1) if m else user))
                self._send(200, {"id": f"chatcmpl-fake-{uuid.uuid4().hex[:12]}", "object": "chat.completion",
                                 "created": int(time.time()), "model": body.get("model", "fake"),
                                 "choices": [{"index": 0, "finish_reason": "stop",
                                              "message": {"role": "assistant", "content": content}}],
                                 "usage": {"prompt_tokens": 100, "completion_tokens": 30, "total_tokens": 130}})

        self.httpd = ThreadingHTTPServer((host, port), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.base_url = f"http://{host}:{self.port}/v1"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self) -> FakeOpenAI:
        self.thread.start()
        return self

    def __exit__(self, *a: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
