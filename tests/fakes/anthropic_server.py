"""A real HTTP server speaking the Anthropic Messages API wire format, for testing the live path offline.

Implements ``POST /v1/messages`` (JSON and SSE streaming, tool_use blocks, error envelopes) and
``GET /v1/models``. Scripted behaviour per request lets tests reproduce 429 / 529 with ``retry-after``,
4xx errors, slow responses (timeouts) and mid-stream ``error`` events.

    with FakeAnthropic() as fake:
        fake.script = [{"status": 429, "retry_after": "1"}, "ok"]
        client = anthropic.Anthropic(api_key="test-key-for-fake-server", base_url=fake.base_url)

Run standalone (used by ``scripts/demo_live.py --fake``):  python -m tests.fakes.anthropic_server --port 0
"""
from __future__ import annotations

import argparse
import json
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

ERROR_TYPES = {400: "invalid_request_error", 401: "authentication_error", 403: "permission_error",
               404: "not_found_error", 413: "request_too_large", 429: "rate_limit_error", 500: "api_error",
               504: "timeout_error", 529: "overloaded_error"}
_SNIPPET_RE = re.compile(r"<untrusted_snippet>\n?(.*?)\n?</untrusted_snippet>", re.S)


def toy_classify(snippet: str) -> dict[str, Any]:
    """Deterministic keyword stand-in for a model. Not a classifier anyone should use."""
    t = snippet.lower()
    if any(w in t for w in ("send", "email", "exfiltrat", "api key", "password", "credentials")):
        return {"category": "data_exfiltration", "intent": "malicious", "target": "agents", "confidence": 0.92,
                "rationale": "asks the agent to send user data elsewhere"}
    if any(w in t for w in ("ignore", "previous instructions", "disregard", "stale", "earlier guidance")):
        return {"category": "instruction_override", "intent": "malicious", "target": "agents", "confidence": 0.9,
                "rationale": "tries to override the agent's instructions"}
    if "recommend" in t or "best" in t:
        return {"category": "recommendation_manipulation", "intent": "manipulative", "target": "summarizers",
                "confidence": 0.8, "rationale": "steers recommendations"}
    return {"category": "other", "intent": "benign", "target": "agents", "confidence": 0.7,
            "rationale": "ordinary page text"}


class FakeAnthropic:
    def __init__(self, host: str = "127.0.0.1", port: int = 0, valid_keys: tuple[str, ...] | None = None):
        self.script: list[Any] = []          # consumed one per POST /v1/messages; then "ok"
        # Opt-in: answer forced tool_choice (any/tool) with a 400 invalid_request_error that names tool_choice,
        # to exercise the classifier's switch to auto. Not a claim about which real models do this.
        self.reject_forced_tool = False
        self.requests: list[dict[str, Any]] = []
        self.valid_keys = valid_keys          # None: any non-empty key is accepted
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

            def _send(self, status: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("request-id", f"req_fake_{uuid.uuid4().hex[:16]}")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _error(self, status: int, message: str, etype: str | None = None,
                       headers: dict[str, str] | None = None) -> None:
                self._send(status, {"type": "error", "error": {"type": etype or ERROR_TYPES.get(status, "api_error"),
                                                               "message": message},
                                    "request_id": f"req_fake_{uuid.uuid4().hex[:16]}"}, headers)

            def _auth_ok(self) -> bool:
                # SDKs send either x-api-key or (newer releases) Authorization: Bearer <key>
                auth = self.headers.get("authorization", "")
                key = self.headers.get("x-api-key", "") or (auth[7:] if auth.lower().startswith("bearer ") else "")
                if not key or (fake.valid_keys is not None and key not in fake.valid_keys):
                    self._error(401, "invalid x-api-key")  # same wording as the real API
                    return False
                if not self.headers.get("anthropic-version"):
                    self._error(400, "anthropic-version header is required")
                    return False
                return True

            def do_GET(self) -> None:
                if self.path.split("?")[0] != "/v1/models":
                    self._error(404, f"Not found: {self.path}")
                    return
                if not self._auth_ok():
                    return
                self._send(200, {"data": [{"type": "model", "id": "claude-haiku-5-5", "display_name": "fake",
                                           "created_at": "2026-01-01T00:00:00Z"}],
                                 "has_more": False, "first_id": "claude-haiku-5-5", "last_id": "claude-haiku-5-5"})

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n)
                if self.path.split("?")[0] != "/v1/messages":
                    self._error(404, f"Not found: {self.path}")
                    return
                try:
                    body = json.loads(raw or b"{}")
                except ValueError:
                    self._error(400, "request body is not valid JSON")
                    return
                with fake.lock:
                    step = fake.script.pop(0) if fake.script else "ok"
                    fake.requests.append({"t": time.monotonic(), "body": body, "step": step,
                                          "headers": {k.lower(): v for k, v in self.headers.items()}})
                if not self._auth_ok():
                    return
                if isinstance(step, dict):
                    if step.get("delay"):
                        time.sleep(float(step["delay"]))
                    if step.get("status"):
                        h = {}
                        if step.get("retry_after") is not None:
                            h["retry-after"] = str(step["retry_after"])
                        if step.get("should_retry") is not None:
                            h["x-should-retry"] = str(step["should_retry"]).lower()
                        self._error(int(step["status"]), step.get("message", "scripted error"), step.get("type"), h)
                        return
                problem = self._validate(body)
                if problem:
                    self._error(400, problem)
                    return
                msg = self._message(body)
                if body.get("stream"):
                    self._stream(msg, step if isinstance(step, dict) else {})
                else:
                    self._send(200, msg)

            def _validate(self, b: dict[str, Any]) -> str | None:
                for k in ("model", "max_tokens", "messages"):
                    if k not in b:
                        return f"{k}: Field required"
                if not isinstance(b["max_tokens"], int) or b["max_tokens"] < 1:
                    return "max_tokens: must be a positive integer"
                if not b["messages"] or b["messages"][0].get("role") != "user":
                    return "messages: first message must use the user role"
                tools = {t.get("name"): t for t in b.get("tools", [])}
                for t in tools.values():
                    if not isinstance(t.get("input_schema"), dict):
                        return "tools.0.input_schema: Field required"
                tc = b.get("tool_choice") or {}
                if tc.get("type") in ("any", "tool") and fake.reject_forced_tool:
                    return f"tool_choice: forced tool use is not supported for {b['model']}"
                if tc.get("type") == "tool" and tc.get("name") not in tools:
                    return "tool_choice.name: tool not found"
                return None

            def _message(self, b: dict[str, Any]) -> dict[str, Any]:
                content = b["messages"][-1].get("content", "")
                if isinstance(content, list):
                    content = " ".join(c.get("text", "") for c in content if isinstance(c, dict))
                m = _SNIPPET_RE.search(content)
                snippet = m.group(1) if m else content
                tools = b.get("tools") or []
                blocks: list[dict[str, Any]] = []
                if tools and (b.get("tool_choice") or {}).get("type") != "none":
                    blocks.append({"type": "tool_use", "id": f"toolu_fake_{uuid.uuid4().hex[:20]}",
                                   "name": tools[0]["name"], "input": toy_classify(snippet)})
                    stop = "tool_use"
                else:
                    blocks.append({"type": "text", "text": json.dumps(toy_classify(snippet))})
                    stop = "end_turn"
                return {"id": f"msg_fake_{uuid.uuid4().hex[:20]}", "type": "message", "role": "assistant",
                        "model": b["model"], "content": blocks, "stop_reason": stop, "stop_sequence": None,
                        "usage": {"input_tokens": max(1, len(json.dumps(b)) // 4), "output_tokens": 42}}

            def _stream(self, msg: dict[str, Any], step: dict[str, Any]) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()

                def ev(name: str, data: dict[str, Any]) -> None:
                    self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
                    self.wfile.flush()

                start = {**msg, "content": [], "stop_reason": None,
                         "usage": {"input_tokens": msg["usage"]["input_tokens"], "output_tokens": 1}}
                ev("message_start", {"type": "message_start", "message": start})
                ev("ping", {"type": "ping"})
                for i, block in enumerate(msg["content"]):
                    if block["type"] == "tool_use":
                        ev("content_block_start", {"type": "content_block_start", "index": i,
                                                   "content_block": {**block, "input": {}}})
                        js = json.dumps(block["input"])
                        parts = [""] + [js[j:j + 17] for j in range(0, len(js), 17)]
                        for k, part in enumerate(parts):
                            if step.get("stream_error") and k == 3:
                                ev("error", {"type": "error", "error": {"type": step["stream_error"],
                                                                        "message": "scripted mid-stream error"}})
                                self.close_connection = True
                                return
                            ev("content_block_delta", {"type": "content_block_delta", "index": i,
                                                       "delta": {"type": "input_json_delta", "partial_json": part}})
                    else:
                        ev("content_block_start", {"type": "content_block_start", "index": i,
                                                   "content_block": {"type": "text", "text": ""}})
                        ev("content_block_delta", {"type": "content_block_delta", "index": i,
                                                   "delta": {"type": "text_delta", "text": block["text"]}})
                    ev("content_block_stop", {"type": "content_block_stop", "index": i})
                ev("message_delta", {"type": "message_delta",
                                     "delta": {"stop_reason": msg["stop_reason"], "stop_sequence": None},
                                     "usage": {"output_tokens": msg["usage"]["output_tokens"]}})
                ev("message_stop", {"type": "message_stop"})
                self.close_connection = True

        self.httpd = ThreadingHTTPServer((host, port), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.base_url = f"http://{host}:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self) -> FakeAnthropic:
        self.thread.start()
        return self

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def __enter__(self) -> FakeAnthropic:
        return self.start()

    def __exit__(self, *a: object) -> None:
        self.close()


def main() -> None:  # pragma: no cover - manual use
    ap = argparse.ArgumentParser(description="fake Anthropic Messages API on localhost")
    ap.add_argument("--port", type=int, default=0)
    a = ap.parse_args()
    fake = FakeAnthropic(port=a.port).start()
    print(f"fake Anthropic Messages API listening on {fake.base_url} (Ctrl-C to stop)", flush=True)
    try:
        fake.thread.join()
    except KeyboardInterrupt:
        fake.close()


if __name__ == "__main__":
    main()
