#!/usr/bin/env python3
"""HTTP -> HTTPS relay for ZigOS to send Telegram messages.

ZigOS doesn't have TLS yet. Telegram's Bot API is HTTPS-only. This relay
listens for plain HTTP POST on port 8080 and forwards the message to
api.telegram.org over HTTPS using the host's TLS stack (urllib).

Usage:
    export TG_BOT_TOKEN='123456:abc...'   # token from @BotFather
    python3 tools/tg_relay.py             # binds 0.0.0.0:8080

Request format from ZigOS:
    POST /send HTTP/1.1
    Content-Type: application/json
    Content-Length: N

    {"chat_id": 12345678, "text": "hello"}

Response: 200 OK on success, 4xx/5xx on failure with a short text body.

Security note: the bot token lives only on the relay host. ZigOS only sees
chat IDs and message text. The relay should not be exposed beyond the LAN.
"""

import http.server
import json
import os
import sys
import urllib.parse
import urllib.request

TOKEN = os.environ.get("TG_BOT_TOKEN")
if not TOKEN:
    print("error: TG_BOT_TOKEN not set", file=sys.stderr)
    sys.exit(1)

API_BASE = f"https://api.telegram.org/bot{TOKEN}"


def send_to_telegram(chat_id: int, text: str) -> tuple[int, str]:
    payload = urllib.parse.urlencode({"chat_id": str(chat_id), "text": text}).encode()
    req = urllib.request.Request(
        f"{API_BASE}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 502, f"relay error: {e}"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/send":
            self._reply(404, "not found")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._reply(400, "bad content-length")
            return
        if length <= 0 or length > 16 * 1024:
            self._reply(400, "bad body length")
            return
        body = self.rfile.read(length)
        try:
            doc = json.loads(body)
            chat_id = int(doc["chat_id"])
            text = str(doc["text"])
        except Exception as e:
            self._reply(400, f"bad json: {e}")
            return
        if not text:
            self._reply(400, "empty text")
            return

        status, info = send_to_telegram(chat_id, text)
        # Mirror Telegram's status straight through; the OS shows it.
        self._reply(status, info[:512])

    # Quieter logs — we only want failures + sends, not raw access lines.
    def log_message(self, fmt, *args):
        sys.stderr.write(f"[relay] {self.address_string()} {fmt % args}\n")

    def _reply(self, status: int, body: str):
        b = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b)


def main():
    port = int(os.environ.get("TG_RELAY_PORT", "8080"))
    server = http.server.HTTPServer(("0.0.0.0", port), Handler)
    print(f"[relay] listening on 0.0.0.0:{port} (telegram bot token loaded)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[relay] shutting down")


if __name__ == "__main__":
    main()
