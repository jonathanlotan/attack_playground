#!/usr/bin/env python3
"""
containerssh authentication webhook for the playground.

it authenticates *anybody* as whatever username they ask for. that is the point of
a playground, and it is why the port is published on 127.0.0.1 only - see the
ports comment in docker-compose.yaml.

stdlib only, deliberately. this was a flask app whose container ran
"pip install flask" on every start, which meant the auth service needed working
network access each time it booted and could not authenticate anyone until the
install finished - during which every ssh login was rejected with
"connection refused" from containerssh's point of view. nothing here needs a
framework.

containerssh appends /password and /pubkey to the configured webhook url, and
config.yaml sets that url to ".../auth", so the paths served are /auth/password
and /auth/pubkey.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_ADDRESS = "0.0.0.0"
LISTEN_PORT = 8080

AUTH_PATHS = ("/auth/password", "/auth/pubkey")
DEFAULT_USERNAME = "guestuser"


class AuthHandler(BaseHTTPRequestHandler):
    # containerssh's http client keeps connections alive; answering as HTTP/1.0
    # makes it reconnect for every authentication attempt. every response below
    # carries an accurate Content-Length, which is what HTTP/1.1 requires here.
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        # the body is always drained, even for a path we reject: leaving it in
        # the socket desynchronises the next request on a kept-alive connection.
        payload = self._read_json()

        if self.path not in AUTH_PATHS:
            self._respond(404, {"error": "not found"})
            return

        # authenticatedUsername must be a string: containerssh sends one, and
        # echoing back whatever json value a hand-written probe put there would
        # hand containerssh a list or an object under that key.
        username = DEFAULT_USERNAME
        if isinstance(payload, dict) and isinstance(payload.get("username"), str):
            username = payload["username"] or DEFAULT_USERNAME

        self._respond(200, {"success": True, "authenticatedUsername": username})

    def do_GET(self):
        # nothing to serve, but answer rather than letting the base class emit a
        # 501 - this port gets curled by hand while debugging.
        self._respond(404, {"error": "not found"})

    def _read_json(self):
        """
        the decoded request body, or None if there isn't a usable one.

        a missing or malformed body is not an error here: this webhook says yes to
        everyone by design, so failing the request would turn a bad probe body
        into what looks like a broken playground.
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (ValueError, OSError):
            return None

    def _respond(self, status, body):
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def main():
    # threading so one slow client cannot hold up another login
    server = ThreadingHTTPServer((LISTEN_ADDRESS, LISTEN_PORT), AuthHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
