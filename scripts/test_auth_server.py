#!/usr/bin/env python3
"""
regression tests for the containerssh auth webhook.

the webhook is the thing that decides whether anyone can log into the playground
at all, and it is now stdlib rather than flask - these pin the wire contract that
containerssh depends on.

stdlib only, no docker and no network beyond loopback. run with:

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import http.client
import json
import os
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import auth_server  # noqa: E402


class AuthServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # the handler logs every request to stderr, which is wanted in the
        # container and only noise here
        cls._quiet = mock.patch.object(auth_server.AuthHandler, "log_message",
                                       lambda *a, **k: None)
        cls._quiet.start()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), auth_server.AuthHandler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls._quiet.stop()

    def post(self, path, body=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            if raw is not None:
                payload = raw
            elif body is not None:
                payload = json.dumps(body).encode()
            else:
                payload = b""
            conn.request("POST", path, body=payload,
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            return resp.status, resp.getheader("Content-Type"), resp.read()
        finally:
            conn.close()

    # ------------------------------------------------------------ the contract

    def test_password_request_is_accepted_and_echoes_the_username(self):
        status, ctype, data = self.post("/auth/password", {"username": "alice"})
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "application/json")
        self.assertEqual(json.loads(data),
                         {"success": True, "authenticatedUsername": "alice"})

    def test_pubkey_request_is_accepted_too(self):
        status, _, data = self.post("/auth/pubkey", {"username": "bob"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["authenticatedUsername"], "bob")

    def test_unknown_path_is_404(self):
        status, _, _ = self.post("/auth/somethingelse", {"username": "alice"})
        self.assertEqual(status, 404)

    # ------------------------------------------------------- degenerate bodies
    #
    # this webhook says yes to everyone by design, so a body it cannot read must
    # not turn into a failed login - that reads as a broken playground.

    def test_malformed_body_still_authenticates(self):
        status, _, data = self.post("/auth/password", raw=b"not json at all")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["authenticatedUsername"], "guestuser")

    def test_empty_body_still_authenticates(self):
        status, _, data = self.post("/auth/password")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["authenticatedUsername"], "guestuser")

    def test_json_that_is_not_an_object_still_authenticates(self):
        status, _, data = self.post("/auth/password", raw=b'["alice"]')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["authenticatedUsername"], "guestuser")

    def test_non_string_username_falls_back(self):
        # authenticatedUsername is a string in containerssh's contract; a probe
        # that puts a list there must not have it echoed back
        status, _, data = self.post("/auth/password", {"username": ["alice"]})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["authenticatedUsername"], "guestuser")

    def test_missing_username_falls_back(self):
        status, _, data = self.post("/auth/password", {"remoteAddress": "1.2.3.4"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["authenticatedUsername"], "guestuser")

    # --------------------------------------------------------------- keepalive

    def test_two_requests_on_one_connection(self):
        # the handler answers as HTTP/1.1, which containerssh's client will hold
        # open. a wrong or missing Content-Length desynchronises the second
        # request on the same socket rather than failing the first one, so it
        # would not show up in any of the tests above.
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            for name in ("first", "second"):
                conn.request("POST", "/auth/password",
                             body=json.dumps({"username": name}).encode(),
                             headers={"Content-Type": "application/json"})
                resp = conn.getresponse()
                data = resp.read()
                self.assertEqual(resp.status, 200)
                self.assertEqual(json.loads(data)["authenticatedUsername"], name)
        finally:
            conn.close()

    def test_rejected_path_does_not_break_the_next_request(self):
        # the body of a rejected request still has to be drained
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("POST", "/nope", body=json.dumps({"username": "x"}).encode(),
                         headers={"Content-Type": "application/json"})
            rejected = conn.getresponse()
            self.assertEqual(rejected.status, 404)
            rejected.read()

            conn.request("POST", "/auth/password",
                         body=json.dumps({"username": "after"}).encode(),
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read())["authenticatedUsername"], "after")
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
