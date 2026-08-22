"""WSGI/ASGI middleware behavior: capture, minimal request context, re-raise."""

import asyncio
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import realuptime_errors  # noqa: E402


class TestMiddleware(unittest.TestCase):
    def setUp(self):
        self.batches = []

        def opener(url, body):
            self.batches.append(json.loads(body))
            return 200, json.dumps({"accepted": 1, "droppedOverQuota": 0, "overQuota": False, "quota": {"used": 1, "limit": 10000, "resetsAt": "2026-09-01T00:00:00.000Z"}}).encode()

        realuptime_errors.init(dsn="https://x/i/rue_a", capture_unhandled=False, _opener=opener, _log=lambda m: None)

    def tearDown(self):
        realuptime_errors._close()

    def test_wsgi_captures_minimal_context_and_reraises(self):
        def app(environ, start_response):
            raise RuntimeError("wsgi boom")

        wrapped = realuptime_errors.WsgiMiddleware(app)
        environ = {"REQUEST_METHOD": "POST", "PATH_INFO": "/checkout", "HTTP_COOKIE": "sid=secret"}
        with self.assertRaises(RuntimeError):
            wrapped(environ, lambda status, headers: None)
        event = self.batches[0]["events"][0]
        self.assertEqual(event["request"], {"method": "POST", "path": "/checkout"})
        self.assertEqual(event["exceptionType"], "RuntimeError")
        # Default capture is minimal: no headers, no query, no body.
        self.assertNotIn("headers", event["request"])

    def test_asgi_captures_and_reraises(self):
        async def app(scope, receive, send):
            raise RuntimeError("asgi boom")

        wrapped = realuptime_errors.AsgiMiddleware(app)
        scope = {"type": "http", "method": "GET", "path": "/orders"}
        with self.assertRaises(RuntimeError):
            asyncio.run(wrapped(scope, None, None))
        event = self.batches[0]["events"][0]
        self.assertEqual(event["request"], {"method": "GET", "path": "/orders"})


if __name__ == "__main__":
    unittest.main()
