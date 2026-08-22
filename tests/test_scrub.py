"""Drives the SHARED scrub vectors through the Python SDK.

The vectors file (packages/errors-js/scrub-vectors.json) is the single
source of truth for scrub semantics across the JS SDK, this SDK, and the
server's second net; this suite must never grow expectations of its own.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import realuptime_errors  # noqa: E402

VECTORS_PATH = os.path.join(os.path.dirname(__file__), "..", "scrub-vectors.json")

BASE = {
    "occurredAt": "2026-08-21T00:00:00.000Z",
    "message": "",
    "exceptionType": None,
    "release": None,
    "environment": None,
    "frames": None,
    "request": None,
    "fingerprint": None,
    "breadcrumbs": None,
    "breadcrumbsDropped": 0,
}


def load_vectors():
    with open(VECTORS_PATH, encoding="utf-8") as fh:
        return json.load(fh)["vectors"]


class TestScrubVectors(unittest.TestCase):
    def test_has_enough_vectors_to_mean_something(self):
        self.assertGreaterEqual(len(load_vectors()), 15)

    def test_all_vectors(self):
        for vector in load_vectors():
            with self.subTest(vector["name"]):
                event = dict(BASE)
                event.update(vector["event"])
                expected = dict(BASE)
                expected.update(vector["expected"])
                output = realuptime_errors.scrub_event(event, vector.get("allowFields"))
                self.assertEqual(output, expected)

    def test_never_mutates_the_input(self):
        event = dict(BASE)
        event.update(
            {
                "message": "sk_live_abcdefgh12345678",
                "request": {"method": "GET", "path": "/x", "status": 500, "headers": {"cookie": "sid=1"}},
            }
        )
        snapshot = json.loads(json.dumps(event))
        realuptime_errors.scrub_event(event)
        self.assertEqual(event, snapshot)


if __name__ == "__main__":
    unittest.main()
