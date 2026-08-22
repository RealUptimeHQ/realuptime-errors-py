"""Transport and public-API behavior, mirroring packages/errors-js/client.test.ts."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import realuptime_errors  # noqa: E402
from realuptime_errors import BUFFER_MAX, BACKOFF_START_S, _Transport  # noqa: E402


def event(message):
    return {
        "occurredAt": "2026-08-21T00:00:00.000Z",
        "message": message,
        "exceptionType": None,
        "release": None,
        "environment": None,
        "frames": None,
        "request": None,
        "fingerprint": None,
    }


def ok_body():
    return json.dumps(
        {
            "accepted": 1,
            "droppedOverQuota": 0,
            "overQuota": False,
            "quota": {"used": 1, "limit": 10000, "resetsAt": "2026-09-01T00:00:00.000Z"},
        }
    ).encode()


class RecordingOpener:
    def __init__(self, responses):
        self.responses = responses
        self.batches = []

    def __call__(self, url, body):
        self.batches.append(json.loads(body))
        result = self.responses[min(len(self.batches) - 1, len(self.responses) - 1)]
        if isinstance(result, Exception):
            raise result
        return result


class TestTransport(unittest.TestCase):
    def test_reports_client_side_drops_on_the_next_batch(self):
        opener = RecordingOpener([(200, ok_body())])
        transport = _Transport("https://x/i/rue_a", opener=opener, log=lambda m: None)
        # Fill past the bound without delivering, then flush once.
        with transport._lock:
            pass
        transport._now = lambda: 0
        # enqueue triggers flush each time; deliveries drain the buffer, so
        # count totals across all batches instead.
        for i in range(BUFFER_MAX + 3):
            transport.enqueue(event("e%d" % i))
        transport.flush()
        total_dropped = sum(b["droppedClient"] for b in opener.batches)
        total_sent = sum(len(b["events"]) for b in opener.batches)
        self.assertEqual(total_dropped + total_sent, BUFFER_MAX + 3)

    def test_over_quota_pauses_until_reset(self):
        refusal = (429, json.dumps({"error": "quota", "reason": "over_quota", "resetsAt": "2026-09-01T00:00:00.000Z"}).encode())
        opener = RecordingOpener([refusal])
        clock = {"now": 1787000000.0}  # inside the 2026-08 window
        transport = _Transport("https://x/i/rue_a", opener=opener, now=lambda: clock["now"], log=lambda m: None)
        transport.enqueue(event("a"))
        self.assertEqual(len(opener.batches), 1)
        transport.enqueue(event("b"))
        self.assertEqual(len(opener.batches), 1)  # paused, no retry into the cap
        clock["now"] = 1788220801.0  # one second past 2026-09-01T00:00:00Z
        transport.enqueue(event("c"))
        self.assertEqual(len(opener.batches), 2)

    def test_revoked_key_disables_for_process_lifetime_logging_once(self):
        logs = []
        refusal = (403, json.dumps({"error": "revoked", "reason": "key_revoked"}).encode())
        opener = RecordingOpener([refusal])
        transport = _Transport("https://x/i/rue_a", opener=opener, log=logs.append)
        transport.enqueue(event("a"))
        transport.enqueue(event("b"))
        self.assertEqual(len(opener.batches), 1)
        self.assertEqual(len([l for l in logs if "revoked" in l]), 1)

    def test_network_failure_backs_off_and_retries_same_event(self):
        opener = RecordingOpener([OSError("refused"), (200, ok_body())])
        clock = {"now": 0.0}
        transport = _Transport("https://x/i/rue_a", opener=opener, now=lambda: clock["now"], log=lambda m: None)
        transport.enqueue(event("a"))
        self.assertEqual(len(opener.batches), 1)
        transport.flush()
        self.assertEqual(len(opener.batches), 1)  # inside backoff
        clock["now"] = BACKOFF_START_S + 1
        transport.flush()
        self.assertEqual(len(opener.batches), 2)
        self.assertEqual(opener.batches[1]["events"][0]["message"], "a")


class TestPublicApiNeverRaises(unittest.TestCase):
    def tearDown(self):
        realuptime_errors._close()

    def test_capture_before_init_is_noop(self):
        realuptime_errors._close()
        realuptime_errors.capture_exception(ValueError("x"))  # must not raise

    def test_broken_opener_never_escapes(self):
        def exploding_opener(url, body):
            raise RuntimeError("opener exploded")

        realuptime_errors.init(
            dsn="https://x/i/rue_a", capture_unhandled=False, _opener=exploding_opener, _log=lambda m: None
        )
        try:
            raise ValueError("boom")
        except ValueError as exc:
            realuptime_errors.capture_exception(exc)  # must not raise
        realuptime_errors.flush()  # must not raise

    def test_frames_are_captured_innermost_first(self):
        captured = {}

        def opener(url, body):
            captured["batch"] = json.loads(body)
            return 200, ok_body()

        realuptime_errors.init(dsn="https://x/i/rue_a", capture_unhandled=False, _opener=opener, _log=lambda m: None)

        def inner():
            raise ValueError("deep")

        try:
            inner()
        except ValueError as exc:
            realuptime_errors.capture_exception(exc)
        frames = captured["batch"]["events"][0]["frames"]
        self.assertEqual(frames[0]["function"], "inner")
        self.assertTrue(frames[0]["inApp"])
        self.assertEqual(captured["batch"]["events"][0]["exceptionType"], "ValueError")


class TestBreadcrumbs(unittest.TestCase):
    """Phase 3: bounded trail, honest eviction counts, JS-SDK parity."""

    def tearDown(self):
        realuptime_errors._close()

    def _capture_batch(self):
        captured = {}

        def opener(url, body):
            captured["batch"] = json.loads(body)
            return 200, ok_body()

        realuptime_errors.init(dsn="https://x/i/rue_a", capture_unhandled=False, _opener=opener, _log=lambda m: None)
        return captured

    def test_trail_rides_next_event_with_eviction_count(self):
        captured = self._capture_batch()
        for i in range(25):
            realuptime_errors.add_breadcrumb("step %d" % i, category="test")
        realuptime_errors.add_breadcrumb("charging", data={"card": "4242424242424242", "order": "ord-1"})
        realuptime_errors.capture_message("boom")
        event = captured["batch"]["events"][0]
        self.assertEqual(len(event["breadcrumbs"]), realuptime_errors.MAX_BREADCRUMBS_PER_EVENT)
        # 26 recorded, 20 kept -> 6 evictions reported, never silent.
        self.assertEqual(event["breadcrumbsDropped"], 6)
        self.assertEqual(event["breadcrumbs"][0]["message"], "step 6")
        last = event["breadcrumbs"][-1]
        self.assertEqual(last["message"], "charging")
        # Scrubbed on the way out: the card never leaves the process.
        self.assertEqual(last["data"]["card"], "[scrubbed]")
        self.assertEqual(last["data"]["order"], "ord-1")

    def test_add_breadcrumb_before_init_is_noop(self):
        realuptime_errors._close()
        realuptime_errors.add_breadcrumb("x")  # must not raise


class TestSourceContext(unittest.TestCase):
    """Phase 3: frames carry real source context read via linecache."""

    def tearDown(self):
        realuptime_errors._close()

    def test_frames_carry_context_lines(self):
        captured = {}

        def opener(url, body):
            captured["batch"] = json.loads(body)
            return 200, ok_body()

        realuptime_errors.init(dsn="https://x/i/rue_a", capture_unhandled=False, _opener=opener, _log=lambda m: None)

        def deep():
            raise ValueError("ctx")

        try:
            deep()
        except ValueError as exc:
            realuptime_errors.capture_exception(exc)
        frame = captured["batch"]["events"][0]["frames"][0]
        self.assertEqual(frame["function"], "deep")
        self.assertIn("raise ValueError", frame["contextLine"])
        self.assertTrue(any("def deep" in line for line in frame["preContext"]))
        self.assertLessEqual(len(frame["preContext"]), realuptime_errors.CONTEXT_LINES)
        self.assertLessEqual(len(frame["postContext"]), realuptime_errors.CONTEXT_LINES)


if __name__ == "__main__":
    unittest.main()
