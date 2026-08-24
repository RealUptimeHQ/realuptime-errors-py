"""Pins the wire contract mirror and the stdlib-only dependency discipline,
the apps/agent/wire-contract.test.ts convention ported to Python."""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import realuptime_errors  # noqa: E402

SOURCE = os.path.join(os.path.dirname(__file__), "..", "realuptime_errors.py")

# Everything this SDK is allowed to import: the Python 3 standard library
# modules it actually uses, and nothing else, ever. It runs inside customer
# processes; its dependency graph must be auditable at a glance.
ALLOWED_IMPORTS = {
    "__future__",
    "json",
    "re",
    "sys",
    "threading",
    "time",
    "urllib.error",
    "urllib.request",
    "datetime",
    "linecache",
    "platform",
}


class TestDependencyHygiene(unittest.TestCase):
    def test_stdlib_only(self):
        with open(SOURCE, encoding="utf-8") as fh:
            source = fh.read()
        # Drop docstrings (the module docstring's usage example says
        # "import realuptime_errors", which is documentation, not an import).
        source = "".join(part for i, part in enumerate(source.split('"""')) if i % 2 == 0)
        imported = set()
        for match in re.finditer(r"^\s*import\s+([\w.]+)|^\s*from\s+([\w.]+)\s+import", source, re.M):
            imported.add(match.group(1) or match.group(2))
        self.assertTrue(imported)
        self.assertEqual(imported - ALLOWED_IMPORTS, set())


class TestWireContractMirror(unittest.TestCase):
    def test_limits_match_the_js_sdk(self):
        # Mirrored from packages/errors-js/types.ts, pinned on both sides.
        self.assertEqual(realuptime_errors.MAX_EVENTS_PER_BATCH, 50)
        self.assertEqual(realuptime_errors.MAX_MESSAGE_LENGTH, 4000)
        self.assertEqual(realuptime_errors.MAX_FRAMES_PER_EVENT, 50)
        self.assertEqual(realuptime_errors.MAX_STRING_LENGTH, 512)
        self.assertEqual(realuptime_errors.BUFFER_MAX, 200)
        self.assertEqual(realuptime_errors.MAX_BREADCRUMBS_PER_EVENT, 20)
        self.assertEqual(realuptime_errors.MAX_BREADCRUMB_DATA_ENTRIES, 10)

    def test_v2_caps_match_the_js_sdk(self):
        # REA-182, mirrored from packages/errors-js/types.ts and pinned
        # there too. The server's copies live in
        # packages/db/error-ingest.ts.
        self.assertEqual(realuptime_errors.MAX_TAGS_PER_EVENT, 20)
        self.assertEqual(realuptime_errors.MAX_CONTEXT_ENTRIES, 20)
        self.assertEqual(realuptime_errors.MAX_CONTEXT_KEY_LENGTH, 64)
        self.assertEqual(realuptime_errors.MAX_LOCAL_VARS_PER_FRAME, 20)
        self.assertEqual(realuptime_errors.MAX_LOCAL_VAR_LENGTH, 256)

    def test_event_field_names(self):
        # Built with no state, so no v2 scope exists to emit: this is the
        # v1 key set, and it must stay exactly this. The v2 keys appearing
        # only when something set them is covered in test_context_v2.py.
        event = realuptime_errors._build_event("m", "TypeError", None)
        self.assertEqual(
            sorted(event.keys()),
            [
                "breadcrumbs",
                "breadcrumbsDropped",
                "environment",
                "exceptionType",
                "fingerprint",
                "frames",
                "message",
                "occurredAt",
                "release",
                "request",
            ],
        )


if __name__ == "__main__":
    unittest.main()
