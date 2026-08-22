"""realuptime-errors: minimal Python error tracking SDK, Phase 1
(docs/errors-plan.md, Linear REA-57).

One wire contract with the JS SDK (packages/errors-js/types.ts); the shared
scrub vectors (packages/errors-js/scrub-vectors.json) pin both SDKs and the
server's second net to byte-identical scrubbing. Python 3 stdlib only, no
dependencies, same rule as deploy/vps: this file runs inside customer
processes and its dependency graph must be auditable at a glance.

Contract with the host app, non-negotiable: THIS SDK NEVER RAISES out of a
public function. A broken SDK logs once and goes quiet; an error tracker
that crashes the app it watches is worse than none.

Usage:

    import realuptime_errors
    realuptime_errors.init(dsn="https://realuptime.io/api/errors/v1/ingest/rue_...",
                           release="v2.4.1", environment="production")
    ...
    realuptime_errors.capture_exception(exc)

WSGI:  app = realuptime_errors.WsgiMiddleware(app)
ASGI:  app = realuptime_errors.AsgiMiddleware(app)
"""

from __future__ import annotations

import json
import linecache
import re
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request

SDK_NAME = "realuptime-errors-py"
SDK_VERSION = "0.2.0"

# Mirrored from packages/errors-js/types.ts and pinned by
# tests/test_wire_contract.py.
MAX_EVENTS_PER_BATCH = 50
MAX_MESSAGE_LENGTH = 4000
MAX_FRAMES_PER_EVENT = 50
MAX_STRING_LENGTH = 512
MAX_BREADCRUMBS_PER_EVENT = 20
MAX_BREADCRUMB_DATA_ENTRIES = 10
BUFFER_MAX = 200

# Context lines captured either side of each frame's own line (Phase 3:
# "Python symbolication depth" -- Python needs no source maps; the depth is
# real source context read IN the customer's process, where the source is).
CONTEXT_LINES = 3

SEND_TIMEOUT_S = 10.0
BACKOFF_START_S = 5.0
BACKOFF_MAX_S = 300.0

SCRUBBED = "[scrubbed]"

_REMOVED_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie"}

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b")
_PREFIXED_KEY_RE = re.compile(r"\b(?:sk|pk|rk|ghp|gho|ghs|xox[a-z]|rua|rue|ru_live)_[A-Za-z0-9_-]{8,}")
_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+_=-])[A-Za-z0-9+_-]{40,}={0,2}")


def _luhn_valid(digits: str) -> bool:
    total = 0
    double = False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return total % 10 == 0


def _scrub_card(match: "re.Match[str]") -> str:
    run = match.group(0)
    digits = run.replace(" ", "").replace("-", "")
    if 13 <= len(digits) <= 19 and _luhn_valid(digits):
        return SCRUBBED
    return run


def scrub_string(value: str) -> str:
    """The five pattern rules, in the shared order (see scrub-vectors.json)."""
    out = _JWT_RE.sub(SCRUBBED, value)
    out = _PREFIXED_KEY_RE.sub(SCRUBBED, out)
    out = _CARD_RE.sub(_scrub_card, out)
    out = _HEX_RE.sub(SCRUBBED, out)
    out = _BASE64_RE.sub(SCRUBBED, out)
    return out


def _scrub_breadcrumb(crumb: dict) -> dict:
    out = dict(crumb)
    if isinstance(out.get("message"), str):
        out["message"] = scrub_string(out["message"])
    data = out.get("data")
    if isinstance(data, dict):
        out["data"] = {
            name: scrub_string(value) if isinstance(value, str) else value for name, value in data.items()
        }
    return out


def _scrub_frame_context(frame: dict) -> dict:
    if not isinstance(frame, dict):
        return frame
    if not (frame.get("contextLine") or frame.get("preContext") or frame.get("postContext")):
        return frame
    out = dict(frame)
    if isinstance(out.get("contextLine"), str):
        out["contextLine"] = scrub_string(out["contextLine"])
    for key in ("preContext", "postContext"):
        lines = out.get(key)
        if isinstance(lines, list):
            out[key] = [scrub_string(line) if isinstance(line, str) else line for line in lines]
    return out


def scrub_event(event: dict, allow_fields: "list[str] | None" = None) -> dict:
    """Scrubs one wire event. Returns a new dict; never mutates the input."""
    allowed = {f.lower() for f in (allow_fields or [])}
    out = dict(event)
    if isinstance(out.get("message"), str):
        out["message"] = scrub_string(out["message"])
    breadcrumbs = out.get("breadcrumbs")
    if isinstance(breadcrumbs, list):
        out["breadcrumbs"] = [_scrub_breadcrumb(c) if isinstance(c, dict) else c for c in breadcrumbs]
    frames = out.get("frames")
    if isinstance(frames, list):
        out["frames"] = [_scrub_frame_context(f) for f in frames]
    request = out.get("request")
    if isinstance(request, dict):
        request = dict(request)
        if isinstance(request.get("path"), str):
            request["path"] = scrub_string(request["path"])
        headers = request.get("headers")
        if isinstance(headers, dict):
            scrubbed_headers = {}
            for name, value in headers.items():
                lower = name.lower()
                if lower in _REMOVED_HEADERS and lower not in allowed:
                    scrubbed_headers[name] = SCRUBBED
                else:
                    scrubbed_headers[name] = scrub_string(value) if isinstance(value, str) else value
            request["headers"] = scrubbed_headers
        out["request"] = request
    return out


def _clip(value: str, limit: int) -> str:
    return value[:limit] if len(value) > limit else value


def _source_context(filename: str, lineno: "int | None") -> dict:
    """Reads CONTEXT_LINES either side of the frame's line via linecache
    (Phase 3). Best-effort: an unreadable file yields no context rather than
    an error, and the lines are pattern-scrubbed with the event."""
    if not lineno or not filename or filename.startswith("<"):
        return {}
    try:
        context_line = linecache.getline(filename, lineno).rstrip("\n")
        if not context_line:
            return {}
        pre = [
            linecache.getline(filename, n).rstrip("\n")
            for n in range(max(1, lineno - CONTEXT_LINES), lineno)
        ]
        post = [linecache.getline(filename, n).rstrip("\n") for n in range(lineno + 1, lineno + 1 + CONTEXT_LINES)]
        while post and post[-1] == "":
            post.pop()
        return {
            "contextLine": _clip(context_line, MAX_STRING_LENGTH),
            "preContext": [_clip(line, MAX_STRING_LENGTH) for line in pre],
            "postContext": [_clip(line, MAX_STRING_LENGTH) for line in post],
        }
    except Exception:
        return {}


def _frames_from_exception(exc: BaseException) -> "list[dict] | None":
    frames = []
    for frame in traceback.extract_tb(exc.__traceback__):
        filename = frame.filename or ""
        in_app = "site-packages" not in filename and "dist-packages" not in filename and not filename.startswith("<")
        entry = {
            "file": _clip(filename, MAX_STRING_LENGTH),
            "function": _clip(frame.name, MAX_STRING_LENGTH) if frame.name else None,
            "line": frame.lineno,
            "inApp": in_app,
        }
        entry.update(_source_context(filename, frame.lineno))
        frames.append(entry)
        if len(frames) >= MAX_FRAMES_PER_EVENT:
            break
    # Innermost first on the wire, matching the JS SDK's stack order.
    frames.reverse()
    return frames or None


class _Transport:
    """Batched, buffered, backed-off delivery. Mirrors
    packages/errors-js/client.ts: over_quota pauses until the reset instant,
    key_revoked disables for the process lifetime, transient failures back
    off exponentially, and client-side drops ride the next successful batch
    as droppedClient so they reach the product's visible drop counters."""

    def __init__(self, endpoint, opener=None, now=None, log=None):
        self._endpoint = endpoint
        self._opener = opener or self._http_post
        self._now = now or time.time
        self._log_fn = log or (lambda message: print(message, file=sys.stderr))
        self._lock = threading.Lock()
        self._events: "list[dict]" = []
        self._dropped_since_report = 0
        self._backoff_s = 0.0
        self._next_attempt_at = 0.0
        self._paused_until = 0.0
        self._disabled = False
        self._logged_kinds: "set[str]" = set()

    def _http_post(self, url: str, body: bytes):
        req = urllib.request.Request(
            url, data=body, headers={"content-type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=SEND_TIMEOUT_S) as res:
                return res.status, res.read()
        except urllib.error.HTTPError as err:
            return err.code, err.read()

    def _log_once(self, kind: str, message: str) -> None:
        if kind in self._logged_kinds:
            return
        self._logged_kinds.add(kind)
        try:
            self._log_fn("[realuptime-errors] " + message)
        except Exception:
            pass

    def enqueue(self, event: dict) -> None:
        with self._lock:
            if self._disabled:
                return
            if len(self._events) >= BUFFER_MAX:
                self._events.pop(0)
                self._dropped_since_report += 1
            self._events.append(event)
        self.flush()

    def flush(self) -> None:
        """Sends what is due. Never raises."""
        try:
            self._deliver()
        except Exception as failure:  # belt and braces: never crash the host
            self._log_once("internal", "delivery failed internally: %r" % (failure,))

    def _deliver(self) -> None:
        while True:
            with self._lock:
                now = self._now()
                if self._disabled or not self._events or now < self._next_attempt_at or now < self._paused_until:
                    return
                events = self._events[:MAX_EVENTS_PER_BATCH]
                dropped_client = self._dropped_since_report
                self._dropped_since_report = 0
            batch = {"sdk": "%s/%s" % (SDK_NAME, SDK_VERSION), "droppedClient": dropped_client, "events": events}
            try:
                status, raw = self._opener(self._endpoint, json.dumps(batch).encode("utf-8"))
            except Exception:
                with self._lock:
                    self._dropped_since_report += dropped_client
                self._back_off("network", "cannot reach the ingest endpoint; buffering and retrying")
                return
            try:
                body = json.loads(raw) if raw else {}
            except Exception:
                body = {}

            if 200 <= status < 300:
                with self._lock:
                    del self._events[: len(events)]
                    self._backoff_s = 0.0
                    self._next_attempt_at = 0.0
                if body.get("overQuota"):
                    self._pause_until((body.get("quota") or {}).get("resetsAt"))
                    self._log_once(
                        "over-quota",
                        "monthly event quota reached; pausing until the window resets. "
                        "Dropped events are counted and shown on your realuptime Errors dashboard.",
                    )
                    return
                continue

            reason = body.get("reason")
            if status == 403 and reason == "key_revoked":
                with self._lock:
                    self._disabled = True
                self._log_once(
                    "revoked",
                    "this project's ingest key was revoked; error reporting is disabled for this process. "
                    "Rotate the key in realuptime Errors settings and redeploy with the new DSN.",
                )
                return
            if status == 429 and reason == "over_quota":
                with self._lock:
                    del self._events[: len(events)]
                self._pause_until(body.get("resetsAt"))
                self._log_once(
                    "over-quota",
                    "monthly event quota reached; pausing until the window resets. "
                    "Dropped events are counted and shown on your realuptime Errors dashboard.",
                )
                return
            if status == 400:
                with self._lock:
                    del self._events[: len(events)]
                    self._dropped_since_report += dropped_client
                self._log_once(
                    "malformed",
                    "the server refused a batch as malformed: %s. This is an SDK bug worth reporting."
                    % (body.get("error") or "no detail",),
                )
                continue

            with self._lock:
                self._dropped_since_report += dropped_client
            self._back_off("transient", "ingest endpoint answered %d; buffering and retrying" % status)
            return

    def _pause_until(self, resets_at) -> None:
        parsed = None
        if isinstance(resets_at, str):
            try:
                import datetime

                parsed = datetime.datetime.fromisoformat(resets_at.replace("Z", "+00:00")).timestamp()
            except Exception:
                parsed = None
        with self._lock:
            self._paused_until = parsed if parsed is not None else self._now() + 3600.0

    def _back_off(self, kind: str, message: str) -> None:
        with self._lock:
            self._backoff_s = BACKOFF_START_S if self._backoff_s <= 0 else min(self._backoff_s * 2, BACKOFF_MAX_S)
            self._next_attempt_at = self._now() + self._backoff_s
        self._log_once(kind, message + " (backing off).")


class _State:
    def __init__(self, dsn, release, environment, allow_fields, transport):
        self.dsn = dsn
        self.release = release
        self.environment = environment
        self.allow_fields = allow_fields
        self.transport = transport
        # Bounded breadcrumb ring, newest last (Phase 3), plus the honesty
        # counter: how many entries eviction has dropped since init.
        self.breadcrumb_lock = threading.Lock()
        self.breadcrumbs: "list[dict]" = []
        self.breadcrumbs_evicted = 0


_state: "_State | None" = None
_hook_installed = False
_previous_excepthook = None


def init(dsn, release=None, environment=None, allow_fields=None, capture_unhandled=True, _opener=None, _now=None, _log=None):
    """Initializes the SDK. Safe to call twice (last call wins); a missing
    DSN logs once and stays inert. Never raises."""
    global _state
    try:
        if not dsn or not isinstance(dsn, str):
            print("[realuptime-errors] init called without a dsn; error reporting is disabled.", file=sys.stderr)
            return
        transport = _Transport(dsn, opener=_opener, now=_now, log=_log)
        _state = _State(dsn, release, environment, list(allow_fields or []), transport)
        if capture_unhandled:
            _install_excepthook()
    except Exception as failure:
        try:
            print("[realuptime-errors] init failed: %r" % (failure,), file=sys.stderr)
        except Exception:
            pass


def _install_excepthook():
    global _hook_installed, _previous_excepthook
    if _hook_installed:
        return
    _previous_excepthook = sys.excepthook

    def hook(exc_type, exc, tb):
        try:
            capture_exception(exc)
            flush()
        except Exception:
            pass
        if _previous_excepthook:
            _previous_excepthook(exc_type, exc, tb)

    sys.excepthook = hook
    _hook_installed = True


def add_breadcrumb(message, category=None, data=None):
    """Records one breadcrumb onto the bounded trail (Phase 3). The trail
    rides the NEXT captured event, newest last, at most
    MAX_BREADCRUMBS_PER_EVENT; older entries are evicted and the eviction
    count rides the event as breadcrumbsDropped, so a truncated trail is
    never presented as the whole story. Never raises."""
    try:
        state = _state
        if state is None or not isinstance(message, str):
            return
        crumb_data = None
        if isinstance(data, dict):
            crumb_data = {}
            for name, value in list(data.items())[:MAX_BREADCRUMB_DATA_ENTRIES]:
                if isinstance(value, str):
                    crumb_data[_clip(str(name), MAX_STRING_LENGTH)] = _clip(value, MAX_STRING_LENGTH)
        now = state.transport._now()
        crumb = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + ".000Z",
            "category": _clip(category, 100) if isinstance(category, str) else None,
            "message": _clip(message, MAX_STRING_LENGTH),
            "data": crumb_data,
        }
        with state.breadcrumb_lock:
            state.breadcrumbs.append(crumb)
            if len(state.breadcrumbs) > MAX_BREADCRUMBS_PER_EVENT:
                state.breadcrumbs.pop(0)
                state.breadcrumbs_evicted += 1
    except Exception:
        pass


def _build_event(message, exception_type, frames, request=None, fingerprint=None, release=None, environment=None):
    state = _state
    now = state.transport._now() if state else time.time()
    breadcrumbs = None
    breadcrumbs_dropped = 0
    if state is not None:
        with state.breadcrumb_lock:
            if state.breadcrumbs:
                breadcrumbs = list(state.breadcrumbs)
            breadcrumbs_dropped = state.breadcrumbs_evicted
    return {
        "occurredAt": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + ".000Z",
        "message": _clip(message, MAX_MESSAGE_LENGTH),
        "exceptionType": _clip(exception_type, MAX_STRING_LENGTH) if exception_type else None,
        "release": release or (state.release if state else None),
        "environment": environment or (state.environment if state else None),
        "frames": frames,
        "request": request,
        "fingerprint": fingerprint,
        "breadcrumbs": breadcrumbs,
        "breadcrumbsDropped": breadcrumbs_dropped,
    }


def capture_exception(exc, request=None, fingerprint=None, release=None, environment=None):
    """Reports an exception. Never raises."""
    try:
        state = _state
        if state is None:
            return
        if isinstance(exc, BaseException):
            event = _build_event(
                str(exc) or type(exc).__name__,
                type(exc).__name__,
                _frames_from_exception(exc),
                request=request,
                fingerprint=fingerprint,
                release=release,
                environment=environment,
            )
        else:
            event = _build_event(str(exc), None, None, request=request, fingerprint=fingerprint, release=release, environment=environment)
        state.transport.enqueue(scrub_event(event, state.allow_fields))
    except Exception as failure:
        try:
            print("[realuptime-errors] capture_exception failed: %r" % (failure,), file=sys.stderr)
        except Exception:
            pass


def capture_message(message, request=None, fingerprint=None, release=None, environment=None):
    """Reports a plain message. Never raises."""
    try:
        state = _state
        if state is None:
            return
        event = _build_event(str(message), None, None, request=request, fingerprint=fingerprint, release=release, environment=environment)
        state.transport.enqueue(scrub_event(event, state.allow_fields))
    except Exception:
        pass


def flush():
    """Delivers anything buffered. Never raises."""
    try:
        if _state is not None:
            _state.transport.flush()
    except Exception:
        pass


def _close():
    """Test seam: drops state and restores the excepthook."""
    global _state, _hook_installed
    _state = None
    if _hook_installed and _previous_excepthook is not None:
        sys.excepthook = _previous_excepthook
        _hook_installed = False


class WsgiMiddleware:
    """Captures unhandled exceptions from a WSGI app, with the default
    minimal request context (method, path; status is unknown mid-flight and
    omitted rather than guessed). Re-raises: the middleware reports, the
    server keeps deciding what a 500 looks like."""

    def __init__(self, app):
        self._app = app

    def __call__(self, environ, start_response):
        try:
            return self._app(environ, start_response)
        except Exception as exc:
            try:
                request = {
                    "method": environ.get("REQUEST_METHOD"),
                    "path": environ.get("PATH_INFO"),
                }
                capture_exception(exc, request=request)
            except Exception:
                pass
            raise


class AsgiMiddleware:
    """ASGI counterpart of WsgiMiddleware, http scope only."""

    def __init__(self, app):
        self._app = app

    async def __call__(self, scope, receive, send):
        try:
            await self._app(scope, receive, send)
        except Exception as exc:
            try:
                if scope.get("type") == "http":
                    request = {"method": scope.get("method"), "path": scope.get("path")}
                    capture_exception(exc, request=request)
                else:
                    capture_exception(exc)
            except Exception:
                pass
            raise
