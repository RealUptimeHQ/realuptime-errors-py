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
import platform
import re
import sys
import threading
import time
import urllib.error
import urllib.request

SDK_NAME = "realuptime-errors-py"
SDK_VERSION = "0.4.0"

# Mirrored from packages/errors-js/types.ts and pinned by
# tests/test_wire_contract.py.
MAX_EVENTS_PER_BATCH = 50
MAX_MESSAGE_LENGTH = 4000
MAX_FRAMES_PER_EVENT = 50
MAX_STRING_LENGTH = 512
MAX_BREADCRUMBS_PER_EVENT = 20
MAX_BREADCRUMB_DATA_ENTRIES = 10
BUFFER_MAX = 200

# v2 caps (REA-182), mirrored from packages/errors-js/types.ts.
MAX_TAGS_PER_EVENT = 20
MAX_CONTEXT_ENTRIES = 20
MAX_CONTEXT_KEY_LENGTH = 64
MAX_LOCAL_VARS_PER_FRAME = 20
MAX_LOCAL_VAR_LENGTH = 256

# Context lines captured either side of each frame's own line (Phase 3:
# "Python symbolication depth" -- Python needs no source maps; the depth is
# real source context read IN the customer's process, where the source is).
CONTEXT_LINES = 3

SEND_TIMEOUT_S = 10.0
BACKOFF_START_S = 5.0
BACKOFF_MAX_S = 300.0

SCRUBBED = "[scrubbed]"

_REMOVED_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie"}

# v2 (REA-182): identity fields removed whole unless allow-listed by these
# exact dotted names. "user.id" is deliberately absent -- an opaque
# identifier in the customer's own key space is the field that makes "how
# many users hit this" answerable, and it is not contact data.
_REMOVED_USER_FIELDS = ("user.email", "user.username")

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


def _scrub_string_map(value):
    """v2: a flat string map (tags, custom context, device, frame locals).
    Values pass the pattern rules; KEYS are left alone -- a key is a label
    the integrator chose, and scrubbing it would make an issue's tag filter
    depend on whether the value beside it looked like a card number."""
    if not isinstance(value, dict):
        return value
    return {name: scrub_string(entry) if isinstance(entry, str) else entry for name, entry in value.items()}


def _scrub_user(user, allowed):
    """v2: `id` passes the pattern rules; `email` and `username` are removed
    whole unless the customer opted that exact dotted name in. An opted-in
    value still passes the pattern rules, so opting one back in can never
    smuggle a raw token through."""
    if not isinstance(user, dict):
        return user
    out = dict(user)
    if isinstance(out.get("id"), str):
        out["id"] = scrub_string(out["id"])
    for field in _REMOVED_USER_FIELDS:
        key = field[len("user.") :]
        value = out.get(key)
        if not isinstance(value, str):
            continue
        out[key] = scrub_string(value) if field in allowed else SCRUBBED
    return out


def _scrub_frame_context(frame: dict) -> dict:
    if not isinstance(frame, dict):
        return frame
    if not (
        frame.get("contextLine")
        or frame.get("preContext")
        or frame.get("postContext")
        or frame.get("vars")
    ):
        return frame
    out = dict(frame)
    if isinstance(out.get("contextLine"), str):
        out["contextLine"] = scrub_string(out["contextLine"])
    for key in ("preContext", "postContext"):
        lines = out.get(key)
        if isinstance(lines, list):
            out[key] = [scrub_string(line) if isinstance(line, str) else line for line in lines]
    if isinstance(out.get("vars"), dict):
        out["vars"] = _scrub_string_map(out["vars"])
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
    for key in ("tags", "context", "device"):
        if isinstance(out.get(key), dict):
            out[key] = _scrub_string_map(out[key])
    if isinstance(out.get("user"), dict):
        out["user"] = _scrub_user(out["user"], allowed)
    request = out.get("request")
    if isinstance(request, dict):
        request = dict(request)
        if isinstance(request.get("path"), str):
            request["path"] = scrub_string(request["path"])
        if isinstance(request.get("route"), str):
            request["route"] = scrub_string(request["route"])
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


# ---------------------------------------------------------------------------
# REA-264: customer-defined ADDITIONAL scrub rules. Mirrors
# packages/db/error-scrub-rules.ts and packages/errors-js/custom-scrub.ts;
# packages/errors-js/custom-scrub-vectors.json pins the three to identical
# output (tests/test_custom_scrub.py). Applied AFTER scrub_event, never
# instead of it: nothing here can relax a default. Rules arrive from the
# project's settings via GET /api/errors/v1/scrub-rules/<key> at init, or
# inline through init(scrub_rules=[...]); either way they only add.
# ---------------------------------------------------------------------------

CUSTOM_SCRUB_RULE_KINDS = ("field_name", "key_glob", "value_regex")
MAX_CUSTOM_SCRUB_RULES = 50
MAX_CUSTOM_SCRUB_PATTERN_LENGTH = 200
SCRUB_RULES_TIMEOUT_S = 5.0
_EMPTY_CUSTOM_SCRUB = {"names": frozenset(), "globs": (), "values": (), "count": 0}


def _glob_to_regex(glob: str) -> "re.Pattern[str]":
    out = "^"
    for ch in glob:
        if ch == "*":
            out += ".*"
        elif ch == "?":
            out += "."
        else:
            out += re.escape(ch)
    return re.compile(out + "$", re.IGNORECASE)


def validate_custom_scrub_rule(rule) -> bool:
    """The server validates every rule it stores with the full safe-subset
    check (no lookaround, backreferences, nested quantifiers, large repeats);
    this SDK only ever receives rules that passed it, so it carries the cheap
    half: shape, bounds, engine-portable syntax, compiles, non-empty match.
    Anything failing is skipped, never raised on."""
    if not isinstance(rule, dict):
        return False
    kind = rule.get("kind")
    pattern = rule.get("pattern")
    if kind not in CUSTOM_SCRUB_RULE_KINDS or not isinstance(pattern, str):
        return False
    if not pattern.strip() or len(pattern) > MAX_CUSTOM_SCRUB_PATTERN_LENGTH or "\n" in pattern or "\r" in pattern:
        return False
    if kind in ("field_name", "key_glob"):
        if pattern != pattern.strip():
            return False
        has_wildcard = "*" in pattern or "?" in pattern
        return has_wildcard if kind == "key_glob" else not has_wildcard
    # value_regex: portability guards the server also applies.
    if re.search(r"(?<!\\)\(\?(?!:)", pattern):
        return False
    if re.search(r"\\[1-9kpPuc]", pattern):
        return False
    try:
        compiled = re.compile(pattern)
    except re.error:
        return False
    return compiled.match("") is None


def compile_custom_scrub_rules(rules) -> dict:
    """Compiles rules, skipping invalid ones. Never raises."""
    names = set()
    globs = []
    values = []
    count = 0
    if not isinstance(rules, (list, tuple)):
        return dict(_EMPTY_CUSTOM_SCRUB)
    for rule in list(rules)[:MAX_CUSTOM_SCRUB_RULES]:
        if not validate_custom_scrub_rule(rule):
            continue
        count += 1
        kind = rule["kind"]
        pattern = rule["pattern"]
        if kind == "field_name":
            names.add(pattern.lower())
        elif kind == "key_glob":
            globs.append(_glob_to_regex(pattern))
        else:
            values.append(re.compile(pattern))
    return {"names": frozenset(names), "globs": tuple(globs), "values": tuple(values), "count": count}


def _custom_matches_key(name: str, compiled: dict) -> bool:
    lower = name.lower()
    if lower in compiled["names"]:
        return True
    for glob in compiled["globs"]:
        if glob.match(lower):
            return True
    return False


def _custom_value(value: str, compiled: dict) -> str:
    out = value
    for pattern in compiled["values"]:
        out = pattern.sub(SCRUBBED, out)
    return out


def _custom_entry(name: str, value: str, compiled: dict) -> str:
    if _custom_matches_key(name, compiled):
        return SCRUBBED
    return _custom_value(value, compiled)


def _custom_map(mapping, compiled: dict, prefix: str = ""):
    if not isinstance(mapping, dict):
        return mapping
    return {
        name: _custom_entry(prefix + name, value, compiled) if isinstance(value, str) else value
        for name, value in mapping.items()
    }


def apply_custom_scrub_rules(event: dict, compiled: dict) -> dict:
    """Applies compiled rules to an event that has ALREADY been through
    scrub_event. Returns a new dict; never mutates the input."""
    if not compiled or compiled.get("count", 0) == 0:
        return event
    out = dict(event)
    if isinstance(out.get("message"), str):
        out["message"] = _custom_value(out["message"], compiled)
    request = out.get("request")
    if isinstance(request, dict):
        request = dict(request)
        for key in ("path", "route"):
            if isinstance(request.get(key), str):
                request[key] = _custom_value(request[key], compiled)
        if isinstance(request.get("headers"), dict):
            request["headers"] = _custom_map(request["headers"], compiled)
        out["request"] = request
    breadcrumbs = out.get("breadcrumbs")
    if isinstance(breadcrumbs, list):
        next_crumbs = []
        for crumb in breadcrumbs:
            if not isinstance(crumb, dict):
                next_crumbs.append(crumb)
                continue
            c = dict(crumb)
            if isinstance(c.get("message"), str):
                c["message"] = _custom_value(c["message"], compiled)
            if isinstance(c.get("data"), dict):
                c["data"] = _custom_map(c["data"], compiled)
            next_crumbs.append(c)
        out["breadcrumbs"] = next_crumbs
    frames = out.get("frames")
    if isinstance(frames, list):
        next_frames = []
        for frame in frames:
            if not isinstance(frame, dict) or not (
                frame.get("contextLine") or frame.get("preContext") or frame.get("postContext") or frame.get("vars")
            ):
                next_frames.append(frame)
                continue
            f = dict(frame)
            if isinstance(f.get("contextLine"), str):
                f["contextLine"] = _custom_value(f["contextLine"], compiled)
            for key in ("preContext", "postContext"):
                if isinstance(f.get(key), list):
                    f[key] = [_custom_value(line, compiled) if isinstance(line, str) else line for line in f[key]]
            if isinstance(f.get("vars"), dict):
                f["vars"] = _custom_map(f["vars"], compiled)
            next_frames.append(f)
        out["frames"] = next_frames
    if isinstance(out.get("user"), dict):
        out["user"] = _custom_map(out["user"], compiled, "user.")
    for key in ("tags", "context", "device"):
        if isinstance(out.get(key), dict):
            out[key] = _custom_map(out[key], compiled)
    return out


def scrub_rules_url_for(dsn: str):
    """The rules endpoint for a DSN, or None for a DSN that is not
    ingest-shaped (no fetch is attempted then)."""
    marker = "/api/errors/v1/ingest/"
    at = dsn.find(marker)
    if at == -1:
        return None
    return dsn[:at] + "/api/errors/v1/scrub-rules/" + dsn[at + len(marker):]


def _http_get(url: str):
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=SCRUB_RULES_TIMEOUT_S) as res:
            return res.status, res.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


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


def _local_vars(frame_obj) -> dict:
    """v2 (REA-182): this frame's locals, stringified, bounded hard.

    OFF BY DEFAULT (init(include_local_variables=True) turns it on), because
    locals are the leakiest thing an error tracker can capture: the variable
    holding the password is, definitionally, in scope at the frame that
    failed to use it. The values pass the pattern scrub with everything
    else, but a regex net is not a guarantee, which is why the switch
    defaults to off rather than to "trust the patterns".

    Bounds: MAX_LOCAL_VARS_PER_FRAME entries, MAX_LOCAL_VAR_LENGTH
    characters each. Dunder names are skipped (they are interpreter
    bookkeeping, never the customer's data). A value whose repr() raises is
    reported as <unrepresentable> rather than swallowing the whole frame."""
    out = {}
    try:
        for name, value in list(frame_obj.f_locals.items()):
            if len(out) >= MAX_LOCAL_VARS_PER_FRAME:
                break
            if not isinstance(name, str) or name.startswith("__"):
                continue
            try:
                text = repr(value)
            except Exception:
                text = "<unrepresentable>"
            out[_clip(name, MAX_CONTEXT_KEY_LENGTH)] = _clip(text, MAX_LOCAL_VAR_LENGTH)
    except Exception:
        return {}
    return out


def _frames_from_exception(exc: BaseException, include_locals: bool = False) -> "list[dict] | None":
    """Walks the traceback directly rather than via traceback.extract_tb, so
    each wire frame can be paired with its own frame OBJECT when local-
    variable capture is on. The file/function/line values are identical to
    what extract_tb produced before (same co_filename, co_name, tb_lineno)."""
    frames = []
    tb = exc.__traceback__
    while tb is not None:
        frame_obj = tb.tb_frame
        filename = frame_obj.f_code.co_filename or ""
        name = frame_obj.f_code.co_name
        lineno = tb.tb_lineno
        in_app = "site-packages" not in filename and "dist-packages" not in filename and not filename.startswith("<")
        entry = {
            "file": _clip(filename, MAX_STRING_LENGTH),
            "function": _clip(name, MAX_STRING_LENGTH) if name else None,
            "line": lineno,
            "inApp": in_app,
        }
        entry.update(_source_context(filename, lineno))
        if include_locals:
            captured = _local_vars(frame_obj)
            if captured:
                entry["vars"] = captured
        frames.append(entry)
        if len(frames) >= MAX_FRAMES_PER_EVENT:
            break
        tb = tb.tb_next
    # Innermost first on the wire, matching the JS SDK's stack order.
    frames.reverse()
    return frames or None


def _detect_device() -> "dict | None":
    """v2: the runtime facts, read out of this process. Never the hostname,
    the local IP or a container id: those identify a MACHINE rather than a
    runtime and add nothing `release` + `environment` does not already say."""
    try:
        info = sys.version_info
        device = {
            "runtime": "python",
            "runtimeVersion": "%d.%d.%d" % (info[0], info[1], info[2]),
            "platform": _clip(str(sys.platform), MAX_STRING_LENGTH),
        }
        try:
            machine = platform.machine()
            if machine:
                device["arch"] = _clip(str(machine), MAX_STRING_LENGTH)
        except Exception:
            pass
        return device
    except Exception:
        return None


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
    def __init__(self, dsn, release, environment, allow_fields, transport, device=None, include_local_variables=False):
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
        # v2 scope (REA-182): sticky identity, tags and context applied to
        # every subsequent event. Bounded at WRITE time so a long-lived
        # process's scope cannot grow without limit.
        self.scope_lock = threading.Lock()
        self.user: "dict | None" = None
        self.tags: "dict[str, str]" = {}
        self.context: "dict[str, str]" = {}
        self.device = device
        self.include_local_variables = include_local_variables
        # REA-264: compiled additional rules; inline ones now, the project's
        # fetched ones once the background GET lands.
        self.custom_scrub = dict(_EMPTY_CUSTOM_SCRUB)
        self._inline_scrub_rules: "list" = []


_state: "_State | None" = None
_hook_installed = False
_previous_excepthook = None


def init(
    dsn,
    release=None,
    environment=None,
    allow_fields=None,
    capture_unhandled=True,
    send_device_info=True,
    include_local_variables=False,
    scrub_rules=None,
    fetch_scrub_rules=True,
    _opener=None,
    _now=None,
    _log=None,
    _rules_fetcher=None,
):
    """Initializes the SDK. Safe to call twice (last call wins); a missing
    DSN logs once and stays inert. Never raises.

    v2 (REA-182) options:

      allow_fields            adds the dotted identity names "user.email"
                              and "user.username" to the existing per-field
                              header opt-back-in. Never a global switch.
      send_device_info        runtime/platform facts about THIS process
                              (never hostname or IP). Default on.
      include_local_variables per-frame locals. Default OFF, hard-capped
                              when on; see _local_vars for why.

    REA-264 options:

      scrub_rules             ADDITIONAL scrub rules for this process, each
                              {"kind": "field_name"|"key_glob"|"value_regex",
                              "pattern": ...}, applied after the defaults. An
                              invalid one is skipped. Nothing relaxes a
                              default.
      fetch_scrub_rules       fetch the project's additional rules (set in
                              realuptime Errors settings) once, in a daemon
                              thread, and apply them client-side too. Default
                              True. Fails open to the defaults; the server
                              applies the same rules at ingest regardless."""
    global _state
    try:
        if not dsn or not isinstance(dsn, str):
            print("[realuptime-errors] init called without a dsn; error reporting is disabled.", file=sys.stderr)
            return
        transport = _Transport(dsn, opener=_opener, now=_now, log=_log)
        _state = _State(
            dsn,
            release,
            environment,
            list(allow_fields or []),
            transport,
            device=_detect_device() if send_device_info else None,
            include_local_variables=bool(include_local_variables),
        )
        _state._inline_scrub_rules = list(scrub_rules or [])
        if scrub_rules:
            _state.custom_scrub = compile_custom_scrub_rules(scrub_rules)
        if capture_unhandled:
            _install_excepthook()
        if fetch_scrub_rules:
            thread = threading.Thread(
                target=_fetch_scrub_rules, args=(_state, _rules_fetcher or _http_get), daemon=True
            )
            thread.start()
    except Exception as failure:
        try:
            print("[realuptime-errors] init failed: %r" % (failure,), file=sys.stderr)
        except Exception:
            pass


def _fetch_scrub_rules(for_state, fetcher):
    """Best-effort, bounded, never raises, never blocks capture: an event
    sent before the response lands gets the defaults plus inline rules here
    and the project's rules at ingest."""
    try:
        url = scrub_rules_url_for(for_state.dsn)
        if not url:
            return
        status, body = fetcher(url)
        if status != 200:
            return
        parsed = json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
        rules = parsed.get("rules") if isinstance(parsed, dict) else None
        if not isinstance(rules, list):
            return
        # init may have been called again while this was in flight; only the
        # state this fetch was started for is updated.
        if _state is not for_state:
            return
        for_state.custom_scrub = compile_custom_scrub_rules(list(for_state._inline_scrub_rules) + rules)
    except Exception:
        # Fail open to the defaults. Silent by design; the server still
        # applies them.
        pass


def _scrub_for(state, event: dict) -> dict:
    """Defaults first, always; the customer's additional rules on the result."""
    return apply_custom_scrub_rules(scrub_event(event, state.allow_fields), state.custom_scrub)


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


def set_user(user):
    """v2 (REA-182): sets the sticky identity applied to every subsequent
    event. None clears it (sign-out).

    Only id / email / username are carried; anything else on the mapping is
    ignored rather than forwarded, so handing this the whole user record
    does not ship its address book. email and username are "[scrubbed]"
    before serialization unless the matching allow_fields entry is set.
    Never raises."""
    try:
        state = _state
        if state is None:
            return
        if not isinstance(user, dict):
            with state.scope_lock:
                state.user = None
            return
        next_user = {}
        for key in ("id", "email", "username"):
            value = user.get(key)
            if isinstance(value, str):
                next_user[key] = _clip(value, MAX_STRING_LENGTH)
        with state.scope_lock:
            state.user = next_user or None
    except Exception:
        pass


def set_tag(key, value):
    """v2: sets one sticky tag; a None value removes it. Tags past
    MAX_TAGS_PER_EVENT are ignored rather than evicting an existing one --
    silently replacing what the integrator set earlier is the worse
    surprise. Never raises."""
    try:
        state = _state
        if state is None or not isinstance(key, str) or not key:
            return
        name = _clip(key, MAX_CONTEXT_KEY_LENGTH)
        with state.scope_lock:
            if value is None:
                state.tags.pop(name, None)
                return
            if not isinstance(value, str):
                return
            if name not in state.tags and len(state.tags) >= MAX_TAGS_PER_EVENT:
                return
            state.tags[name] = _clip(value, MAX_STRING_LENGTH)
    except Exception:
        pass


def set_tags(tags):
    """v2: merges several sticky tags at once. Never raises."""
    try:
        if not isinstance(tags, dict):
            return
        for name, value in tags.items():
            set_tag(name, value)
    except Exception:
        pass


def set_context(key, value=None):
    """v2: sets one sticky custom-context entry, or merges a whole mapping:

        set_context("tenant", "acme")
        set_context({"tenant": "acme", "shard": "eu-1"})

    A None value removes the named entry; set_context(None) clears the whole
    context. Never raises."""
    try:
        state = _state
        if state is None:
            return
        if key is None:
            with state.scope_lock:
                state.context = {}
            return
        if isinstance(key, dict):
            for name, entry in key.items():
                set_context(name, entry)
            return
        if not isinstance(key, str) or not key:
            return
        name = _clip(key, MAX_CONTEXT_KEY_LENGTH)
        with state.scope_lock:
            if value is None:
                state.context.pop(name, None)
                return
            if not isinstance(value, str):
                return
            if name not in state.context and len(state.context) >= MAX_CONTEXT_ENTRIES:
                return
            state.context[name] = _clip(value, MAX_STRING_LENGTH)
    except Exception:
        pass


def _bounded_map(value, limit):
    """Bounds a caller-supplied per-capture override the same way the sticky
    setters bound the scope."""
    out = {}
    if not isinstance(value, dict):
        return out
    for name, entry in value.items():
        if len(out) >= limit:
            break
        if not isinstance(name, str) or not name or not isinstance(entry, str):
            continue
        out[_clip(name, MAX_CONTEXT_KEY_LENGTH)] = _clip(entry, MAX_STRING_LENGTH)
    return out


def _build_event(
    message,
    exception_type,
    frames,
    request=None,
    fingerprint=None,
    release=None,
    environment=None,
    user=None,
    tags=None,
    context=None,
):
    state = _state
    now = state.transport._now() if state else time.time()
    breadcrumbs = None
    breadcrumbs_dropped = 0
    scope_user = None
    scope_tags = {}
    scope_context = {}
    device = None
    if state is not None:
        with state.breadcrumb_lock:
            if state.breadcrumbs:
                breadcrumbs = list(state.breadcrumbs)
            breadcrumbs_dropped = state.breadcrumbs_evicted
        with state.scope_lock:
            scope_user = dict(state.user) if state.user else None
            scope_tags = dict(state.tags)
            scope_context = dict(state.context)
            device = dict(state.device) if state.device else None
    event = {
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
    # v2 fields are emitted only when NON-EMPTY, so an integration that
    # never touches the v2 API keeps producing byte-identical v1 payloads.
    merged_user = scope_user
    if isinstance(user, dict):
        merged_user = dict(scope_user or {})
        merged_user.update({k: v for k, v in user.items() if k in ("id", "email", "username")})
    if merged_user:
        event["user"] = merged_user
    merged_tags = dict(scope_tags)
    merged_tags.update(_bounded_map(tags, MAX_TAGS_PER_EVENT))
    if merged_tags:
        event["tags"] = merged_tags
    merged_context = dict(scope_context)
    merged_context.update(_bounded_map(context, MAX_CONTEXT_ENTRIES))
    if merged_context:
        event["context"] = merged_context
    if device:
        event["device"] = device
    return event


def capture_exception(exc, request=None, fingerprint=None, release=None, environment=None, user=None, tags=None, context=None):
    """Reports an exception. Never raises.

    v2: user / tags / context are per-capture overrides merged OVER the
    sticky scope set by set_user / set_tag / set_context."""
    try:
        state = _state
        if state is None:
            return
        extra = {"user": user, "tags": tags, "context": context}
        if isinstance(exc, BaseException):
            event = _build_event(
                str(exc) or type(exc).__name__,
                type(exc).__name__,
                _frames_from_exception(exc, include_locals=state.include_local_variables),
                request=request,
                fingerprint=fingerprint,
                release=release,
                environment=environment,
                **extra,
            )
        else:
            event = _build_event(
                str(exc), None, None, request=request, fingerprint=fingerprint, release=release, environment=environment, **extra
            )
        state.transport.enqueue(_scrub_for(state, event))
    except Exception as failure:
        try:
            print("[realuptime-errors] capture_exception failed: %r" % (failure,), file=sys.stderr)
        except Exception:
            pass


def capture_message(message, request=None, fingerprint=None, release=None, environment=None, user=None, tags=None, context=None):
    """Reports a plain message. Never raises."""
    try:
        state = _state
        if state is None:
            return
        event = _build_event(
            str(message),
            None,
            None,
            request=request,
            fingerprint=fingerprint,
            release=release,
            environment=environment,
            user=user,
            tags=tags,
            context=context,
        )
        state.transport.enqueue(_scrub_for(state, event))
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
