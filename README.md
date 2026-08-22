# realuptime-errors

Zero-dependency error tracking SDK for Python (WSGI/ASGI middleware plus
manual capture): part of
[RealUptime Errors](https://realuptime.io/error-tracking).

This is a **mirror**. It is published from `packages/errors-py` in the
[realuptime monorepo](https://github.com/RealUptimeHQ/realuptime) by
`scripts/publish-sdk-mirrors.mjs` and is not edited directly; open issues
and PRs against this repo, but expect source changes to land here after
they merge upstream.

## Install

Installs straight from GitHub today. npm and PyPI packages are coming; this note disappears the day they ship.

```bash
pip install "git+https://github.com/RealUptimeHQ/realuptime-errors-py"
```

## Usage

```python
import realuptime_errors

realuptime_errors.init(
    dsn="https://realuptime.io/api/errors/v1/ingest/rue_...",  # from your project's dashboard
    release="v2.4.1",
    environment="production",
)

realuptime_errors.capture_exception(some_exception)
```

WSGI: `app = realuptime_errors.WsgiMiddleware(app)`
ASGI: `app = realuptime_errors.AsgiMiddleware(app)`

## What this SDK actually does

- **Never raises out of a public function.** Every entry point catches
  everything; a broken SDK logs once to stderr (prefixed
  `[realuptime-errors]`) and goes quiet. An error tracker that crashes the
  app it watches is worse than none.
- **Scrubs PII by default, client-side**, before anything serializes:
  `Authorization`/`Proxy-Authorization`/`Cookie`/`Set-Cookie` headers are
  replaced whole; card-shaped digit runs (Luhn-checked), JWTs, prefixed API
  keys, and long hex/base64 runs are pattern-scrubbed anywhere they appear
  in the message, request context, breadcrumbs, or captured source lines.
  Opt one field back in with `allow_fields=["x-request-id"]`; there is no
  global "disable scrubbing" switch, by design.
- **Never silently drops.** The in-memory buffer (200 events) evicts the
  oldest event when full, counts every eviction, and reports the count on
  the next successful batch, so drops show up on your dashboard instead of
  disappearing.
- **Standard library only.** No third-party imports, ever, checked by a
  test in this repo (`tests/test_wire_contract.py`) that scans the source
  for anything outside an explicit allow-list.

## API

| Function | Notes |
| --- | --- |
| `init(dsn, release=None, environment=None, allow_fields=None, capture_unhandled=True)` | Installs a `sys.excepthook` for unhandled exceptions unless `capture_unhandled=False`. Safe to call twice; a missing DSN logs once and stays inert. |
| `capture_exception(exc, request=None, fingerprint=None, release=None, environment=None)` | Reports an exception. |
| `capture_message(message, ...)` | Reports a plain message. |
| `add_breadcrumb(message, category=None, data=None)` | Bounded trail (last 20), rides the next event. |
| `flush()` | Delivers anything buffered. |
| `WsgiMiddleware(app)` / `AsgiMiddleware(app)` | Captures unhandled exceptions with minimal request context (method, path), then re-raises. |

## Version

This mirror tracks SDK_VERSION `0.2.0` in `realuptime_errors.py`, the
string every event actually carries on the wire.

## License

MIT, see [LICENSE](./LICENSE).
