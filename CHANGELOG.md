# Changelog

## 0.4.2 (2026-11-13)


### Bug Fixes

* **errors:** scrub credential values in name=value text and query strings (REA-1260)

## 0.4.1 (2026-11-12)

### Features

* Scrubbing: a case-insensitive key-name denylist (password, secret, token, api key, authorization, credential, private key, access key, session) is applied before the pattern scrub, matching whole camelCase or snake_case segments.
* Scrubbing: new pattern rules for AWS access key ids, Stripe webhook signing secrets and credentials in URL userinfo.
* `init()` rejects a DSN that is not the full ingest URL (a bare key never worked and failed silently), and `is_enabled()` reports whether reporting is on.
* New DSNs name the dedicated intake host, `ingest.realuptime.io`. DSNs already issued keep working.

### Bug Fixes

* The thread that fetches the project's scrub rules is stopped and joined on close and at exit, so a process that calls `init()` repeatedly no longer crashes while the interpreter shuts down.

## 0.4.0 (2026-08-24)

First published release.

### Features

* Error capture with bounded buffering and honest drop counters, standard library only.
* Scrub-by-default for sensitive values before an event leaves the process.
* Wire contract v2: identity, tags, context and device fields.
* Flask, Django, FastAPI and Celery adapters.
* Additive-only custom scrub rules served for the project.
