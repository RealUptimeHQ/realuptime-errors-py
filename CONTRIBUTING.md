# Contributing

This repository is a read-only mirror: development happens in RealUptime's
private repository, and each release is exported here from the real source,
tests included. That has two practical consequences:

- **Issues are welcome.** Bug reports and feature requests filed here are
  read and triaged like any other support channel. A good bug report names
  the SDK version, the Python version, what you expected and what
  happened, and a minimal way to reproduce it, with secrets removed.
- **Pull requests cannot be merged directly.** A maintainer will re-apply an
  accepted change in the source repository crediting you, and it will appear
  here in the next mirror publish. Small patches are genuinely easier to
  land than large ones.

Security problems are not reported in public issues; see
[SECURITY.md](SECURITY.md).

## Tests

New functionality and bug fixes are expected to come with a test in the same
change, and no change lands unless the whole suite passes; the suite is the one in this
repository, run by RealUptime's merge gate before anything is published
here. If you propose a patch, include the test that fails without it.

Run the test suite (Python 3, no test dependencies):

```bash
python3 -m unittest discover -s tests
```

