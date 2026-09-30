# Contributing to TinyWatch

TinyWatch keeps its runtime intentionally small: the application, HTTP API, collectors, and embedded browser UI live in `tinywatch.py` and use only Python's standard library. Tests and project documentation are separate development files and do not add runtime dependencies.

## Development setup

Use Python 3.10 or newer. No package installation or frontend build is required.

```bash
python -m py_compile tinywatch.py
python -m unittest discover -s tests -v
python scripts/check_inline_js.py
```

The Python checks use only the standard library. The embedded UI check uses Node.js 20 to parse the inline script and verify that chart downsampling preserves peaks and collection-gap boundaries; Node is a development tool and is not needed to run TinyWatch. GitHub Actions runs all checks on Linux, Windows, and macOS with Python 3.10 and 3.12. Keep regression tests self-contained; do not add remote assets, real credentials, or host-specific assumptions.

## Change guidelines

- Keep monitoring data collection best-effort and report unavailable platform capabilities clearly.
- Isolate collector errors so one unavailable subsystem does not fail a complete host snapshot; avoid writing fabricated zero values to history for failed collectors.
- Keep history sampling independent of authenticated browser polling and retain a bounded cache for remote node snapshots.
- Keep chart and UI assets embedded. Do not add CDN scripts, remote fonts, or external stylesheets.
- Preserve backward compatibility for the JSON schema, or include an explicit recovery/migration path.
- Never log passwords, session cookies, or agent tokens. Remote agent credentials must only be sent over verified HTTPS, except to loopback.
- Keep changes focused, document user-visible behavior, and add regression coverage for persistence and security-sensitive paths.
- Run the syntax and unit checks above before opening a pull request. Include the operating system and Python version if a failure is platform-specific.

## Pull requests

Describe the user-visible change, its platform impact, and the verification performed. Do not include real host names, database files, tokens, or screenshots containing private infrastructure details.
