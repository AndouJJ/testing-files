---
name: Arkime Analyzer project
description: Web-based Arkime network traffic analysis tool; single-file Python app with field analysis and port anomaly scan features
type: project
---

Arkime Analyzer v3 — repo at github.com/AndouJJ/testing-files.

**Why:** Tool for analysing network traffic from a separately hosted Arkime instance (port 8005) without manually clicking through results.

**Key files:**
- `arkime_web.py` — entire app, single file, stdlib only. Run with `python arkime_web.py`, opens at http://localhost:8080
- `integration_test.py` — integration tests
- `port_scan_tests.py` — port anomaly scan tests

**Arkime server details:**
- Hosted on port 8005
- Uses **HTTP Digest authentication** (not Basic) — confirmed via curl returning `WWW-Authenticate: Digest`
- Browser login works fine; the tool needed Digest auth support added

**Change made (Digest auth fix):**
- `_get()` in `arkime_web.py` now has a Digest auth code path using `urllib.request.HTTPDigestAuthHandler`
- Added "Digest — username / password" option to the auth type dropdown in the UI
- `toggleAuth()` updated to show username/password fields for both Basic and Digest

**How to apply:** When working on this project, remember the Arkime server requires Digest auth. Any new API calls made by the tool must go through `_get()` which already handles this — do not add raw `urlopen` calls that bypass it.
