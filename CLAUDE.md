# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Luxray is a single-file web application for analyzing network traffic from Arkime (formerly Moloch). It identifies anomalies and patterns without manual inspection of thousands of results.

**Constraint: Python stdlib only** - No third-party libraries. All HTTP handling, JSON parsing, SSL, threading, and the web server use only Python standard library modules.

## Running the Application

```bash
python arkime_web.py                    # Start server, auto-opens browser at localhost:8080
python arkime_web.py --port 9090        # Different port
python arkime_web.py --host 0.0.0.0     # Bind all interfaces (Docker)
python arkime_web.py --no-browser       # Don't auto-open browser
python arkime_web.py --dev              # Load index.html from disk for UI development
```

Stop with Ctrl+C. No build step required.

## Architecture

The entire application lives in `arkime_web.py` (~6500 lines). It's organized into clearly marked sections:

| Lines | Section | Purpose |
|-------|---------|---------|
| 63-240 | Arkime API layer | `_get()`, `_post_with_session()` for Arkime communication, auth handling (Basic/Digest/API key), SSL context |
| 280-392 | Field analysis | `do_analyze()` - parallel field queries using ThreadPoolExecutor |
| 422-506 | Correlation/Sessions | `do_correlate()`, `do_sessions()` - drilldown into specific values |
| 513-556 | Anomaly hints | `do_anomaly_hints()` - source IP concentration for rare values |
| 575-1765 | Port mappings | 400+ port-to-protocol mappings from IANA/nDPI/Wikipedia, loaded from inline data |
| 1786-2345 | Port scan modes | Four detection modes: sig-to-port, port-to-sig, host-diversity, byte-pattern |
| 2353-2505 | Baseline management | Save/compare "normal" traffic snapshots |
| 2510-2600 | Settings persistence | Atomic JSON writes to `arkime_settings.json` |
| 2604-2658 | Cache | In-memory TTL cache for Arkime responses (5 min default) |
| 2667-5851 | Embedded UI | Full HTML/CSS/JS as Python string literal |
| 6090-6460 | HTTP handler | `Handler` class with routing for all `/api/*` endpoints |
| 6469+ | Entry point | `main()` with argument parsing |

## Key Patterns

**API endpoints** follow the pattern `do_<action>(cfg)` where `cfg` is a dict from the JSON request body. The Handler routes POST requests to these functions.

**SSE streaming** is used for long-running operations (`/api/analyze-stream`, `/api/port-scan-stream`) to provide progress updates.

**CSRF protection**: All mutating POST endpoints (except `/api/test`) require `X-CSRF-Token` header matching `CSRF_TOKEN` generated at startup.

**Settings file**: `arkime_settings.json` stores presets, baselines, allowlists, and UI state (never passwords). Uses atomic writes via temp file + rename.

## Port Scan Modes

1. **sig_to_port**: Signature (JA3/UA) appearing on unexpected ports
2. **port_to_sig**: Known port carrying unexpected protocol
3. **host_diversity**: Single host hitting many destination ports (scanner/beacon)
4. **byte_pattern**: Raw payload hex/ASCII patterns on unexpected ports (uses Arkime Hunt API)

## Data Files

- `arkime_settings.json` - User configuration, presets, baselines (auto-generated)
- `service-names-port-numbers.csv` - IANA port registry reference (not loaded at runtime; port mappings are inline)
