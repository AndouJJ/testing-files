# Luxray

A web-based tool for analyzing network traffic captured by [Arkime](https://arkime.com/) (formerly Moloch). Automates the process of finding anomalies and interesting patterns without manually clicking through thousands of results.

## Features

### Field Analysis
- Displays the most common and rare values for selected fields
- Anomaly hints and one-click drilldowns
- Bulk investigation with correlation and session views
- Customizable allowlists with wildcard support

### Port Anomaly Scan
Four detection modes:

1. **Signature on Unexpected Port** - Finds traffic where application signatures (JA3, user agents) appear on unusual ports
2. **Unexpected Protocol on Known Port** - Detects non-standard protocols on well-known ports (e.g., non-DNS on port 53)
3. **Host Using Many Ports** - Identifies hosts scanning or beaconing across many destination ports
4. **Byte Pattern on Unexpected Port** - Searches raw packet payloads for hex or ASCII patterns using Arkime's Hunt API and flags when patterns appear on unexpected ports. Example patterns:
   - `160303` (hex) - TLS 1.2/1.3 handshake, expected on port 443
   - `SSH-2.0` (ASCII) - SSH banner, expected on port 22
   - `4d5a` (hex) - Windows executable (MZ header), suspicious on any port

### Additional Features
- Named presets for saving configurations
- Baseline comparisons for detecting changes from "normal"
- Dark mode
- CSV and JSON export
- Results caching

## Requirements

- Python 3.x (no external dependencies - stdlib only)
- Access to an Arkime server

## Quick Start

```bash
python arkime_web.py
```

Your browser will open automatically at `http://localhost:8080`.

### Options

| Flag | Description |
|------|-------------|
| `--port 9090` | Use a different port |
| `--host 0.0.0.0` | Bind to all interfaces (useful in Docker) |
| `--no-browser` | Don't auto-open the browser |
| `--dev` | Load index.html from disk (for UI development) |

## Usage

1. Enter your Arkime server URL and credentials
2. Click **Test Connection** to verify
3. Set your time range
4. Select fields to analyze (defaults: `port.dst`, `port.src`, `http.useragent`, `http.uri`)
5. Click **Run Analysis**

For detailed usage instructions, see [HOW_TO_USE.txt](HOW_TO_USE.txt).

## Files

| File | Description |
|------|-------------|
| `arkime_web.py` | Main application |
| `integration_test.py` | Integration tests |
| `port_scan_tests.py` | Port scan feature tests |
| `HOW_TO_USE.txt` | Detailed usage guide |

## License

This project is provided as-is for network security analysis purposes.
