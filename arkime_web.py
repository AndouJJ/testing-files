#!/usr/bin/env python3
"""
Luxray — Web UI (v3)
====================
Single-file web application. No third-party libraries required (stdlib only).

Run:   python arkime_web.py
Open:  http://localhost:8080   (opens automatically)

Options:
  --port 9090         Use a different port
  --host 0.0.0.0      Bind address (use 0.0.0.0 inside Docker)
  --no-browser        Don't auto-open the browser
  --dev               Load index.html from disk if present (for UI iteration)

What's new in v3:
  - Port anomaly scan with three modes:
      1. Signature -> unexpected port (same JA3/UA on the wrong port)
      2. Known port -> unexpected signature (non-DNS on 53, etc.)
      3. Host -> port diversity (scanner/beacon shape per src IP)
  - Saved baselines (mode 1): snapshot "normal" per-signature port
    distributions and diff future scans against them to detect new
    signatures, new ports on known signatures, and dominance shifts
  - SSE progress streaming for long-running port scans
  - Port chip UI with inline pivot + sessions drilldown
  - Correlate/Sessions modals extended with "pin field" support
  - Shannon entropy + port-share statistics for each signature

What was new in v2:
  - Parallel per-field analysis (ThreadPoolExecutor)
  - Server-Sent Events progress stream during analysis
  - Named presets (save/load/delete full configs)
  - Quick time-range buttons (1h / 4h / 24h / 7d / etc.)
  - Server-side results caching with TTL
  - Bulk-select rows for multi-value correlation / session view
  - Multi-pivot correlation: drill further from inside the modal
  - Sortable tables, per-card value search, one-click allowlist
  - Anomaly hinting (source-IP concentration) for rare-value triage
  - "Download full report" JSON export
  - Session modal: packets, duration, tags, node columns
  - Atomic settings writes, CSRF token, expression-value escaping
"""

import http.server
import json
import urllib.request
import urllib.parse
import urllib.error
import ssl
import base64
import sys
import os
import argparse
import webbrowser
import threading
import secrets
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

_PORTS_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "arkime_ports.json")
try:
    with open(_PORTS_JSON, "r", encoding="utf-8") as _f:
        PORTS_DATA = json.load(_f)
except FileNotFoundError:
    PORTS_DATA = {}


# ==============================================================================
# Utility functions
# ==============================================================================

def _effective_workers(cfg, task_count):
    """
    Calculate optimal worker count based on:
    - User config (max_workers)
    - System capabilities (CPU count)
    - Task count (no point having more workers than tasks)
    """
    cpu_count = os.cpu_count() or 4
    # Default to 2x CPU count for I/O-bound work, capped at 24
    default_workers = min(cpu_count * 2, 24)
    user_max = int(cfg.get("max_workers", default_workers))
    return min(max(1, user_max), task_count)


# ==============================================================================
# Arkime API layer
# ==============================================================================

def _auth_header(cfg):
    t = cfg.get("auth_type", "basic")
    if t == "basic":
        user = cfg.get("username", "") or ""
        pwd  = cfg.get("password", "") or ""
        # Always include the colon — this is what HTTP Basic requires.
        creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        return f"Basic {creds}"
    if t == "apikey":
        return f"Bearer {cfg.get('api_key','')}"
    return ""


def _ssl_ctx(cfg, force_context=False):
    """
    Create SSL context for HTTPS connections.

    If skip_tls_verify is set, returns a context that doesn't verify certificates
    (needed for airgapped environments with self-signed certs).

    If force_context is True, always returns a context (default context when
    not skipping verification). This is needed for opener-based requests.
    """
    if cfg.get("skip_tls_verify"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if force_context:
        return ssl.create_default_context()
    return None


def _get(cfg, path, params=None):
    qs = ("?" + urllib.parse.urlencode(params)) if params else ""
    url = cfg["url"].rstrip("/") + path + qs
    timeout = int(cfg.get("timeout_secs", 1800))
    ctx = _ssl_ctx(cfg)

    if cfg.get("auth_type") == "digest":
        user = cfg.get("username", "") or ""
        pwd  = cfg.get("password", "") or ""
        pwd_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        pwd_mgr.add_password(None, url, user, pwd)
        auth_handler = urllib.request.HTTPDigestAuthHandler(pwd_mgr)
        if ctx:
            opener = urllib.request.build_opener(
                auth_handler,
                urllib.request.HTTPSHandler(context=ctx),
            )
        else:
            opener = urllib.request.build_opener(auth_handler)
        with opener.open(url, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")

    req = urllib.request.Request(url)
    h = _auth_header(cfg)
    if h:
        req.add_header("Authorization", h)
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def _post_with_session(cfg, path, body=None):
    """POST JSON to Arkime using an authenticated session with cookie."""
    import http.cookiejar
    base_url = cfg["url"].rstrip("/")
    url = base_url + path
    timeout = int(cfg.get("timeout_secs", 1800))
    is_https = base_url.lower().startswith("https://")
    # For opener-based requests, always get an SSL context for HTTPS
    ctx = _ssl_ctx(cfg, force_context=is_https)
    data = json.dumps(body).encode("utf-8") if body else b"{}"

    cj = http.cookiejar.CookieJar()
    cookie_handler = urllib.request.HTTPCookieProcessor(cj)

    # Build handlers list
    handlers = [cookie_handler]

    if cfg.get("auth_type") == "digest":
        user = cfg.get("username", "") or ""
        pwd  = cfg.get("password", "") or ""
        pwd_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        pwd_mgr.add_password(None, base_url, user, pwd)
        handlers.append(urllib.request.HTTPDigestAuthHandler(pwd_mgr))

    # Always add HTTPSHandler for HTTPS URLs to ensure proper SSL handling
    if is_https and ctx:
        handlers.append(urllib.request.HTTPSHandler(context=ctx))

    opener = urllib.request.build_opener(*handlers)

    # Step 1: Establish session by hitting an authenticated endpoint
    # Try /api/user first (preferred), fall back to main page
    h = _auth_header(cfg)
    session_endpoints = ["/api/user", "/"]
    for endpoint in session_endpoints:
        init_req = urllib.request.Request(base_url + endpoint)
        if h and cfg.get("auth_type") != "digest":
            init_req.add_header("Authorization", h)
        try:
            with opener.open(init_req, timeout=timeout) as r:
                r.read()
            # Check if we got a cookie
            if any(c.name.upper() in ("ARKIME-COOKIE", "MOLOCH-COOKIE") for c in cj):
                break
        except urllib.error.HTTPError:
            continue  # Try next endpoint

    # Step 2: Extract cookie value for x-arkime-cookie header
    # Try multiple cookie name variants (case-insensitive) for compatibility
    cookie_val = None
    cookie_raw = None  # Keep raw value too in case unquoting breaks it
    for c in cj:
        if c.name.upper() == "ARKIME-COOKIE":
            cookie_raw = c.value
            cookie_val = urllib.parse.unquote(c.value)
            break
    # Fallback: try MOLOCH-COOKIE for older Arkime/Moloch versions
    if not cookie_val:
        for c in cj:
            if c.name.upper() == "MOLOCH-COOKIE":
                cookie_raw = c.value
                cookie_val = urllib.parse.unquote(c.value)
                break

    if not cookie_val:
        # Debug: list what cookies we did receive
        cookie_names = [c.name for c in cj]
        raise RuntimeError(
            f"Could not obtain ARKIME-COOKIE from server. "
            f"Cookies received: {cookie_names or 'none'}. "
            f"Check that your Arkime URL is correct and authentication succeeded."
        )

    # Step 3: POST with cookie header
    # Try with decoded cookie value first, then raw if that fails with 403
    cookie_variants = [cookie_val]
    if cookie_raw and cookie_raw != cookie_val:
        cookie_variants.append(cookie_raw)

    last_error = None
    for cv in cookie_variants:
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("x-arkime-cookie", cv)
        if h and cfg.get("auth_type") != "digest":
            req.add_header("Authorization", h)

        try:
            with opener.open(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            if e.code == 403 and cv != cookie_variants[-1]:
                # Try next cookie variant
                last_error = e
                continue
            if e.code == 403:
                raise RuntimeError(
                    f"HTTP 403 Forbidden from Arkime Hunt API. "
                    f"This usually means CSRF validation failed or missing permissions. "
                    f"Ensure your Arkime user has 'packetSearch' or 'huntEnabled' role. "
                    f"Cookie obtained: {'yes' if cookie_val else 'no'}"
                ) from e
            raise

    # Should not reach here, but just in case
    if last_error:
        raise last_error


def _parse_dt(s):
    for fmt in (
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",    "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(s.strip(), fmt)
        except ValueError:
            pass
    raise ValueError(f"Unrecognised date format: '{s}'. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")


def _time_params(cfg):
    s = _parse_dt(cfg["start_date"])
    e = _parse_dt(cfg["end_date"])
    if e <= s:
        raise ValueError("end_date must be after start_date")
    return {
        "startTime": str(int(s.timestamp())),
        "stopTime":  str(int(e.timestamp())),
        "date":      "-1",
    }


def _esc_val(v):
    """
    Escape a value for use inside an Arkime expression string literal.
    For == (exact match), only backslash and double-quote need escaping.
    The value is treated as a literal string, not a regex.
    """
    return str(v).replace("\\", "\\\\").replace('"', '\\"')


def _build_expr(cfg):
    parts = []
    tags = cfg.get("tags") or []
    if tags:
        op = " || " if cfg.get("tags_match", "any") == "any" else " && "
        te = op.join(f'tags == "{_esc_val(t)}"' for t in tags)
        parts.append(f"({te})" if len(tags) > 1 else te)
    if cfg.get("expression", "").strip():
        parts.append(cfg["expression"].strip())
    return " && ".join(parts)


def _allowlisted(value, field, al):
    for entry in al.get(field, []):
        if entry.endswith("*") and value.startswith(entry[:-1]):
            return True
        if value == entry:
            return True
    return False


def _fetch_unique(cfg, field, expression):
    """Shared helper: GET /api/unique (with fallback) and parse rows."""
    params = {"exp": field, "counts": "1"}
    params.update(_time_params(cfg))
    if expression:
        params["expression"] = expression
    # Default to 50K limit for billion-session environments; 0 means use default
    DEFAULT_MAX_UNIQUE = 50000
    max_unique = int(cfg.get("max_unique", 0))
    effective_limit = max_unique if max_unique > 0 else DEFAULT_MAX_UNIQUE
    params["maxvaluesperfield"] = str(effective_limit)

    body, last_err = None, None
    for path in ("/api/unique", "/unique.txt"):
        try:
            body = _get(cfg, path, params)
            break
        except urllib.error.HTTPError as e:
            last_err = f"HTTP {e.code}: {e.reason}"
        except urllib.error.URLError as e:
            last_err = f"Connection error: {e.reason}"
            break
        except Exception as e:
            last_err = str(e)
            break

    if body is None:
        raise RuntimeError(last_err or "No response from Arkime")

    raw = []
    for line in body.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        idx = line.rfind(",")
        if idx == -1:
            raw.append((line, 1))
        else:
            try:
                raw.append((line[:idx].strip(), int(line[idx + 1:].strip())))
            except ValueError:
                raw.append((line, 1))
    raw.sort(key=lambda x: x[1], reverse=True)
    return raw


def _analyze_one_field(cfg, field, expr):
    """Run frequency + rarity analysis for a single field. Pure function."""
    al = cfg.get("allowlist", {}) or {}
    top_n_limit    = int(cfg.get("top_n", 20))
    rare_threshold = int(cfg.get("rare_threshold", 3))
    max_rare       = int(cfg.get("max_rare_display", 50))

    r = {"field": field}
    try:
        raw = _fetch_unique(cfg, field, expr)
        filtered = [(v, c) for v, c in raw if not _allowlisted(v, field, al)]
        r["skipped"]      = len(raw) - len(filtered)
        r["total_unique"] = len(filtered)
        r["total_hits"]   = sum(c for _, c in filtered)
        r["top_n"]        = [{"value": v, "count": c} for v, c in filtered[:top_n_limit]]
        rare              = [(v, c) for v, c in filtered if c <= rare_threshold]
        r["rare"]         = [{"value": v, "count": c} for v, c in (rare[:max_rare] if max_rare > 0 else rare)]
    except Exception as e:
        r["error"] = str(e)
    return r


def do_analyze(cfg, progress=None):
    """
    Run analysis for every field in cfg['fields']. Fields run in parallel.
    If `progress` is provided, it's called as progress(done, total, field).
    """
    time_p = _time_params(cfg)  # validate up-front
    expr   = _build_expr(cfg)
    fields = [f for f in (cfg.get("fields") or []) if f.strip()]
    if not fields:
        return []

    workers = _effective_workers(cfg, len(fields))
    results_by_field = {}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_analyze_one_field, cfg, f, expr): f for f in fields}
        done = 0
        total = len(fields)
        if progress:
            progress(0, total, None)
        for fut in as_completed(futures):
            f = futures[fut]
            try:
                results_by_field[f] = fut.result()
            except Exception as e:
                results_by_field[f] = {"field": f, "error": str(e)}
            done += 1
            if progress:
                progress(done, total, f)

    # Preserve original field order
    return [results_by_field[f] for f in fields]


def do_test(cfg):
    try:
        _get(cfg, "/api/fields")
        return {"ok": True, "message": "Connected successfully"}
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"ok": False, "message": "Authentication failed (HTTP 401) — check username/password"}
        return {"ok": False, "message": f"HTTP {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"ok": False, "message": f"Could not connect: {e.reason}"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def do_arkime_fields(cfg):
    try:
        raw  = _get(cfg, "/api/fields")
        data = json.loads(raw)
        if isinstance(data, list):
            names = sorted({
                item.get("exp") or item.get("dbField") or item.get("name", "")
                for item in data if isinstance(item, dict)
            } - {""})
        elif isinstance(data, dict):
            names = sorted(k for k in data.keys() if k)
        else:
            names = []
        return {"ok": True, "fields": names}
    except urllib.error.HTTPError as e:
        return {"ok": False, "fields": [], "message": f"HTTP {e.code}"}
    except Exception as e:
        return {"ok": False, "fields": [], "message": str(e)}


def do_arkime_tags(cfg):
    tag_names, last_err = [], None
    for path in ("/api/unique", "/unique.txt"):
        try:
            body = _get(cfg, path, {"exp": "tags", "counts": "1", "date": "-1"})
            for line in body.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                idx = line.rfind(",")
                tag = line[:idx].strip() if idx != -1 else line
                if tag:
                    tag_names.append(tag)
            break
        except urllib.error.HTTPError as e:
            last_err = f"HTTP {e.code}"
        except Exception as e:
            last_err = str(e)
            break
    if tag_names:
        return {"ok": True, "tags": sorted(tag_names)}
    return {"ok": False, "tags": [], "message": last_err or "No tags found"}


# ==============================================================================
# Cross-field correlation
# ==============================================================================

def _is_ip_field(field):
    """Check if a field is an IP-type field that shouldn't have quoted values."""
    ip_fields = {"ip.src", "ip.dst", "ip", "srcIp", "dstIp", "source.ip", "destination.ip"}
    return field in ip_fields or field.startswith("ip.")


def _format_value(field, v):
    """Format a value for an Arkime expression - IPs unquoted, others quoted."""
    if _is_ip_field(field):
        return str(v)
    return f'"{_esc_val(v)}"'


def _pivot_expression(pivot_field, pivot_values, match="any"):
    """Build an expression clause for one or more pivot values."""
    if not pivot_values:
        return ""
    if isinstance(pivot_values, str):
        pivot_values = [pivot_values]
    op = " || " if match == "any" else " && "
    parts = [f'{pivot_field} == {_format_value(pivot_field, v)}' for v in pivot_values]
    return f"({op.join(parts)})" if len(parts) > 1 else parts[0]


def do_correlate(cfg):
    """
    Return the top-N distribution of cfg['target_field'] for all sessions
    where cfg['pivot_field'] matches cfg['pivot_values'] (or cfg['pivot_value']).
    Supports multi-value pivots for bulk investigation.
    """
    pivot_field = cfg["pivot_field"]
    values = cfg.get("pivot_values")
    if not values:
        single = cfg.get("pivot_value", "")
        values = [single] if single != "" else []
    if not values:
        raise ValueError("No pivot values supplied")

    match = cfg.get("pivot_match", "any")
    pivot_expr = _pivot_expression(pivot_field, values, match)
    base_expr  = _build_expr(cfg)
    full_expr  = f'{pivot_expr} && {base_expr}' if base_expr else pivot_expr

    raw = _fetch_unique(cfg, cfg["target_field"], full_expr)

    top_n = int(cfg.get("top_n", 20))
    total = sum(c for _, c in raw)
    return {
        "results":    [{"value": v, "count": c} for v, c in raw[:top_n]],
        "total":      total,
        "total_unique": len(raw),
        "expression": full_expr,
    }


# ==============================================================================
# Session drilldown
# ==============================================================================

def do_sessions(cfg):
    """
    Fetch sessions matching the time range, base expression, and either:
      - cfg['extra_expr'] (raw extra clause), or
      - cfg['pivot_field'] + cfg['pivot_values'] (bulk pin)
    """
    base_expr  = _build_expr(cfg)
    extra_expr = cfg.get("extra_expr", "").strip()

    if not extra_expr and cfg.get("pivot_field") and cfg.get("pivot_values"):
        extra_expr = _pivot_expression(
            cfg["pivot_field"],
            cfg["pivot_values"],
            cfg.get("pivot_match", "any"),
        )

    parts     = [p for p in [base_expr, extra_expr] if p]
    full_expr = " && ".join(parts)

    params = {
        "length": str(min(int(cfg.get("session_limit", 100)), 500)),
        "fields": "id,ip.src,ip.dst,port.src,port.dst,firstPacket,lastPacket,"
                  "network.bytes,network.packets,ipProtocol,protocols,node,tags",
        "order":  "firstPacket:desc",
    }
    params.update(_time_params(cfg))
    if full_expr:
        params["expression"] = full_expr

    body, last_err = None, None
    for path in ("/api/sessions", "/sessions.json"):
        try:
            body = _get(cfg, path, params)
            break
        except urllib.error.HTTPError as e:
            last_err = f"HTTP {e.code}: {e.reason}"
        except urllib.error.URLError as e:
            last_err = f"Connection error: {e.reason}"
            break

    if body is None:
        raise RuntimeError(last_err or "No response from Arkime")

    data = json.loads(body)
    total = data.get("recordsFiltered") or data.get("iTotalDisplayRecords") or len(data.get("data", []))
    return {
        "sessions":   data.get("data", []),
        "total":      total,
        "expression": full_expr,
    }


# ==============================================================================
# Anomaly hinting — pulls source-IP concentration for rare values in one batch
# ==============================================================================

# Rate limiting for anomaly hints to prevent overwhelming Arkime
_anomaly_rate_lock = threading.Lock()
_anomaly_last_batch = 0.0
_ANOMALY_MIN_INTERVAL = 0.5  # seconds between batches


def do_anomaly_hints(cfg):
    """
    For a list of (field, value) pairs, return the source-IP concentration for
    each — i.e. how many distinct src IPs contacted that value, and the top
    src IP's share. High concentration + low volume = classic beaconing shape.
    """
    global _anomaly_last_batch

    # Rate limit: ensure minimum interval between batches
    with _anomaly_rate_lock:
        elapsed = time.time() - _anomaly_last_batch
        if elapsed < _ANOMALY_MIN_INTERVAL:
            time.sleep(_ANOMALY_MIN_INTERVAL - elapsed)
        _anomaly_last_batch = time.time()

    pairs = cfg.get("pairs") or []
    if not pairs:
        return {"hints": []}

    base_expr = _build_expr(cfg)
    hints = []

    def _one(pair):
        field = pair.get("field", "")
        value = pair.get("value", "")
        try:
            pivot = f'{field} == {_format_value(field, value)}'
            full  = f'{pivot} && {base_expr}' if base_expr else pivot
            raw   = _fetch_unique(cfg, "ip.src", full)
            total = sum(c for _, c in raw)
            n_src = len(raw)
            top_share = (raw[0][1] / total) if total and raw else 0.0
            return {
                "field":      field,
                "value":      value,
                "src_count":  n_src,
                "total_hits": total,
                "top_src":    raw[0][0] if raw else None,
                "top_share":  round(top_share, 3),
            }
        except Exception as e:
            return {"field": field, "value": value, "error": str(e)}

    # Keep this capped — anomaly hints fire off many queries
    max_workers = _effective_workers(cfg, len(pairs))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_one, p) for p in pairs]
        for fut in as_completed(futures):
            hints.append(fut.result())

    return {"hints": hints}


# ==============================================================================
# Port anomaly scan — three modes
#
# Mode 1: signature -> ports
#   For each signature seen >= min_sessions times, fetch its port distribution.
#   Flag signatures where one port dominates (>= dominance) and outlier ports
#   exist at <= outlier_max sessions.
#
# Mode 2: port -> signatures
#   For each listed well-known port, fetch its signature distribution.
#   Flag signatures that don't match the port's expected signature(s).
#
# Mode 3: host -> port diversity
#   For each src IP, count distinct dst ports used with the same signature.
#   Flag hosts whose (distinct_ports / sessions) ratio is high — scan/beacon
#   shape.
# ==============================================================================

def _load_port_expectations():
    """Load port expectations from IANA CSV file, with Arkime-specific additions."""
    import csv
    
    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "service-names-port-numbers.csv")
    
    expectations = {}
    
    if os.path.exists(csv_path):
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                port = row.get("Port Number", "").strip()
                service = row.get("Service Name", "").strip().lower()
                transport = row.get("Transport Protocol", "").strip().lower()
                desc = row.get("Description", "").strip().lower()
                
                if not port or not port.isdigit():
                    continue
                if not service or service in ("", "unassigned", "reserved"):
                    continue
                
                if port not in expectations:
                    expectations[port] = []
                
                if service and service not in expectations[port]:
                    expectations[port].append(service)
                if transport and transport not in expectations[port]:
                    expectations[port].append(transport)
    
    for port, entry in PORTS_DATA.items():
        if port not in expectations:
            expectations[port] = []
        for proto in entry["services"]:
            if proto not in expectations[port]:
                expectations[port].append(proto)
    
    return expectations


PORT_EXPECTATIONS_DEFAULT = _load_port_expectations()


def _load_port_info_for_html():
    """Load detailed port info with descriptions for the IANA reference page."""
    import csv

    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "service-names-port-numbers.csv")

    # port -> {services: [...], descriptions: [...], transports: [...]}
    port_info = {}

    if os.path.exists(csv_path):
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                port = row.get("Port Number", "").strip()
                service = row.get("Service Name", "").strip()
                transport = row.get("Transport Protocol", "").strip().upper()
                desc = row.get("Description", "").strip()

                if not port or not port.isdigit():
                    continue
                if not service or service.lower() in ("", "unassigned", "reserved"):
                    continue

                if port not in port_info:
                    port_info[port] = {"services": [], "descriptions": [], "transports": set()}

                if service and service not in port_info[port]["services"]:
                    port_info[port]["services"].append(service)
                if desc and desc not in port_info[port]["descriptions"]:
                    port_info[port]["descriptions"].append(desc)
                if transport:
                    port_info[port]["transports"].add(transport)

    for port, entry in PORTS_DATA.items():
        if port not in port_info:
            port_info[port] = {"services": [], "descriptions": [], "transports": set()}
        for svc in entry["services"]:
            if svc not in port_info[port]["services"]:
                port_info[port]["services"].append(svc)
        if entry["desc"] and entry["desc"] not in port_info[port]["descriptions"]:
            port_info[port]["descriptions"].insert(0, entry["desc"])

    return port_info


def _port_share_stats(port_counts):
    """Return (dominant_port, dominant_share, entropy, total) for a {port: count} dict."""
    import math
    if not port_counts:
        return None, 0.0, 0.0, 0
    total = sum(port_counts.values())
    if total == 0:
        return None, 0.0, 0.0, 0
    dominant = max(port_counts.items(), key=lambda kv: kv[1])
    dom_share = dominant[1] / total
    # Shannon entropy over port distribution (in bits)
    entropy = 0.0
    for c in port_counts.values():
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return dominant[0], round(dom_share, 4), round(entropy, 3), total


def do_port_scan_sig_to_port(cfg, progress=None):
    """
    Mode 1: For each signature, find its port distribution and flag those
    where traffic is concentrated on one port but has outliers on others.

    Instead of querying per-signature (which fails for complex string values),
    we query per-port to get signatures, then pivot the data.
    """
    sig_field  = cfg.get("signature_field") or "tls.ja3"
    port_field = cfg.get("port_field") or "port"
    min_sess   = int(cfg.get("min_sessions", 10))
    max_sigs   = int(cfg.get("max_sigs", 100))
    dominance  = float(cfg.get("dominance", 0.9))
    outlier_max= int(cfg.get("outlier_max", 3))

    _ = _time_params(cfg)  # validate
    base_expr = _build_expr(cfg)

    # Step A: get top ports by volume
    # Use port.dst for unique query (Arkime's unique API needs a specific field)
    port_query_field = "port.dst" if port_field == "port" else port_field
    ports_raw = _fetch_unique(cfg, port_query_field, base_expr)
    # Configurable port limit for performance (default 50 for billion-session scale)
    max_ports = int(cfg.get("max_ports", 50))
    top_ports = [p for p, c in ports_raw[:max_ports]]

    if not top_ports:
        return {
            "mode": "sig_to_port",
            "signature_field": sig_field,
            "port_field": port_field,
            "signatures": [],
            "total_signatures_seen": 0,
            "eligible_signatures": 0,
            "truncated": False,
            "warning": f"No ports found for field '{port_query_field}'",
        }

    # Step B: for each port, get signature distribution
    # Build a map: signature -> {port: count}
    sig_to_ports = {}  # sig_val -> {port: count}
    sig_totals = {}    # sig_val -> total count

    def fetch_port(port):
        try:
            pivot = f'{port_field} == {port}'
            full = f'{pivot} && {base_expr}' if base_expr else pivot
            return port, _fetch_unique(cfg, sig_field, full), None
        except Exception as e:
            return port, [], str(e)

    total_ports = len(top_ports)
    done_count = 0
    if progress:
        progress(0, total_ports, None)

    errors = []
    workers = _effective_workers(cfg, len(top_ports))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(fetch_port, p): p for p in top_ports}
        for fut in as_completed(futures):
            port, sigs, err = fut.result()
            if err:
                errors.append(f"port {port}: {err}")
            for sig_val, count in sigs:
                if sig_val not in sig_to_ports:
                    sig_to_ports[sig_val] = {}
                    sig_totals[sig_val] = 0
                sig_to_ports[sig_val][port] = sig_to_ports[sig_val].get(port, 0) + count
                sig_totals[sig_val] += count
            done_count += 1
            if progress:
                progress(done_count, total_ports, f"port {port}")

    # Step C: filter and analyze each signature
    eligible = [(sig, sig_totals[sig]) for sig in sig_to_ports if sig_totals[sig] >= min_sess]
    eligible.sort(key=lambda x: -x[1])
    truncated = len(eligible) > max_sigs
    eligible = eligible[:max_sigs]

    results = []
    for sig_val, total in eligible:
        port_counts = sig_to_ports[sig_val]
        dom, dom_share, entropy, _ = _port_share_stats(port_counts)
        ports_sorted = sorted(port_counts.items(), key=lambda kv: -kv[1])
        outliers = [(p, c) for p, c in ports_sorted if p != dom and c <= outlier_max]
        flagged = dom_share >= dominance and len(outliers) > 0

        results.append({
            "signature":       sig_val,
            "total":           total,
            "dominant_port":   dom,
            "dominant_share":  dom_share,
            "distinct_ports":  len(port_counts),
            "entropy":         entropy,
            "ports":           [{"port": p, "count": c} for p, c in ports_sorted],
            "outliers":        [{"port": p, "count": c} for p, c in outliers],
            "flagged":         flagged,
        })

    # Sort: flagged first (by total desc), then by distinct_ports desc
    results.sort(key=lambda r: (
        0 if r.get("flagged") else 1,
        -(r.get("total") or 0),
    ))

    result = {
        "mode":                   "sig_to_port",
        "signature_field":        sig_field,
        "port_field":             port_field,
        "signatures":             results,
        "total_signatures_seen":  len(sig_to_ports),
        "eligible_signatures":    len(eligible),
        "truncated":              truncated,
        "ports_queried":          len(top_ports),
        "thresholds": {
            "min_sessions": min_sess,
            "max_sigs":     max_sigs,
            "dominance":    dominance,
            "outlier_max":  outlier_max,
        },
    }
    if errors:
        result["errors"] = errors[:10]  # limit to first 10 errors
    return result


def do_port_scan_port_to_sig(cfg, progress=None):
    """
    Mode 2: For each port in cfg['ports_to_check'], fetch the distribution of
    cfg['signature_field'] on that port, and compare against expected
    signatures.
    """
    sig_field  = cfg.get("signature_field") or "protocols"
    port_field = cfg.get("port_field") or "port"
    ports      = cfg.get("ports_to_check") or list(PORT_EXPECTATIONS_DEFAULT.keys())
    expectations = cfg.get("port_expectations") or PORT_EXPECTATIONS_DEFAULT
    max_other  = int(cfg.get("max_other_sigs", 20))

    _ = _time_params(cfg)
    base_expr = _build_expr(cfg)

    def one(port):
        try:
            pivot = f'{port_field} == {port}'   # ports are numeric in Arkime
            full  = f'{pivot} && {base_expr}' if base_expr else pivot
            sig_raw = _fetch_unique(cfg, sig_field, full)
            total = sum(c for _, c in sig_raw)
            expected = set(expectations.get(str(port), []))

            # Split into "matches expectation" and "unexpected"
            matches   = []
            unexpected = []
            for sig, count in sig_raw:
                # A session's `protocols` field is a comma-joined list; treat
                # each token individually if we're keying on protocols.
                tokens = [t.strip().lower() for t in str(sig).split(",")] if sig_field == "protocols" else [str(sig).lower()]
                if expected and any(t in expected for t in tokens):
                    matches.append({"signature": sig, "count": count})
                else:
                    unexpected.append({"signature": sig, "count": count})

            unexpected_total = sum(u["count"] for u in unexpected)
            flagged = bool(expected) and unexpected_total > 0

            return {
                "port":             port,
                "expected":         sorted(expected) if expected else [],
                "total":            total,
                "matches":          matches[:max_other],
                "unexpected":       unexpected[:max_other],
                "unexpected_total": unexpected_total,
                "unexpected_unique": len(unexpected),
                "flagged":          flagged,
            }
        except Exception as e:
            return {"port": port, "error": str(e)}

    workers = _effective_workers(cfg, len(ports))
    results = []
    done = 0
    total_n = len(ports)
    if progress:
        progress(0, total_n, None)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(one, p) for p in ports]
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            done += 1
            if progress:
                progress(done, total_n, str(r.get("port")))

    # Sort flagged ports first, then by port number
    def _port_key(r):
        try:   return int(r.get("port"))
        except Exception: return 99999
    results.sort(key=lambda r: (0 if r.get("flagged") else 1, _port_key(r)))

    return {
        "mode":            "port_to_sig",
        "signature_field": sig_field,
        "port_field":      port_field,
        "ports":           results,
    }


def do_port_scan_host_diversity(cfg, progress=None):
    """
    Mode 3: For each IP seen in the window (both src and dst), compute
    distinct ports used and the port-per-session ratio. Flag hosts where
    the ratio is high and distinct ports exceeds a threshold.
    """
    sig_field   = cfg.get("signature_field") or ""   # optional
    port_field  = cfg.get("port_field") or "port.dst"
    min_sess    = int(cfg.get("min_sessions", 20))
    min_ports   = int(cfg.get("min_distinct_ports", 10))
    ratio_thresh= float(cfg.get("port_ratio_threshold", 0.4))
    max_hosts   = int(cfg.get("max_hosts", 100))

    _ = _time_params(cfg)
    base_expr = _build_expr(cfg)

    # Optionally pin to a specific signature value
    pinned = cfg.get("pinned_signature_value")
    if sig_field and pinned:
        sig_clause = f'{sig_field} == "{_esc_val(pinned)}"'
        base_expr = f'{sig_clause} && {base_expr}' if base_expr else sig_clause

    # Limit initial IP fetch to prevent memory explosion on billion-session datasets
    max_host_candidates = int(cfg.get("max_host_candidates", 10000))
    host_cfg = dict(cfg)
    host_cfg["max_unique"] = max_host_candidates

    # Query both ip.src and ip.dst, merge counts
    hosts_src = {h: c for h, c in _fetch_unique(host_cfg, "ip.src", base_expr)}
    hosts_dst = {h: c for h, c in _fetch_unique(host_cfg, "ip.dst", base_expr)}
    merged = {}
    for h, c in hosts_src.items():
        merged[h] = merged.get(h, 0) + c
    for h, c in hosts_dst.items():
        merged[h] = merged.get(h, 0) + c

    # Filter BEFORE sorting to reduce memory usage
    hosts_raw = [(h, c) for h, c in merged.items() if c >= min_sess]
    hosts_raw.sort(key=lambda kv: -kv[1])
    eligible = hosts_raw[:max_hosts]
    truncated = len(hosts_raw) > max_hosts

    if not eligible:
        return {
            "mode":            "host_diversity",
            "signature_field": sig_field,
            "port_field":      port_field,
            "host_field":      "ip.src OR ip.dst",
            "hosts":           [],
            "truncated":       truncated,
        }

    # Use port.dst for unique query (Arkime's unique API needs a specific field)
    port_query_field = "port.dst" if port_field == "port" else port_field

    def one(host, count):
        try:
            pivot = f'(ip.src == {host} || ip.dst == {host})'
            full  = f'{pivot} && {base_expr}' if base_expr else pivot
            port_raw = _fetch_unique(cfg, port_query_field, full)
            port_counts = {v: c for v, c in port_raw}
            total = sum(port_counts.values())
            distinct = len(port_counts)
            ratio = (distinct / total) if total else 0.0
            _, dom_share, entropy, _ = _port_share_stats(port_counts)
            flagged = (distinct >= min_ports and ratio >= ratio_thresh)
            top_ports = sorted(port_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
            return {
                "host":           host,
                "total":          total,
                "distinct_ports": distinct,
                "ratio":          round(ratio, 3),
                "entropy":        entropy,
                "dominant_share": dom_share,
                "top_ports":      [{"port": p, "count": c} for p, c in top_ports],
                "flagged":        flagged,
            }
        except Exception as e:
            return {"host": host, "total": count, "error": str(e)}

    workers = _effective_workers(cfg, len(eligible))
    results = []
    done = 0
    total_n = len(eligible)
    if progress:
        progress(0, total_n, None)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(one, h, c): h for h, c in eligible}
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            done += 1
            if progress:
                progress(done, total_n, r.get("host"))

    results.sort(key=lambda r: (
        0 if r.get("flagged") else 1,
        -(r.get("ratio") or 0),
        -(r.get("distinct_ports") or 0),
    ))

    return {
        "mode":            "host_diversity",
        "signature_field": sig_field,
        "port_field":      port_field,
        "host_field":      "ip.src OR ip.dst",
        "hosts":           results,
        "truncated":       truncated,
        "thresholds": {
            "min_sessions":         min_sess,
            "min_distinct_ports":   min_ports,
            "port_ratio_threshold": ratio_thresh,
            "max_hosts":            max_hosts,
        },
    }


# ==============================================================================
# Mode 4: Byte pattern → port check (uses Hunt API)
# ==============================================================================

def _get_session_count(cfg):
    """Get the total number of sessions matching the current query."""
    params = {"length": "0", "date": "-1"}
    params.update(_time_params(cfg))
    expr = _build_expr(cfg)
    if expr:
        params["expression"] = expr
    try:
        body = _get(cfg, "/api/sessions", params)
        if not body or not body.strip():
            return 1000
        data = json.loads(body) if isinstance(body, str) else body
        return data.get("recordsFiltered", data.get("recordsTotal", 1000))
    except Exception:
        return 1000


def _create_hunt(cfg, name, search_text, search_type, src=True, dst=True):
    """
    Create a hunt job in Arkime to search raw packet payloads.
    search_type: 'ascii', 'asciicase', 'hex', or 'regex'
    Returns the hunt ID.
    """
    time_p = _time_params(cfg)
    total_sessions = _get_session_count(cfg)
    max_packets = str(cfg.get("hunt_max_packets", 10000))

    body = {
        "totalSessions": total_sessions,
        "name": name,
        "size": max_packets,
        "search": search_text,
        "searchType": search_type,
        "type": "raw",
        "src": src,
        "dst": dst,
        "query": {
            "startTime": int(time_p["startTime"]),
            "stopTime": int(time_p["stopTime"]),
        },
    }
    expr = _build_expr(cfg)
    if expr:
        body["query"]["expression"] = expr

    resp = _post_with_session(cfg, "/api/hunt", body)
    if "hunt" in resp and "id" in resp["hunt"]:
        return resp["hunt"]["id"]
    if "id" in resp:
        return resp["id"]
    raise RuntimeError(f"Failed to create hunt: {resp}")


def _get_hunt_status(cfg, hunt_id):
    """Get the status and results of a hunt."""
    params = {"date": "-1", "history": "all"}
    body = _get(cfg, f"/api/hunts", params)
    if not body or not body.strip():
        raise RuntimeError(f"Empty response for hunts")
    data = json.loads(body) if isinstance(body, str) else body
    # Find our hunt in the list
    for hunt in data.get("data", []):
        if hunt.get("id") == hunt_id:
            return {"hunt": hunt}
    # Hunt not found - return not_found status so we keep polling
    return {"hunt": {"id": hunt_id, "status": "not_found"}}


def _wait_for_hunt(cfg, hunt_id, poll_interval=2, max_wait=300):
    """Poll until a hunt finishes or times out. Returns the hunt object."""
    start = time.time()
    last_good_hunt = None
    while time.time() - start < max_wait:
        status = _get_hunt_status(cfg, hunt_id)
        hunt = status.get("hunt", status)
        if hunt.get("status") == "finished":
            return hunt
        if hunt.get("status") == "error":
            raise RuntimeError(f"Hunt failed: {hunt.get('error', 'unknown error')}")
        if hunt.get("status") == "not_found":
            # Hunt disappeared - if we had a previous good status, it finished
            if last_good_hunt and last_good_hunt.get("matchedSessions", 0) > 0:
                last_good_hunt["status"] = "finished"
                return last_good_hunt
            # Otherwise keep polling briefly in case it's still being created
            time.sleep(poll_interval)
            continue
        # Remember this hunt state
        last_good_hunt = hunt
        time.sleep(poll_interval)
    raise RuntimeError(f"Hunt {hunt_id} timed out after {max_wait}s")


def _get_hunt_sessions(cfg, hunt_id, limit=1000):
    """Get sessions that matched a hunt by querying with huntId."""
    params = {
        "huntId": hunt_id,
        "length": str(limit),
        "date": "-1",
    }

    body = _get(cfg, "/api/sessions", params)
    if body and body.strip():
        data = json.loads(body) if isinstance(body, str) else body
        return data.get("data", [])
    return []


def _delete_hunt(cfg, hunt_id):
    """Clean up a hunt after we're done."""
    try:
        _post_with_session(cfg, f"/api/hunt/{hunt_id}/delete", {})
    except Exception:
        pass


def _process_single_hunt(cfg, pat_cfg, port_field, hunt_timeout, cleanup):
    """Process a single pattern through Hunt API. Returns result dict."""
    pattern = pat_cfg.get("pattern", "").strip()
    pat_type = pat_cfg.get("type", "hex").lower()
    expected_ports = set(int(p) for p in pat_cfg.get("expected_ports", []))

    if not pattern:
        return {"pattern": pattern, "error": "Empty pattern"}

    search_type = "hex" if pat_type == "hex" else "ascii"

    try:
        hunt_name = f"luxray_byte_scan_{pattern[:20]}_{int(time.time())}_{secrets.token_hex(4)}"
        hunt_id = _create_hunt(cfg, hunt_name, pattern, search_type)

        hunt = _wait_for_hunt(cfg, hunt_id, max_wait=hunt_timeout)
        matched = hunt.get("matchedSessions", 0)

        if matched == 0:
            result = {
                "pattern": pattern,
                "type": pat_type,
                "expected_ports": sorted(expected_ports),
                "matched_sessions": 0,
                "ports": [],
                "unexpected_ports": [],
                "flagged": False,
            }
        else:
            sessions = _get_hunt_sessions(cfg, hunt_id)
            port_counts = {}
            for sess in sessions:
                ports = []
                if port_field == "port":
                    p_dst = sess.get("destination", {}).get("port")
                    p_src = sess.get("source", {}).get("port")
                    if p_dst is not None:
                        ports.append(p_dst)
                    if p_src is not None:
                        ports.append(p_src)
                elif port_field == "port.dst":
                    p = sess.get("destination", {}).get("port")
                    if p is not None:
                        ports.append(p)
                elif port_field == "port.src":
                    p = sess.get("source", {}).get("port")
                    if p is not None:
                        ports.append(p)
                else:
                    p = sess.get(port_field)
                    if p is not None:
                        ports = [p] if not isinstance(p, list) else p

                for p in ports:
                    if p is not None:
                        port_counts[int(p)] = port_counts.get(int(p), 0) + 1

            ports_sorted = sorted(port_counts.items(), key=lambda x: -x[1])
            unexpected = [(p, c) for p, c in ports_sorted
                          if p not in expected_ports and p < 49152]
            flagged = len(unexpected) > 0 if expected_ports else False

            result = {
                "pattern": pattern,
                "type": pat_type,
                "expected_ports": sorted(expected_ports),
                "matched_sessions": matched,
                "ports": [{"port": p, "count": c} for p, c in ports_sorted],
                "unexpected_ports": [{"port": p, "count": c} for p, c in unexpected],
                "flagged": flagged,
            }

        if cleanup:
            _delete_hunt(cfg, hunt_id)

        return result

    except Exception as e:
        return {
            "pattern": pattern,
            "type": pat_type,
            "expected_ports": sorted(expected_ports) if expected_ports else [],
            "error": str(e),
        }


def do_port_scan_byte_pattern(cfg, progress=None):
    """
    Mode 4: Search for byte patterns in raw payloads using Hunt API,
    then check which ports those sessions used vs. expected ports.

    cfg keys:
      patterns: list of {pattern, type ('hex'|'ascii'), expected_ports: [int, ...]}
      port_field: 'port' (both), 'port.dst', or 'port.src'
      cleanup_hunts: bool (default True) - delete hunts after completion
      hunt_timeout: int (default 300) - max seconds to wait per hunt
      hunt_workers: int (default 4) - max parallel hunts (be careful with Arkime load)
    """
    patterns = cfg.get("patterns") or []
    if not patterns:
        raise ValueError("No patterns provided")

    port_field = cfg.get("port_field") or "port"
    cleanup = cfg.get("cleanup_hunts", True)
    hunt_timeout = int(cfg.get("hunt_timeout", 300))
    hunt_workers = int(cfg.get("hunt_workers", 4))

    _ = _time_params(cfg)  # validate

    total = len(patterns)
    results_by_idx = {}

    if progress:
        progress(0, total, "Starting parallel hunts...")

    done_count = [0]  # Use list for closure mutability
    lock = threading.Lock()

    def process_with_progress(idx, pat_cfg):
        result = _process_single_hunt(cfg, pat_cfg, port_field, hunt_timeout, cleanup)
        with lock:
            done_count[0] += 1
            if progress:
                progress(done_count[0], total, result.get("pattern", ""))
        return idx, result

    workers = min(hunt_workers, len(patterns))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(process_with_progress, i, pat_cfg): i
            for i, pat_cfg in enumerate(patterns)
        }
        for fut in as_completed(futures):
            idx, result = fut.result()
            results_by_idx[idx] = result

    # Preserve original order
    results = [results_by_idx[i] for i in range(len(patterns))]
    flagged_count = sum(1 for r in results if r.get("flagged"))

    return {
        "mode": "byte_pattern",
        "port_field": port_field,
        "patterns": results,
        "total_patterns": len(patterns),
        "flagged_count": flagged_count,
        "note": "Ephemeral ports (49152-65535) are excluded from 'unexpected' flagging.",
    }


# ==============================================================================
# Baselines — save a scan result under a name, diff future scans against it
# ==============================================================================

def _sig_to_port_as_baseline_data(scan_result):
    """Reduce a mode-1 scan to {signature: {port: count}}."""
    out = {}
    for s in scan_result.get("signatures") or []:
        if s.get("error"): continue
        out[s["signature"]] = {p["port"]: p["count"] for p in s.get("ports") or []}
    return out


def do_baseline_save(data):
    """
    Save a scan result as a named baseline.
    Expects: {name, description, scan_result, built_from: {start, end}, min_sessions}
    """
    name = (data.get("name") or "").strip()
    if not name:
        raise ValueError("Baseline name is required")
    scan = data.get("scan_result") or {}
    if scan.get("mode") != "sig_to_port":
        raise ValueError("Only mode 1 (signature → port) scans can be saved as baselines")

    built_from = data.get("built_from") or {}
    baseline = {
        "description":     (data.get("description") or "").strip(),
        "signature_field": scan.get("signature_field"),
        "port_field":      scan.get("port_field"),
        "built_from":      built_from,
        "built_at":        datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "min_sessions":    scan.get("thresholds", {}).get("min_sessions"),
        "data":            _sig_to_port_as_baseline_data(scan),
    }
    store = _load_store()
    store.setdefault("baselines", {})[name] = baseline
    _save_store(store)
    return {"ok": True, "name": name, "signature_count": len(baseline["data"])}


def do_baseline_list():
    store = _load_store()
    bl = store.get("baselines", {})
    items = []
    for name, b in bl.items():
        items.append({
            "name":            name,
            "description":     b.get("description", ""),
            "signature_field": b.get("signature_field"),
            "port_field":      b.get("port_field"),
            "built_from":      b.get("built_from", {}),
            "built_at":        b.get("built_at"),
            "signature_count": len(b.get("data", {})),
        })
    items.sort(key=lambda x: x["name"])
    return {"baselines": items}


def do_baseline_delete(data):
    name = (data.get("name") or "").strip()
    store = _load_store()
    bl = store.get("baselines", {})
    if name in bl:
        del bl[name]
        store["baselines"] = bl
        _save_store(store)
    return {"ok": True}


def do_baseline_compare(data):
    """
    Compare a fresh mode-1 scan against a saved baseline.
    Returns per-signature diff with severity.

    Expects: {name, scan_result}
    """
    name = (data.get("name") or "").strip()
    store = _load_store()
    bl = store.get("baselines", {})
    if name not in bl:
        raise ValueError(f"Baseline not found: {name}")
    baseline = bl[name]
    scan = data.get("scan_result") or {}
    if scan.get("mode") != "sig_to_port":
        raise ValueError("Comparison requires a mode 1 (signature → port) scan")
    if scan.get("signature_field") != baseline.get("signature_field"):
        raise ValueError(
            f"Signature field mismatch: scan uses '{scan.get('signature_field')}', "
            f"baseline was built with '{baseline.get('signature_field')}'"
        )

    bdata = baseline.get("data", {})
    diffs = []

    # Signatures present in the new scan
    scan_sigs = set()
    for s in scan.get("signatures") or []:
        if s.get("error"): continue
        sig = s["signature"]
        scan_sigs.add(sig)
        scan_ports = {p["port"]: p["count"] for p in s.get("ports") or []}
        baseline_ports = bdata.get(sig)

        if baseline_ports is None:
            diffs.append({
                "signature":     sig,
                "kind":          "new_signature",
                "severity":      "medium",
                "total":         s.get("total"),
                "scan_ports":    sorted(scan_ports.keys()),
                "baseline_ports": [],
                "new_ports":     sorted(scan_ports.keys()),
                "shifted_dominant": None,
            })
            continue

        new_ports = sorted(set(scan_ports) - set(baseline_ports))
        # Dominance shift
        if baseline_ports:
            bd_dom = max(baseline_ports.items(), key=lambda kv: kv[1])[0]
        else:
            bd_dom = None
        if scan_ports:
            sc_dom = max(scan_ports.items(), key=lambda kv: kv[1])[0]
        else:
            sc_dom = None
        shifted = (bd_dom and sc_dom and bd_dom != sc_dom)

        if new_ports or shifted:
            severity = "high" if (new_ports and s.get("flagged")) else ("medium" if new_ports else "low")
            diffs.append({
                "signature":        sig,
                "kind":             "known_signature_new_ports" if new_ports else "dominance_shift",
                "severity":         severity,
                "total":            s.get("total"),
                "scan_ports":       sorted(scan_ports.keys()),
                "baseline_ports":   sorted(baseline_ports.keys()),
                "new_ports":        new_ports,
                "shifted_dominant": {"baseline": bd_dom, "scan": sc_dom} if shifted else None,
            })

    # Signatures that disappeared entirely (still useful context, low severity)
    disappeared = sorted(set(bdata.keys()) - scan_sigs)

    # Order: high severity first, then medium, then low
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    diffs.sort(key=lambda d: (sev_rank.get(d["severity"], 3), -(d.get("total") or 0)))

    return {
        "baseline":     {"name": name, **{k: baseline.get(k) for k in ("description","built_from","built_at","signature_field","port_field")}},
        "diffs":        diffs,
        "disappeared_count": len(disappeared),
        "disappeared_sample": disappeared[:20],
        "new_count":    sum(1 for d in diffs if d["kind"] == "new_signature"),
        "changed_count": sum(1 for d in diffs if d["kind"] != "new_signature"),
    }


# ==============================================================================
# Settings + preset persistence
# ==============================================================================

SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "arkime_settings.json")


def _atomic_write(path, text):
    """Write file atomically via rename. Works on Windows and POSIX."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, path)


def _load_store():
    if not os.path.exists(SETTINGS_FILE):
        return {}
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_store(store):
    _atomic_write(SETTINGS_FILE, json.dumps(store, indent=2, ensure_ascii=False))


def _strip_password(d):
    return {k: v for k, v in d.items() if k != "password"}


def do_save_settings(data):
    store = _load_store()
    # Save credentials for air-gapped environments - auto-connect on reload
    store["current"] = data
    _save_store(store)
    return {"ok": True}


def do_load_settings():
    store = _load_store()
    return store.get("current", {})


def _preset_crud(store_key):
    """Factory for preset CRUD operations on a given store key."""
    def list_presets():
        store = _load_store()
        return {"names": sorted(store.get(store_key, {}).keys())}

    def save_preset(data):
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("Preset name is required")
        cfg = data.get("config") or {}
        store = _load_store()
        store.setdefault(store_key, {})[name] = _strip_password(cfg)
        _save_store(store)
        return {"ok": True, "name": name}

    def load_preset(data):
        name = (data.get("name") or "").strip()
        store = _load_store()
        presets = store.get(store_key, {})
        if name not in presets:
            raise ValueError(f"Preset not found: {name}")
        return {"config": presets[name]}

    def delete_preset(data):
        name = (data.get("name") or "").strip()
        store = _load_store()
        presets = store.get(store_key, {})
        if name in presets:
            del presets[name]
            store[store_key] = presets
            _save_store(store)
        return {"ok": True}

    return list_presets, save_preset, load_preset, delete_preset


do_list_presets, do_save_preset, do_load_preset, do_delete_preset = _preset_crud("presets")
do_list_ps_presets, do_save_ps_preset, do_load_ps_preset, do_delete_ps_preset = _preset_crud("ps_presets")


# ==============================================================================
# Server-side results cache (keyed by hash of the relevant config fragment)
# ==============================================================================

class _Cache:
    def __init__(self, ttl_secs=300, max_entries=64):
        self.ttl = ttl_secs
        self.max = max_entries
        self._data = {}
        self._lock = threading.Lock()

    def _key(self, kind, cfg, extras):
        # Only hash the fields that actually change results — never creds.
        keyable = {
            "kind":       kind,
            "url":        cfg.get("url", ""),
            "start":      cfg.get("start_date", ""),
            "end":        cfg.get("end_date", ""),
            "tags":       sorted(cfg.get("tags") or []),
            "tags_match": cfg.get("tags_match", "any"),
            "expr":       cfg.get("expression", ""),
            "fields":     list(cfg.get("fields") or []),
            "top_n":      cfg.get("top_n"),
            "rare":       cfg.get("rare_threshold"),
            "max_rare":   cfg.get("max_rare_display"),
            "allowlist":  cfg.get("allowlist") or {},
            "extras":     extras,
        }
        raw = json.dumps(keyable, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha1(raw).hexdigest()

    def get(self, kind, cfg, extras=None):
        k = self._key(kind, cfg, extras or {})
        with self._lock:
            hit = self._data.get(k)
            if not hit:
                return None
            ts, val = hit
            if time.time() - ts > self.ttl:
                self._data.pop(k, None)
                return None
            return val

    def put(self, kind, cfg, value, extras=None):
        k = self._key(kind, cfg, extras or {})
        with self._lock:
            if len(self._data) >= self.max:
                # evict oldest
                oldest = min(self._data.items(), key=lambda kv: kv[1][0])[0]
                self._data.pop(oldest, None)
            self._data[k] = (time.time(), value)

    def clear(self):
        with self._lock:
            self._data.clear()


# Environment-configurable cache settings for large deployments
CACHE_MAX_ENTRIES = int(os.environ.get("LUXRAY_CACHE_MAX_ENTRIES", 256))
CACHE_TTL_SECS = int(os.environ.get("LUXRAY_CACHE_TTL_SECS", 600))
CACHE = _Cache(ttl_secs=CACHE_TTL_SECS, max_entries=CACHE_MAX_ENTRIES)


# ==============================================================================
# CSRF token — random per-process; required on all POSTs
# ==============================================================================

CSRF_TOKEN = secrets.token_urlsafe(32)


# ==============================================================================
# Embedded HTML page
# ==============================================================================

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Luxray</title>
<style>
:root{
  --bg:#f0f2f5;--surface:#fff;--surface-2:#f9fafb;
  --border:#e5e7eb;--border-2:#f3f4f6;
  --text-1:#111827;--text-2:#374151;--text-3:#6b7280;--text-4:#9ca3af;--text-5:#d1d5db;
  --input-bg:#f9fafb;--input-border:#d1d5db;
  --tag-bg:#dbeafe;--tag-fg:#1d4ed8;--tag-btn:#93c5fd;
  --bar-bg:#e5e7eb;--row-hover:#fafbff;--code-bg:#f3f4f6;
  --danger-bg:#fef2f2;
  --err-bg:#fef2f2;--err-border:#fecaca;--err-fg:#dc2626;--err-hint:#ef4444;
  --anom-bg:#fef3c7;--anom-fg:#92400e;
  --sel-bg:#dbeafe;
}
body.dark{
  color-scheme:dark;
  --bg:#0f1117;--surface:#1a1d27;--surface-2:#22253a;
  --border:#2d3139;--border-2:#252836;
  --text-1:#f1f3f9;--text-2:#c9cdd6;--text-3:#8b909e;--text-4:#5a5f6e;--text-5:#3d4154;
  --input-bg:#22253a;--input-border:#3d4154;
  --tag-bg:#1e3a5f;--tag-fg:#60a5fa;--tag-btn:#3b82f6;
  --bar-bg:#2d3139;--row-hover:#22253a;--code-bg:#22253a;
  --danger-bg:#2d1515;
  --err-bg:#2d1515;--err-border:#7f1d1d;--err-fg:#f87171;--err-hint:#fca5a5;
  --anom-bg:#3d2b0a;--anom-fg:#fbbf24;
  --sel-bg:#1e3a5f;
}
*,*::before,*::after{transition:background-color .2s,border-color .2s,color .15s}
.spinner,.dot.busy,.bar-fg,.prog-fill{transition:none}

*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:14px;color:var(--text-1);background:var(--bg)}
#app{display:flex;flex-direction:column;height:100vh}

header{background:#1a1a2e;color:#fff;padding:0 20px;height:50px;display:flex;align-items:center;gap:12px;flex-shrink:0}
header h1{font-size:1rem;font-weight:700;letter-spacing:.01em}
header .sep{color:#ffffff30}
header .sub{font-size:.75rem;color:#ffffff70}
#darkToggle{margin-left:auto;background:none;border:1px solid #ffffff30;color:#fff;width:34px;height:34px;border-radius:7px;cursor:pointer;font-size:1rem;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:background .15s!important}
#darkToggle:hover{background:#ffffff20}

#body{display:flex;flex:1;overflow:hidden}

#sidebar{width:340px;flex-shrink:0;background:var(--surface);border-right:1px solid var(--border);overflow-y:auto;padding:14px 16px;display:flex;flex-direction:column;gap:0}
.sec{padding-bottom:14px;margin-bottom:14px;border-bottom:1px solid var(--border-2)}
.sec:last-child{border-bottom:none;margin-bottom:0}
.sec-title{font-size:.65rem;font-weight:800;text-transform:uppercase;letter-spacing:.1em;color:var(--text-4);margin-bottom:10px;display:flex;align-items:center;justify-content:space-between}
.sec-title .sec-act{font-weight:600;color:#3b82f6;cursor:pointer;text-transform:none;letter-spacing:0;font-size:.72rem;background:none;border:none;padding:0}
.sec-title .sec-act:hover{text-decoration:underline}

label{display:block;font-size:.75rem;font-weight:600;color:var(--text-2);margin-bottom:3px;margin-top:8px}
label:first-of-type,label.no-mt{margin-top:0}
input[type=text],input[type=password],input[type=number],input[type=datetime-local],select,textarea{
  width:100%;padding:6px 9px;border:1px solid var(--input-border);border-radius:6px;
  font-size:.8rem;color:var(--text-1);background:var(--input-bg)}
input:focus,select:focus,textarea:focus{outline:none;border-color:#3b82f6;background:var(--surface)}
textarea{resize:vertical;font-family:inherit}
body.dark select option{background:var(--surface-2);color:var(--text-1)}

.row2{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.radio-row{display:flex;gap:16px;margin-top:5px}
.radio-row label{display:flex;align-items:center;gap:5px;margin:0;font-weight:500;cursor:pointer;font-size:.78rem}
.check-row{display:flex;align-items:center;gap:7px;margin-top:7px}
.check-row label{margin:0;font-weight:500;cursor:pointer;font-size:.78rem}
.check-row input{width:auto}

.quick-row{display:flex;flex-wrap:wrap;gap:4px;margin-top:7px}
.quick-btn{flex:1;min-width:38px;padding:4px 6px;font-size:.7rem;background:var(--surface-2);border:1px solid var(--border);color:var(--text-2);border-radius:5px;cursor:pointer;font-weight:600}
.quick-btn:hover{border-color:#3b82f6;color:#3b82f6}

/* Tags */
.field-row .srch-wrap{flex:1}
.srch-wrap{position:relative}
.srch-inp{padding-right:28px!important}
.srch-arrow{position:absolute;right:0;top:0;bottom:0;width:28px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--text-3);border:none;border-left:1px solid var(--input-border);background:none;border-radius:0 6px 6px 0;font-size:.7rem}
.srch-arrow:hover{color:#3b82f6;background:var(--surface-2)}
.srch-list{position:absolute;z-index:300;left:0;right:0;max-height:200px;overflow-y:auto;background:var(--surface);border:1px solid #3b82f6;border-radius:6px;margin-top:2px;box-shadow:0 4px 16px rgba(0,0,0,.2);display:none}
.srch-opt{padding:5px 9px;font-size:.78rem;cursor:pointer;color:var(--text-1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.srch-opt:hover{background:var(--surface-2);color:#3b82f6}
.srch-none{padding:6px 9px;font-size:.78rem;color:var(--text-4);font-style:italic}
.srch-hl{font-weight:700;color:#3b82f6}
#tagList{display:flex;flex-direction:column;gap:5px;margin-top:7px;min-height:20px}
.pill{display:inline-flex;align-items:center;gap:3px;background:var(--tag-bg);color:var(--tag-fg);padding:2px 8px 2px 9px;border-radius:10px;font-size:.72rem;font-weight:600}
.pill button{background:none;border:none;cursor:pointer;color:var(--tag-btn);font-size:.85rem;padding:0 0 0 2px;line-height:1;transition:color .15s!important}
.pill button:hover{color:var(--tag-fg)}

/* Field list */
#fieldList{display:flex;flex-direction:column;gap:5px;margin-top:6px}
.field-row{display:flex;gap:5px;align-items:center}
.field-row input{flex:1}
.rm-btn{background:none;border:none;cursor:pointer;color:var(--text-5);font-size:.95rem;padding:3px 5px;border-radius:4px;line-height:1;flex-shrink:0}
.rm-btn:hover{color:#ef4444;background:var(--danger-bg)}
.add-btn{width:100%;padding:6px;background:none;border:1px dashed var(--text-5);color:var(--text-4);border-radius:6px;cursor:pointer;font-size:.75rem;margin-top:5px}
.add-btn:hover{border-color:#3b82f6;color:#3b82f6}

/* Preset bar */
.preset-row{display:flex;gap:6px;align-items:center}
.preset-row select{flex:1}
.preset-row .btn-icon{padding:5px 9px;background:var(--surface);border:1px solid var(--input-border);color:var(--text-2);border-radius:6px;cursor:pointer;font-size:.8rem;flex-shrink:0}
.preset-row .btn-icon:hover{border-color:#3b82f6;color:#3b82f6}

/* Buttons */
.btn-primary{width:100%;padding:9px;background:#1d4ed8;color:#fff;border:none;border-radius:8px;font-size:.88rem;font-weight:700;cursor:pointer;letter-spacing:.01em;transition:background .15s!important}
.btn-primary:hover{background:#1e40af}
.btn-primary:disabled{background:#9ca3af;cursor:not-allowed}
.btn-outline{padding:5px 12px;background:var(--surface);border:1px solid var(--input-border);color:var(--text-2);border-radius:6px;cursor:pointer;font-size:.75rem;font-weight:600}
.btn-outline:hover{border-color:#3b82f6;color:#3b82f6}
.btn-sm{padding:3px 8px;background:var(--surface);border:1px solid var(--input-border);color:var(--text-3);border-radius:4px;cursor:pointer;font-size:.7rem}
.btn-sm:hover{border-color:#3b82f6;color:#3b82f6}
.btn-row{display:flex;gap:7px;margin-top:7px}
.btn-row .btn-primary{flex:1}

/* Connection status */
#connStatus{display:flex;align-items:center;gap:7px;font-size:.73rem;color:var(--text-3);margin-top:6px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--text-5);flex-shrink:0;transition:background .2s!important}
.dot.ok{background:#22c55e}
.dot.err{background:#ef4444}
.dot.busy{background:#f59e0b;animation:blink .7s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}

body.dark ::-webkit-scrollbar{width:8px;background:var(--bg)}
body.dark ::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}

/* Results panel */
#results{flex:1;overflow-y:auto;padding:18px 20px;background:var(--bg)}
.placeholder{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:10px;color:var(--text-4);text-align:center}
.placeholder .ico{font-size:2.4rem;opacity:.35}
.placeholder p{font-size:.85rem}
.loading{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:14px}
.spinner{width:36px;height:36px;border:4px solid var(--bar-bg);border-top-color:#3b82f6;border-radius:50%;animation:spin .7s linear infinite;transition:none!important}
@keyframes spin{to{transform:rotate(360deg)}}

.prog-wrap{width:340px;max-width:80%}
.prog-text{font-size:.82rem;color:var(--text-2);text-align:center;margin-bottom:8px;font-variant-numeric:tabular-nums}
.prog-text .prog-field{color:var(--text-4);font-family:'SFMono-Regular',Consolas,monospace;font-size:.75rem}
.prog-bar{height:6px;background:var(--bar-bg);border-radius:3px;overflow:hidden}
.prog-fill{height:100%;background:#3b82f6;border-radius:3px;width:0%;transition:width .25s ease}
.prog-done{font-size:.72rem;color:var(--text-4);text-align:center;margin-top:7px;display:flex;flex-direction:column;gap:2px;max-height:80px;overflow-y:auto}

.run-header{background:var(--surface);border-radius:9px;padding:12px 16px;margin-bottom:14px;font-size:.78rem;color:var(--text-3);display:flex;flex-wrap:wrap;gap:10px;align-items:center;box-shadow:0 2px 8px rgba(0,0,0,.12);position:sticky;top:0;z-index:100}
.run-header strong{color:var(--text-1)}
.run-tag{background:var(--surface-2);padding:2px 8px;border-radius:4px;font-size:.72rem}
.run-header .spacer{flex:1}
.run-header button{font-size:.72rem;padding:4px 10px}

/* Bulk action bar */
#bulkBar{background:#1d4ed8;color:#fff;border-radius:9px;padding:10px 14px;margin-bottom:14px;display:none;align-items:center;gap:10px;font-size:.82rem;box-shadow:0 2px 6px rgba(29,78,216,.3)}
#bulkBar.on{display:flex}
#bulkBar .b-count{font-weight:700}
#bulkBar .spacer{flex:1}
#bulkBar button{background:rgba(255,255,255,.15);color:#fff;border:1px solid rgba(255,255,255,.25);padding:5px 12px;border-radius:6px;cursor:pointer;font-size:.75rem;font-weight:600}
#bulkBar button:hover{background:rgba(255,255,255,.25)}

/* Cards */
.card{background:var(--surface);border-radius:10px;padding:18px 20px;margin-bottom:14px;box-shadow:0 1px 3px rgba(0,0,0,.07)}
.card-header{display:flex;align-items:center;gap:10px;cursor:pointer;padding:4px 0;user-select:none}
.card-header:hover{opacity:.85}
.card-toggle{color:var(--text-3);font-size:.8rem;width:16px;text-align:center;flex-shrink:0}
.card-title{font-weight:700;font-size:.95rem;color:var(--text-1);font-family:'SFMono-Regular',Consolas,monospace}
.card-summary{font-size:.75rem;color:var(--text-3);flex:1}
.card-body{margin-top:12px}
.card-top{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px;gap:12px;flex-wrap:wrap}
.card-sub{font-size:.72rem;color:var(--text-4);margin-top:2px;margin-bottom:8px}
.btn-sm{padding:4px 8px;font-size:.7rem}
.card-btns{display:flex;gap:6px;flex-shrink:0;flex-wrap:wrap}

.stats{display:flex;background:var(--surface-2);border-radius:7px;overflow:hidden;margin-bottom:14px;border:1px solid var(--border-2)}
.stat{flex:1;padding:10px 14px;border-right:1px solid var(--border-2)}
.stat:last-child{border-right:none}
.stat-val{font-size:1.15rem;font-weight:700;color:var(--text-1);font-variant-numeric:tabular-nums;line-height:1}
.stat-lbl{font-size:.65rem;text-transform:uppercase;letter-spacing:.06em;color:var(--text-4);margin-top:3px}

.tbl-label{font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text-4);margin:14px 0 6px;display:flex;align-items:center;justify-content:space-between;gap:10px}
.card-search{flex-shrink:0}
.card-search input{width:180px;padding:4px 8px;font-size:.72rem;font-family:inherit;letter-spacing:0;text-transform:none}

/* Tables */
table{width:100%;border-collapse:collapse;font-size:.78rem}
th{text-align:left;padding:5px 10px;background:var(--surface-2);color:var(--text-3);font-weight:700;font-size:.67rem;text-transform:uppercase;letter-spacing:.05em;border-bottom:2px solid var(--border);user-select:none}
th.r,td.r{text-align:right}
th.sortable{cursor:pointer}
th.sortable:hover{color:#3b82f6}
th.sortable .sort-ind{font-size:.7em;opacity:.6;margin-left:3px}
td{padding:6px 10px;border-bottom:1px solid var(--border-2);color:var(--text-2);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--row-hover)}
tr.sel td{background:var(--sel-bg)!important}
.val{font-family:'SFMono-Regular',Consolas,monospace;font-size:.73rem;word-break:break-all;max-width:380px}
.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.pct{color:var(--text-4);white-space:nowrap;width:50px}
.bar-col{width:90px}
.bar-bg{height:5px;background:var(--bar-bg);border-radius:3px;overflow:hidden}
.bar-fg{height:100%;background:#3b82f6;border-radius:3px;transition:none!important}
.bar-fg.amber{background:#f59e0b}
.empty{text-align:center;color:var(--text-4);padding:18px;font-size:.8rem}

.chk-col{width:24px;padding-right:0}
.chk-col input{margin:0;cursor:pointer}

.anom-col{width:70px}
.anom-chip{display:inline-block;font-size:.65rem;padding:1px 6px;border-radius:3px;background:var(--anom-bg);color:var(--anom-fg);font-weight:700;letter-spacing:.02em;cursor:help}
.anom-chip.loading{background:var(--surface-2);color:var(--text-4);font-weight:400}

/* Error */
.err-card{background:var(--err-bg);border:1px solid var(--err-border);border-radius:9px;padding:14px 16px;margin-bottom:14px;color:var(--err-fg);font-size:.82rem}
.err-title{font-weight:700;margin-bottom:3px;font-size:.88rem}
.err-hint{color:var(--err-hint);margin-top:5px;font-size:.75rem}

code{background:var(--code-bg);padding:1px 5px;border-radius:3px;font-size:.85em;color:var(--text-2)}

/* Row action buttons */
.act-col{width:90px;white-space:nowrap}
.act-btn{background:none;border:none;cursor:pointer;color:var(--text-4);font-size:.88rem;padding:2px 5px;border-radius:3px;line-height:1;transition:background .1s!important,color .1s!important}
.act-btn:hover{background:var(--surface-2);color:#3b82f6}
.act-btn.allow:hover{color:#10b981}

/* Modal */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:100;align-items:center;justify-content:center;padding:16px}
.modal-overlay.open{display:flex}
.modal{background:var(--surface);border-radius:12px;width:min(920px,100%);max-height:86vh;display:flex;flex-direction:column;box-shadow:0 24px 64px rgba(0,0,0,.35)}
.modal-head{display:flex;align-items:flex-start;padding:16px 20px;border-bottom:1px solid var(--border);gap:12px;flex-shrink:0}
.modal-head-text{flex:1;min-width:0}
.modal-title{font-weight:700;font-size:.95rem;color:var(--text-1)}
.modal-sub{font-size:.72rem;color:var(--text-3);font-family:'SFMono-Regular',Consolas,monospace;margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.modal-close{background:none;border:none;cursor:pointer;color:var(--text-4);font-size:1.1rem;padding:4px 7px;border-radius:5px;line-height:1;flex-shrink:0;transition:background .1s!important}
.modal-close:hover{background:var(--surface-2);color:var(--text-1)}
.modal-body{flex:1;overflow-y:auto;padding:16px 20px}
.modal-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.modal-toolbar label{margin:0;font-size:.78rem;white-space:nowrap}
.modal-toolbar select,.modal-toolbar input[type=text]{width:auto;flex:1;min-width:120px}
.modal-count{font-size:.75rem;color:var(--text-3);margin-bottom:10px}
.corr-expr{font-size:.7rem;color:var(--text-4);font-family:monospace;background:var(--surface-2);padding:6px 10px;border-radius:5px;margin-bottom:12px;word-break:break-all}

/* Breadcrumb trail for multi-pivot correlation */
.breadcrumbs{display:flex;gap:4px;flex-wrap:wrap;align-items:center;margin-bottom:10px;font-size:.72rem}
.crumb{background:var(--surface-2);padding:3px 9px;border-radius:12px;color:var(--text-2);font-family:'SFMono-Regular',Consolas,monospace;font-size:.7rem}
.crumb.active{background:var(--tag-bg);color:var(--tag-fg);font-weight:600}
.breadcrumbs .sep{color:var(--text-5)}

/* Toast */
.toast{position:fixed;bottom:20px;right:20px;background:var(--surface);color:var(--text-1);padding:10px 16px;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.2);font-size:.82rem;border-left:3px solid #3b82f6;z-index:200;animation:toastIn .2s ease;max-width:340px}

/* Port chips (port anomaly scan results) */
.port-chip{display:inline-flex;align-items:center;gap:4px;margin:2px 3px 2px 0;padding:2px 6px 2px 8px;border-radius:10px;background:var(--surface-2);font-size:.72rem;border:1px solid var(--border);font-family:'SFMono-Regular',Consolas,monospace}
.port-chip.dom{background:var(--tag-bg);color:var(--tag-fg);border-color:transparent}
.port-chip.out{background:var(--anom-bg);color:var(--anom-fg);border-color:transparent}
.port-chip.flagged{background:#fecaca;color:#991b1b;border-color:#f87171}
.byte-pattern-row{background:var(--surface-2);border:1px solid var(--border);border-radius:6px;padding:8px;margin-bottom:6px}
.port-chip .port-val{font-weight:700}
.port-chip .port-count{color:var(--text-3);font-size:.68rem}
.port-chip .chip-act{background:none;border:none;cursor:pointer;color:inherit;opacity:.6;padding:0 2px;font-size:.7rem;line-height:1}
.port-chip .chip-act:hover{opacity:1}

details.card > summary{list-style:none;cursor:pointer;position:relative;padding-left:18px!important}
details.card > summary::before{content:"\25B6";position:absolute;left:0;top:2px;font-size:.7em;color:var(--text-4);transition:transform .15s}
details[open].card > summary::before{transform:rotate(90deg)}

tr.clean td{opacity:.75}
.toast.ok{border-left-color:#22c55e}
.toast.err{border-left-color:#ef4444}
@keyframes toastIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
</style>
</head>
<body>
<div id="app">

<header>
  <h1>Luxray</h1>
  <span class="sep">|</span>
  <span class="sub">Field Frequency &amp; Rarity Analysis</span>
  <button id="darkToggle" onclick="toggleDark()" title="Toggle dark mode">&#x1F319;</button>
</header>

<div id="body">

<div id="sidebar">

  <div class="sec">
    <div class="sec-title">Presets</div>
    <div class="preset-row">
      <select id="presetSelect">
        <option value="">— choose preset —</option>
      </select>
      <button class="btn-icon" onclick="loadPreset()" title="Load selected preset">&#x2B07;</button>
      <button class="btn-icon" onclick="savePresetPrompt()" title="Save current config as preset">&#x1F4BE;</button>
      <button class="btn-icon" onclick="deletePreset()" title="Delete selected preset">&#x1F5D1;</button>
    </div>
  </div>

  <div class="sec">
    <div class="sec-title">Connection</div>
    <label class="no-mt">Arkime URL</label>
    <input type="text" id="url" placeholder="http://arkime-host:8005">
    <label>Authentication</label>
    <select id="authType" onchange="toggleAuth()">
      <option value="basic">Basic — username / password</option>
      <option value="digest">Digest — username / password</option>
      <option value="apikey">API Key</option>
      <option value="none">None</option>
    </select>
    <div id="basicFields">
      <label>Username</label>
      <input type="text" id="username">
      <label>Password</label>
      <input type="password" id="password">
    </div>
    <div id="apikeyField" style="display:none">
      <label>API Key</label>
      <input type="text" id="apiKey">
    </div>
    <div class="check-row">
      <input type="checkbox" id="skipTls">
      <label for="skipTls">Skip TLS certificate verification</label>
    </div>
    <div id="connStatus"><span class="dot" id="connDot"></span><span id="connMsg">Not tested</span></div>
    <div class="btn-row">
      <button class="btn-primary" id="testBtn" onclick="testConn()">Test Connection</button>
    </div>
  </div>

  <div class="sec">
    <div class="sec-title">Time Range <span style="font-weight:400;color:#d1d5db;font-size:.85em">(local time)</span></div>
    <label class="no-mt">Start</label>
    <input type="datetime-local" id="startDate">
    <label>End</label>
    <input type="datetime-local" id="endDate">
    <div class="quick-row">
      <button class="quick-btn" onclick="setQuickRange(1)">1h</button>
      <button class="quick-btn" onclick="setQuickRange(4)">4h</button>
      <button class="quick-btn" onclick="setQuickRange(12)">12h</button>
      <button class="quick-btn" onclick="setQuickRange(24)">24h</button>
      <button class="quick-btn" onclick="setQuickRange(72)">3d</button>
      <button class="quick-btn" onclick="setQuickRange(168)">7d</button>
    </div>
  </div>

  <div class="sec">
    <div class="sec-title">Tag Filter</div>
    <div id="tagList"></div>
    <button class="add-btn" onclick="addTag()">+ Add tag</button>
    <label style="margin-top:8px">Match logic</label>
    <div class="radio-row">
      <label><input type="radio" name="tagsMatch" value="any" checked> Any tag (OR)</label>
      <label><input type="radio" name="tagsMatch" value="all"> All tags (AND)</label>
    </div>
  </div>

  <div class="sec">
    <div class="sec-title">Extra Expression</div>
    <input type="text" id="expression" placeholder='e.g. ip.src == 10.0.0.0/8' class="no-mt" style="margin-top:0">
    <div style="font-size:.7rem;color:#9ca3af;margin-top:4px">Applied on top of any tag filter using AND</div>
  </div>

  <div class="sec">
    <div class="sec-title">
      <span>Fields to Analyze</span>
    </div>
    <div id="fieldList"></div>
    <button class="add-btn" onclick="addField('')">+ Add field</button>
  </div>

  <div class="sec">
    <div class="sec-title">Analysis Settings</div>
    <div class="row2">
      <div>
        <label class="no-mt">Top N</label>
        <input type="number" id="topN" value="20" min="1" max="500">
      </div>
      <div>
        <label class="no-mt">Rare threshold</label>
        <input type="number" id="rareThresh" value="3" min="1">
      </div>
    </div>
    <label>Max rare rows shown <span style="font-weight:400;color:#9ca3af">(0 = unlimited)</span></label>
    <input type="number" id="maxRare" value="50" min="0">
    <label>Max unique values per field <span style="font-weight:400;color:#9ca3af">(0 = server default)</span></label>
    <input type="number" id="maxUnique" value="0" min="0">
    <div class="row2" style="margin-top:8px">
      <div>
        <label class="no-mt">Timeout (s)</label>
        <input type="number" id="timeoutSecs" value="1800" min="5" max="7200">
      </div>
      <div>
        <label class="no-mt">Parallel workers</label>
        <input type="number" id="maxWorkers" value="12" min="1" max="24">
      </div>
    </div>
    <div class="check-row">
      <input type="checkbox" id="anomHints" checked>
      <label for="anomHints">Show anomaly hints for rare values</label>
    </div>
  </div>

  <div class="sec">
    <div class="sec-title">
      <span>Allowlist</span>
    </div>
    <div style="font-size:.72rem;color:var(--text-3);margin-bottom:6px;line-height:1.5">
      One entry per line: <code>field: value</code><br>
      Wildcard prefix: <code>http.uri: /static/*</code>
    </div>
    <textarea id="allowlist" rows="5" placeholder="port.dst: 80&#10;port.dst: 443&#10;http.uri: /favicon.ico&#10;http.uri: /robots.txt"></textarea>
  </div>

  <div class="sec">
    <div class="sec-title">
      <span>Port Anomaly Scan</span>
      <button class="sec-act" onclick="togglePortScan()" id="portScanToggle">Show</button>
    </div>
    <div id="portScanBody" style="display:none">
      <label class="no-mt">Preset</label>
      <div class="preset-row">
        <select id="psPresetSelect">
          <option value="">— choose preset —</option>
        </select>
        <button class="btn-icon" onclick="loadPsPreset()" title="Load selected preset">&#x2B07;</button>
        <button class="btn-icon" onclick="savePsPresetPrompt()" title="Save current config as preset">&#x1F4BE;</button>
        <button class="btn-icon" onclick="deletePsPreset()" title="Delete selected preset">&#x1F5D1;</button>
      </div>

      <label>Mode</label>
      <select id="psMode" onchange="renderPortScanMode()">
        <option value="sig_to_port">1 &mdash; Signature on unexpected port</option>
        <option value="port_to_sig">2 &mdash; Unexpected protocol on known port</option>
        <option value="host_diversity">3 &mdash; Host using many ports (scan/beacon)</option>
        <option value="byte_pattern">4 &mdash; Byte pattern on unexpected port</option>
      </select>

      <div id="psMode_sig_to_port">
        <label>Grouping field <span style="font-weight:normal;color:var(--text-3)">(group traffic by this field)</span></label>
        <div class="srch-wrap" data-mode="ps-sig1">
          <input type="text" id="psSigField" class="srch-inp" value="tls.ja3" placeholder="Select or search..."
                 oninput="_srchRender(this,arkimeFields,this.value)"
                 onfocus="_srchRender(this,arkimeFields,this.value)"
                 onblur="_srchClose(this)">
          <button class="srch-arrow" onmousedown="event.preventDefault()" onclick="_srchToggle(this.previousElementSibling,arkimeFields)">&#9662;</button>
          <div class="srch-list"></div>
        </div>
        <label>Port field</label>
        <input type="text" id="psPortField" value="port">
        <div class="row2" style="margin-top:8px">
          <div>
            <label class="no-mt">Min sessions</label>
            <input type="number" id="psMinSessions" value="10" min="1">
          </div>
          <div>
            <label class="no-mt">Max signatures</label>
            <input type="number" id="psMaxSigs" value="100" min="1">
          </div>
        </div>
        <div class="row2" style="margin-top:8px">
          <div>
            <label class="no-mt">Dominance &#8805;</label>
            <input type="number" id="psDominance" value="0.9" min="0" max="1" step="0.01">
          </div>
          <div>
            <label class="no-mt">Outlier max count</label>
            <input type="number" id="psOutlierMax" value="3" min="1">
          </div>
        </div>
        <div style="font-size:.7rem;color:var(--text-3);margin-top:8px;line-height:1.5">
          Groups by field value (e.g. user agent, JA3, protocol), finds which port each
          value normally uses, then flags when it appears on unusual ports.
        </div>
      </div>

      <div id="psMode_port_to_sig" style="display:none">
        <label>Signature field</label>
        <div class="srch-wrap" data-mode="ps-sig2">
          <input type="text" id="psSigField2" class="srch-inp" value="protocols" placeholder="Select or search..."
                 oninput="_srchRender(this,arkimeFields,this.value)"
                 onfocus="_srchRender(this,arkimeFields,this.value)"
                 onblur="_srchClose(this)">
          <button class="srch-arrow" onmousedown="event.preventDefault()" onclick="_srchToggle(this.previousElementSibling,arkimeFields)">&#9662;</button>
          <div class="srch-list"></div>
        </div>
        <label>Port field</label>
        <input type="text" id="psPortField2" value="port">
        <label>Ports to check <span style="font-weight:400;color:#9ca3af">(one per line)</span></label>
        <textarea id="psPortsList" rows="4" placeholder="53&#10;80&#10;443&#10;22"></textarea>
        <div class="btn-row" style="margin-top:4px">
          <button class="btn-outline" onclick="loadDefaultPorts()" style="flex:1">Load default port list</button>
          <a href="/iana-ports" target="_blank" class="btn-outline" style="flex:1;text-align:center;text-decoration:none">View IANA port reference</a>
        </div>
        <label>Expected signatures <span style="font-weight:400;color:#9ca3af">(port: sig1,sig2)</span></label>
        <textarea id="psExpectations" rows="5" placeholder="53: dns&#10;443: tls,http&#10;80: http,tcp"></textarea>
      </div>

      <div id="psMode_host_diversity" style="display:none">
        <div style="font-size:.75rem;color:var(--text-3);margin-bottom:8px">
          Checks both source and destination IPs for scanning/beaconing behavior.
        </div>
        <label>Port field</label>
        <div class="srch-wrap" data-mode="ps-port3">
          <input type="text" id="psPortField3" class="srch-inp" value="port" placeholder="Select or search..."
                 oninput="_srchRender(this,arkimeFields,this.value)"
                 onfocus="_srchRender(this,arkimeFields,this.value)"
                 onblur="_srchClose(this)">
          <button class="srch-arrow" onmousedown="event.preventDefault()" onclick="_srchToggle(this.previousElementSibling,arkimeFields)">&#9662;</button>
          <div class="srch-list"></div>
        </div>
        <label>Pin to signature value <span style="font-weight:400;color:#9ca3af">(optional)</span></label>
        <div class="row2">
          <div class="srch-wrap" data-mode="ps-pin" style="flex:1">
            <input type="text" id="psPinField" class="srch-inp" placeholder="field (e.g. tls.ja3)"
                   oninput="_srchRender(this,arkimeFields,this.value)"
                   onfocus="_srchRender(this,arkimeFields,this.value)"
                   onblur="_srchClose(this)">
            <button class="srch-arrow" onmousedown="event.preventDefault()" onclick="_srchToggle(this.previousElementSibling,arkimeFields)">&#9662;</button>
            <div class="srch-list"></div>
          </div>
          <input type="text" id="psPinValue" placeholder="value">
        </div>
        <div class="row2" style="margin-top:8px">
          <div>
            <label class="no-mt">Min sessions</label>
            <input type="number" id="psMinSessions3" value="20" min="1">
          </div>
          <div>
            <label class="no-mt">Min distinct ports</label>
            <input type="number" id="psMinDistinctPorts" value="10" min="1">
          </div>
        </div>
        <div class="row2" style="margin-top:8px">
          <div>
            <label class="no-mt">Ratio &#8805;</label>
            <input type="number" id="psPortRatio" value="0.4" min="0" max="1" step="0.01">
          </div>
          <div>
            <label class="no-mt">Max hosts</label>
            <input type="number" id="psMaxHosts" value="100" min="1">
          </div>
        </div>
        <div style="font-size:.7rem;color:var(--text-3);margin-top:8px;line-height:1.5">
          Flags hosts with &ge; min-distinct-ports AND
          (distinct ports / sessions) &ge; ratio threshold.
        </div>
      </div>

      <div id="psMode_byte_pattern" style="display:none">
        <label>Port field</label>
        <select id="psPortField4">
          <option value="port" selected>port (src or dst)</option>
          <option value="port.dst">port.dst</option>
          <option value="port.src">port.src</option>
        </select>
        <label>Byte patterns</label>
        <div id="bytePatternList"></div>
        <div class="btn-row" style="margin-top:8px">
          <button class="btn-outline" style="flex:1" onclick="addBytePattern()">+ Add pattern</button>
        </div>
        <div class="row2" style="margin-top:8px">
          <div>
            <label class="no-mt">Max packets/session</label>
            <select id="psHuntMaxPackets">
              <option value="50">50</option>
              <option value="500">500</option>
              <option value="5000">5,000</option>
              <option value="10000" selected>10,000</option>
              <option value="100000">100,000</option>
              <option value="1000000">1,000,000</option>
              <option value="10000000">10,000,000 (admin)</option>
            </select>
          </div>
          <div>
            <label class="no-mt">Hunt timeout (sec)</label>
            <input type="number" id="psHuntTimeout" value="300" min="30">
          </div>
        </div>
        <div class="row2" style="margin-top:8px">
          <div>
            <label class="no-mt">Cleanup hunts</label>
            <select id="psCleanupHunts">
              <option value="true" selected>Yes</option>
              <option value="false">No</option>
            </select>
          </div>
          <div></div>
        </div>
        <div style="font-size:.7rem;color:var(--text-3);margin-top:8px;line-height:1.5">
          Searches raw packet payloads using Arkime Hunt API.<br>
          Flags when a byte pattern appears on an unexpected port.
        </div>
      </div>

      <!-- Baseline (mode 1 only) -->
      <div id="psBaselineBlock">
        <label style="margin-top:12px">Baseline <span style="font-weight:400;color:#9ca3af">(mode 1 only)</span></label>
        <div class="preset-row">
          <select id="psBaselineSelect">
            <option value="">— none, just run the scan —</option>
          </select>
          <button class="btn-icon" onclick="refreshBaselines()" title="Refresh list">&#x21BB;</button>
          <button class="btn-icon" onclick="deleteBaseline()" title="Delete selected baseline">&#x1F5D1;</button>
        </div>
        <div id="psBaselineInfo" style="font-size:.7rem;color:var(--text-3);margin-top:6px;min-height:14px"></div>
        <div class="btn-row">
          <button class="btn-outline" style="flex:1" onclick="saveBaselineFromLastScan()">Save last scan as baseline&hellip;</button>
        </div>
      </div>

      <div class="btn-row" style="margin-top:10px">
        <button class="btn-primary" id="psRunBtn" onclick="runPortScan()" style="flex:1">&#9654; Run Port Scan</button>
        <button class="btn-outline" id="psStopBtn" onclick="stopPortScan()" style="display:none;color:#ef4444;border-color:#ef4444">&#9632; Stop</button>
      </div>
    </div>
  </div>

  <button class="btn-primary" id="runBtn" onclick="runAnalysis()">&#9654; Run Analysis</button>

</div>

<div id="results">
  <div class="placeholder" id="placeholder">
    <div class="ico">&#x1F50D;</div>
    <p>Configure the settings on the left<br>and click <strong>Run Analysis</strong> to begin.</p>
  </div>
</div>

</div>
</div>

<div class="modal-overlay" id="modalOverlay" onclick="maybeCloseModal(event)">
  <div class="modal" id="modal">
    <div class="modal-head">
      <div class="modal-head-text">
        <div class="modal-title" id="modalTitle"></div>
        <div class="modal-sub"  id="modalSub"></div>
      </div>
      <button class="modal-close" onclick="closeModal()" title="Close">&#x2715;</button>
    </div>
    <div class="modal-body" id="modalBody"></div>
  </div>
</div>

<script>
window.__CSRF = "__CSRF_TOKEN__";

// ── State ────────────────────────────────────────────────────────────────────
let tags          = [];
let fields        = ["port.dst", "port.src", "http.useragent", "http.uri"];
let arkimeFields  = [];
let arkimeTags    = [];
let lastResults = {};
let rowData     = [];
let lastCfg     = null;
let selection   = new Set();   // indices into rowData
let sortState   = {};          // key -> {col, dir}
let searchState = {};          // key -> filter string
let anomHints   = {};          // "field||value" -> hint object
let presetList  = [];
let corrStack   = [];          // breadcrumb trail inside the modal

// ── Init ─────────────────────────────────────────────────────────────────────
(async function init() {
  if (localStorage.getItem("arkime_dark") === "1") {
    document.body.classList.add("dark");
    document.getElementById("darkToggle").textContent = "\u2600\uFE0F";
  }

  const now  = new Date();
  const prev = new Date(now - 86400000);
  document.getElementById("startDate").value = dtLocal(prev);
  document.getElementById("endDate").value   = dtLocal(now);

  await loadSettingsFromServer();
  try {
    const saved = localStorage.getItem("arkime_ui_cfg");
    if (saved) loadConfig(JSON.parse(saved));
  } catch (_) {}

  toggleAuth();
  renderFields();
  renderTags();
  refreshPresets();
})();

function dtLocal(d) {
  const z = n => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${z(d.getMonth()+1)}-${z(d.getDate())}T${z(d.getHours())}:${z(d.getMinutes())}`;
}

function setQuickRange(hours) {
  const now = new Date();
  const start = new Date(now - hours * 3600 * 1000);
  document.getElementById("startDate").value = dtLocal(start);
  document.getElementById("endDate").value   = dtLocal(now);
}

function toggleAuth() {
  const t = document.getElementById("authType").value;
  document.getElementById("basicFields").style.display  = (t === "basic" || t === "digest") ? "" : "none";
  document.getElementById("apikeyField").style.display  = t === "apikey" ? "" : "none";
}

// ── Searchable dropdown ───────────────────────────────────────────────────────
function _srchRender(inp, opts, q) {
  const list = inp.parentElement.querySelector('.srch-list');
  if (!list) return;
  if (!opts.length) {
    list.innerHTML = '<div class="srch-none">Test connection to load options</div>';
    list.style.display = 'block';
    return;
  }
  const lq = (q || "").toLowerCase();
  const filt = lq ? opts.filter(o => o.toLowerCase().includes(lq)) : opts;
  if (!filt.length) {
    list.innerHTML = '<div class="srch-none">No matches</div>';
  } else {
    list.innerHTML = filt.slice(0, 150).map(o => {
      let label;
      if (lq) {
        const idx = o.toLowerCase().indexOf(lq);
        label = idx >= 0
          ? esc(o.slice(0,idx)) + `<span class="srch-hl">${esc(o.slice(idx,idx+lq.length))}</span>` + esc(o.slice(idx+lq.length))
          : esc(o);
      } else {
        label = esc(o);
      }
      return `<div class="srch-opt" data-val="${esc(o)}" onmousedown="event.preventDefault()" onclick="_srchPick(this)">${label}</div>`;
    }).join('');
  }
  list.style.display = 'block';
}

function _srchToggle(inp, opts) {
  const list = inp.parentElement && inp.parentElement.querySelector('.srch-list');
  if (!list) return;
  if (list.style.display === 'block') {
    list.style.display = 'none';
  } else {
    _srchRender(inp, opts, inp.value);
    inp.focus();
  }
}

function _srchPick(el) {
  const wrap = el.closest('.srch-wrap');
  const inp  = wrap.querySelector('input');
  const val  = el.dataset.val;
  inp.value  = val;
  wrap.querySelector('.srch-list').style.display = 'none';
  const mode = wrap.dataset.mode;
  if (mode === 'field') {
    fields[parseInt(wrap.dataset.idx)] = val;
  } else if (mode === 'tag-row') {
    tags[parseInt(wrap.dataset.idx)] = val;
  }
  // Trigger change event to ensure value is captured
  inp.dispatchEvent(new Event('change'));
}

function _srchClose(inp) {
  setTimeout(() => {
    const list = inp.parentElement && inp.parentElement.querySelector('.srch-list');
    if (list) list.style.display = 'none';
  }, 150);
}

// ── Tags ─────────────────────────────────────────────────────────────────────
function addTag() { tags.push(""); renderTags(); }
function removeTag(i) { tags.splice(i, 1); renderTags(); }
function renderTags() {
  document.getElementById("tagList").innerHTML = tags.map((t, i) =>
    `<div class="field-row">
      <div class="srch-wrap" data-mode="tag-row" data-idx="${i}">
        <input type="text" class="srch-inp" value="${esc(t)}" placeholder="Select or search…"
               oninput="_srchRender(this,arkimeTags,this.value);tags[${i}]=this.value"
               onfocus="_srchRender(this,arkimeTags,this.value)"
               onblur="_srchClose(this)"
               onchange="tags[${i}]=this.value">
        <button class="srch-arrow" onmousedown="event.preventDefault()" onclick="_srchToggle(this.previousElementSibling,arkimeTags)">▾</button>
        <div class="srch-list"></div>
      </div>
      <button class="rm-btn" onclick="removeTag(${i})" title="Remove">&#x2715;</button>
    </div>`
  ).join("");
}

// ── Fields ───────────────────────────────────────────────────────────────────
function syncFieldsFromDOM() {
  document.querySelectorAll('#fieldList .srch-wrap[data-mode="field"]').forEach(wrap => {
    const idx = parseInt(wrap.dataset.idx);
    const inp = wrap.querySelector('input');
    if (inp && !isNaN(idx) && idx < fields.length) {
      fields[idx] = inp.value;
    }
  });
}
function addField(val) { syncFieldsFromDOM(); fields.push(val || ""); renderFields(); }
function removeField(i) { syncFieldsFromDOM(); fields.splice(i, 1); renderFields(); }
function renderFields() {
  document.getElementById("fieldList").innerHTML = fields.map((f, i) =>
    `<div class="field-row">
      <div class="srch-wrap" data-mode="field" data-idx="${i}">
        <input type="text" class="srch-inp" value="${esc(f)}" placeholder="Select or search…"
               oninput="_srchRender(this,arkimeFields,this.value);fields[${i}]=this.value"
               onfocus="_srchRender(this,arkimeFields,this.value)"
               onblur="_srchClose(this);fields[${i}]=this.value"
               onchange="fields[${i}]=this.value">
        <button class="srch-arrow" onmousedown="event.preventDefault()" onclick="_srchToggle(this.previousElementSibling,arkimeFields)">▾</button>
        <div class="srch-list"></div>
      </div>
      <button class="rm-btn" onclick="removeField(${i})" title="Remove">&#x2715;</button>
    </div>`
  ).join("");
}

// ── Allowlist ────────────────────────────────────────────────────────────────
function parseAllowlist() {
  const al = {};
  for (const line of document.getElementById("allowlist").value.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const colon = t.indexOf(":");
    if (colon === -1) continue;
    const field = t.slice(0, colon).trim();
    const value = t.slice(colon + 1).trim();
    if (field && value) (al[field] = al[field] || []).push(value);
  }
  return al;
}
function allowlistToText(al) {
  return Object.entries(al).flatMap(([f, vs]) => vs.map(v => `${f}: ${v}`)).join("\n");
}
function addToAllowlist(field, value) {
  const ta = document.getElementById("allowlist");
  const line = `${field}: ${value}`;
  const cur = ta.value.split("\n").map(l => l.trim()).filter(Boolean);
  if (cur.includes(line)) { toast("Already in allowlist", "ok"); return; }
  ta.value = (ta.value.trim() ? ta.value.trimEnd() + "\n" : "") + line + "\n";
  toast(`Added to allowlist: ${field} = ${value.slice(0, 40)}${value.length > 40 ? "…" : ""}`, "ok");
}

// ── Config ───────────────────────────────────────────────────────────────────
function getConfig() {
  return {
    url:              document.getElementById("url").value.trim(),
    auth_type:        document.getElementById("authType").value,
    username:         document.getElementById("username").value,
    password:         document.getElementById("password").value,
    api_key:          document.getElementById("apiKey").value,
    skip_tls_verify:  document.getElementById("skipTls").checked,
    start_date:       document.getElementById("startDate").value,
    end_date:         document.getElementById("endDate").value,
    tags:             [...tags],
    tags_match:       document.querySelector('input[name="tagsMatch"]:checked').value,
    expression:       document.getElementById("expression").value.trim(),
    fields:           fields.filter(f => f.trim()),
    top_n:            parseInt(document.getElementById("topN").value)      || 20,
    rare_threshold:   parseInt(document.getElementById("rareThresh").value) || 3,
    max_rare_display: parseIntOr(document.getElementById("maxRare").value, 50),
    max_unique:       parseIntOr(document.getElementById("maxUnique").value, 0),
    timeout_secs:     parseInt(document.getElementById("timeoutSecs").value) || 1800,
    max_workers:      parseInt(document.getElementById("maxWorkers").value) || 12,
    anom_hints:       document.getElementById("anomHints").checked,
    allowlist:        parseAllowlist(),
  };
}
function parseIntOr(v, fallback) {
  const n = parseInt(v);
  return Number.isFinite(n) ? n : fallback;
}

function loadConfig(c) {
  const set = (id, v) => { if (v !== undefined && v !== null) document.getElementById(id).value = v; };
  set("url",        c.url);
  set("username",   c.username);
  set("password",   c.password);
  set("apiKey",     c.api_key);
  set("expression", c.expression);
  set("topN",       c.top_n);
  set("rareThresh", c.rare_threshold);
  set("maxRare",      c.max_rare_display);
  set("maxUnique",    c.max_unique);
  set("timeoutSecs",  c.timeout_secs);
  set("maxWorkers",   c.max_workers);
  if (c.auth_type) document.getElementById("authType").value = c.auth_type;
  if (c.skip_tls_verify) document.getElementById("skipTls").checked = true;
  if (c.anom_hints !== undefined) document.getElementById("anomHints").checked = !!c.anom_hints;
  if (c.start_date) document.getElementById("startDate").value = c.start_date;
  if (c.end_date)   document.getElementById("endDate").value   = c.end_date;
  if (Array.isArray(c.tags))   { tags   = c.tags;   renderTags(); }
  if (Array.isArray(c.fields)) { fields = c.fields; renderFields(); }
  if (c.tags_match) {
    const r = document.querySelector(`input[name="tagsMatch"][value="${c.tags_match}"]`);
    if (r) r.checked = true;
  }
  if (c.allowlist && Object.keys(c.allowlist).length)
    document.getElementById("allowlist").value = allowlistToText(c.allowlist);
  toggleAuth();
}

// ── Presets ──────────────────────────────────────────────────────────────────
async function refreshPresets() {
  try {
    const res = await fetch("/api/presets");
    if (!res.ok) return;
    const data = await res.json();
    presetList = data.names || [];
    const sel = document.getElementById("presetSelect");
    const current = sel.value;
    sel.innerHTML = `<option value="">— choose preset —</option>` +
      presetList.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join("");
    if (presetList.includes(current)) sel.value = current;
  } catch(_) {}
}

async function loadPreset() {
  const name = document.getElementById("presetSelect").value;
  if (!name) { toast("Choose a preset first", "err"); return; }
  try {
    const data = await apiFetch("/api/preset/load", {name});
    if (data.error) { toast(data.error, "err"); return; }
    // Preserve password — presets deliberately never contain it
    const pwd = document.getElementById("password").value;
    loadConfig(data.config || {});
    if (pwd) document.getElementById("password").value = pwd;
    toast(`Loaded preset: ${name}`, "ok");
  } catch(e) { toast("Load failed: " + e.message, "err"); }
}

async function savePresetPrompt() {
  const sel = document.getElementById("presetSelect");
  const suggested = sel.value || "";
  const name = prompt("Save current configuration as preset:\n(enter a name, or an existing name to overwrite)", suggested);
  if (!name || !name.trim()) return;
  try {
    const data = await apiFetch("/api/preset/save", {name: name.trim(), config: getConfig()});
    if (data.error) { toast(data.error, "err"); return; }
    await refreshPresets();
    document.getElementById("presetSelect").value = name.trim();
    toast(`Saved preset: ${name.trim()}`, "ok");
  } catch(e) { toast("Save failed: " + e.message, "err"); }
}

async function deletePreset() {
  const name = document.getElementById("presetSelect").value;
  if (!name) { toast("Choose a preset first", "err"); return; }
  if (!confirm(`Delete preset "${name}"?`)) return;
  try {
    await apiFetch("/api/preset/delete", {name});
    await refreshPresets();
    toast(`Deleted preset: ${name}`, "ok");
  } catch(e) { toast("Delete failed: " + e.message, "err"); }
}

// ── Port Scan Presets ────────────────────────────────────────────────────────
let psPresetList = [];

async function refreshPsPresets() {
  try {
    const res = await fetch("/api/ps-presets");
    if (!res.ok) return;
    const data = await res.json();
    psPresetList = data.names || [];
    const sel = document.getElementById("psPresetSelect");
    const current = sel.value;
    sel.innerHTML = `<option value="">— choose preset —</option>` +
      psPresetList.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join("");
    if (psPresetList.includes(current)) sel.value = current;
  } catch(_) {}
}

async function loadPsPreset() {
  const name = document.getElementById("psPresetSelect").value;
  if (!name) { toast("Choose a preset first", "err"); return; }
  try {
    const data = await apiFetch("/api/ps-preset/load", {name});
    if (data.error) { toast(data.error, "err"); return; }
    applyPsConfig(data.config || {});
    toast(`Loaded preset: ${name}`, "ok");
  } catch(e) { toast("Load failed: " + e.message, "err"); }
}

async function savePsPresetPrompt() {
  const sel = document.getElementById("psPresetSelect");
  const suggested = sel.value || "";
  const name = prompt("Save current port scan configuration as preset:\n(enter a name, or an existing name to overwrite)", suggested);
  if (!name || !name.trim()) return;
  try {
    const data = await apiFetch("/api/ps-preset/save", {name: name.trim(), config: getPortScanCfg()});
    if (data.error) { toast(data.error, "err"); return; }
    await refreshPsPresets();
    document.getElementById("psPresetSelect").value = name.trim();
    toast(`Saved preset: ${name.trim()}`, "ok");
  } catch(e) { toast("Save failed: " + e.message, "err"); }
}

async function deletePsPreset() {
  const name = document.getElementById("psPresetSelect").value;
  if (!name) { toast("Choose a preset first", "err"); return; }
  if (!confirm(`Delete preset "${name}"?`)) return;
  try {
    await apiFetch("/api/ps-preset/delete", {name});
    await refreshPsPresets();
    toast(`Deleted preset: ${name}`, "ok");
  } catch(e) { toast("Delete failed: " + e.message, "err"); }
}

function applyPsConfig(cfg) {
  // Set mode first (this shows/hides the right sections)
  const mode = cfg.mode || "sig_to_port";
  document.getElementById("psMode").value = mode;
  renderPortScanMode();

  // Mode 1: sig_to_port
  if (mode === "sig_to_port") {
    if (cfg.signature_field) document.getElementById("psSigField").value = cfg.signature_field;
    if (cfg.port_field) document.getElementById("psPortField").value = cfg.port_field;
    if (cfg.min_sessions != null) document.getElementById("psMinSessions").value = cfg.min_sessions;
    if (cfg.max_sigs != null) document.getElementById("psMaxSigs").value = cfg.max_sigs;
    if (cfg.dominance != null) document.getElementById("psDominance").value = cfg.dominance;
    if (cfg.outlier_max != null) document.getElementById("psOutlierMax").value = cfg.outlier_max;
  }
  // Mode 2: port_to_sig
  else if (mode === "port_to_sig") {
    if (cfg.signature_field) document.getElementById("psSigField2").value = cfg.signature_field;
    if (cfg.port_field) document.getElementById("psPortField2").value = cfg.port_field;
    if (cfg.ports_to_check) document.getElementById("psPortsList").value = cfg.ports_to_check.join("\n");
    if (cfg.port_expectations) {
      const lines = Object.entries(cfg.port_expectations).map(([port, sigs]) => `${port}: ${sigs.join(", ")}`);
      document.getElementById("psExpectations").value = lines.join("\n");
    }
  }
  // Mode 3: host_diversity
  else if (mode === "host_diversity") {
    if (cfg.port_field) document.getElementById("psPortField3").value = cfg.port_field;
    if (cfg.signature_field) document.getElementById("psPinField").value = cfg.signature_field;
    if (cfg.pinned_signature_value) document.getElementById("psPinValue").value = cfg.pinned_signature_value;
    if (cfg.min_sessions != null) document.getElementById("psMinSessions3").value = cfg.min_sessions;
    if (cfg.min_distinct_ports != null) document.getElementById("psMinDistinctPorts").value = cfg.min_distinct_ports;
    if (cfg.port_ratio_threshold != null) document.getElementById("psPortRatio").value = cfg.port_ratio_threshold;
    if (cfg.max_hosts != null) document.getElementById("psMaxHosts").value = cfg.max_hosts;
  }
  // Mode 4: byte_pattern
  else if (mode === "byte_pattern") {
    if (cfg.port_field) document.getElementById("psPortField4").value = cfg.port_field;
    if (cfg.hunt_max_packets != null) document.getElementById("psHuntMaxPackets").value = cfg.hunt_max_packets;
    if (cfg.hunt_timeout != null) document.getElementById("psHuntTimeout").value = cfg.hunt_timeout;
    if (cfg.cleanup_hunts != null) document.getElementById("psCleanupHunts").value = cfg.cleanup_hunts ? "true" : "false";
    // Restore byte patterns
    if (cfg.patterns && cfg.patterns.length) {
      document.getElementById("bytePatternList").innerHTML = "";
      bytePatternId = 0;
      for (const p of cfg.patterns) {
        const portsStr = (p.expected_ports || []).join(", ");
        addBytePattern(p.pattern || "", p.type || "hex", portsStr);
      }
    }
  }
}

// ── Test connection ──────────────────────────────────────────────────────────
async function testConn() {
  setConn("busy", "Testing…");
  document.getElementById("testBtn").disabled = true;
  try {
    const cfg = getConfig();
    const res = await apiFetch("/api/test", cfg);
    setConn(res.ok ? "ok" : "err", res.message);
    if (res.ok) {
      loadArkimeFields(cfg);
      loadArkimeTags(cfg);
      // Save credentials on successful connection
      saveSettingsToServer(cfg);
    }
  } catch(e) {
    setConn("err", "Request failed: " + e.message);
  }
  document.getElementById("testBtn").disabled = false;
}

async function loadArkimeFields(cfg) {
  try {
    const res = await apiFetch("/api/arkime-fields", cfg);
    if (res.ok && res.fields.length) {
      arkimeFields = res.fields;
      renderFields();
    }
  } catch(_) {}
}

async function loadArkimeTags(cfg) {
  try {
    const res = await apiFetch("/api/arkime-tags", cfg);
    if (res.ok && res.tags.length) { arkimeTags = res.tags; renderTags(); }
  } catch(_) {}
}
function setConn(state, msg) {
  document.getElementById("connDot").className = "dot " + state;
  document.getElementById("connMsg").textContent = msg;
}

// ── Run analysis (with progress) ─────────────────────────────────────────────
async function runAnalysis() {
  const cfg = getConfig();
  if (!cfg.url)            { toast("Please enter an Arkime URL.", "err"); return; }
  if (!cfg.fields.length)  { toast("Please add at least one field.", "err"); return; }
  if (!cfg.start_date)     { toast("Please set a start date.", "err"); return; }
  if (!cfg.end_date)       { toast("Please set an end date.", "err"); return; }

  const toSave = {...cfg};
  localStorage.setItem("arkime_ui_cfg", JSON.stringify(toSave));
  saveSettingsToServer(toSave);

  lastCfg = cfg;
  selection.clear();
  updateBulkBar();
  lastResults = {};
  sortState = {};
  searchState = {};
  anomHints = {};

  const panel = document.getElementById("results");
  panel.innerHTML = `
    <div class="loading">
      <div class="spinner"></div>
      <div class="prog-wrap">
        <div class="prog-text" id="progText">Starting…</div>
        <div class="prog-bar"><div class="prog-fill" id="progFill"></div></div>
        <div class="prog-done" id="progDone"></div>
      </div>
    </div>`;
  document.getElementById("runBtn").disabled = true;

  try {
    const data = await runAnalysisStreaming(cfg);
    if (data.error) { showError(panel, "Analysis failed", data.error); return; }
    renderResults(panel, data.results, cfg);

    if (cfg.anom_hints) {
      kickOffAnomalyHints(cfg, data.results);
    }
  } catch(e) {
    showError(panel, "Request error", e.message);
  } finally {
    document.getElementById("runBtn").disabled = false;
  }
}

function runAnalysisStreaming(cfg) {
  // POST → returns SSE stream of progress events, ending with a final "result" event.
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/analyze-stream", true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.setRequestHeader("X-CSRF-Token", window.__CSRF);
    let lastIdx = 0;
    let finalResult = null;

    xhr.onreadystatechange = function() {
      if (xhr.readyState >= 3) {
        const chunk = xhr.responseText.slice(lastIdx);
        lastIdx = xhr.responseText.length;
        const events = chunk.split("\n\n");
        for (const ev of events) {
          if (!ev.trim()) continue;
          const lines = ev.split("\n");
          let eventType = "message";
          let dataStr = "";
          for (const ln of lines) {
            if (ln.startsWith("event:")) eventType = ln.slice(6).trim();
            else if (ln.startsWith("data:")) dataStr += ln.slice(5).trim();
          }
          if (!dataStr) continue;
          try {
            const payload = JSON.parse(dataStr);
            if (eventType === "progress") {
              updateProgress(payload);
            } else if (eventType === "result") {
              finalResult = payload;
            } else if (eventType === "error") {
              reject(new Error(payload.error || "Unknown error"));
              xhr.abort();
              return;
            }
          } catch(_) {}
        }
      }
      if (xhr.readyState === 4) {
        if (finalResult) resolve(finalResult);
        else if (xhr.status === 0) reject(new Error("Connection closed"));
        else reject(new Error(`HTTP ${xhr.status}`));
      }
    };
    xhr.onerror = () => reject(new Error("Network error"));
    xhr.send(JSON.stringify(cfg));
  });
}

function updateProgress(p) {
  const total = p.total || 1;
  const done  = p.done  || 0;
  const pct   = Math.round(done / total * 100);
  const pt = document.getElementById("progText");
  const pf = document.getElementById("progFill");
  const pd = document.getElementById("progDone");
  if (!pt || !pf) return;
  pf.style.width = pct + "%";
  if (done === 0) {
    pt.innerHTML = `Launching <strong>${total}</strong> field quer${total===1?"y":"ies"} in parallel…`;
  } else if (done === total) {
    pt.innerHTML = `<strong>${done}/${total}</strong> complete — finalising…`;
  } else {
    pt.innerHTML = `<strong>${done}/${total}</strong> fields complete`;
  }
  if (p.field && pd) {
    const line = document.createElement("div");
    line.innerHTML = `&#x2713; <span class="prog-field">${esc(p.field)}</span>`;
    pd.appendChild(line);
    pd.scrollTop = pd.scrollHeight;
  }
}

// ── Render results ───────────────────────────────────────────────────────────
function renderResults(panel, results, cfg) {
  rowData = [];
  if (!results || !results.length) {
    panel.innerHTML = '<div class="placeholder"><div class="ico">&#x1F4ED;</div><p>No results returned.</p></div>';
    return;
  }

  const tagInfo = cfg.tags && cfg.tags.length
    ? `<span class="run-tag">tags: ${esc(cfg.tags.join(", "))} (${cfg.tags_match})</span>` : "";
  const exprInfo = cfg.expression ? `<span class="run-tag">expr: ${esc(cfg.expression)}</span>` : "";
  const fmt = s => s.replace("T", " ");

  const header = `<div class="run-header">
    <span><strong>From</strong> ${esc(fmt(cfg.start_date))}</span>
    <span><strong>To</strong> ${esc(fmt(cfg.end_date))}</span>
    ${tagInfo}${exprInfo}
    <span class="spacer"></span>
    <span style="color:#9ca3af;margin-right:8px">${results.length} field${results.length!==1?"s":""}</span>
    <button class="btn-outline btn-sm" onclick="expandAllCards()" title="Expand all">&#x25BC; Expand</button>
    <button class="btn-outline btn-sm" onclick="collapseAllCards()" title="Collapse all">&#x25B6; Collapse</button>
    <button class="btn-outline" onclick="downloadReport()">&#x2193; Report</button>
  </div>
  <div id="bulkBar">
    <span class="b-count" id="bulkCount">0 selected</span>
    <span class="spacer"></span>
    <button onclick="bulkCorrelate()">&#x21C4; Correlate selected</button>
    <button onclick="bulkSessions()">&#x2261; Sessions for selected</button>
    <button onclick="bulkAllowlist()">&#x2713; Allowlist selected</button>
    <button onclick="clearSelection()">Clear</button>
  </div>`;

  let cards = "";
  for (const r of results) {
    lastResults[r.field] = r;
    cards += r.error ? errCard(r) : resultCard(r, cfg);
  }
  panel.innerHTML = header + cards;
  updateBulkBar();
}

function errCard(r) {
  return `<div class="err-card">
    <div class="err-title">&#x26A0;&#xFE0F; ${esc(r.field)}</div>
    <div>${esc(r.error)}</div>
    <div class="err-hint">Tip: check the field name, authentication, and date range.</div>
  </div>`;
}

function resultCard(r, cfg) {
  const maxTop  = r.top_n.length ? Math.max(...r.top_n.map(x => x.count)) : 1;
  const topKey  = `${r.field}::top`;
  const rareKey = `${r.field}::rare`;
  const cardId  = `card-${btoa(r.field).replace(/[^a-zA-Z0-9]/g, '')}`;

  // Register rows in rowData
  const topIdx  = r.top_n.map(row => {
    const i = rowData.length;
    rowData.push({field: r.field, value: row.value, count: row.count, bucket: "top"});
    return i;
  });
  const rareIdx = r.rare.map(row => {
    const i = rowData.length;
    rowData.push({field: r.field, value: row.value, count: row.count, bucket: "rare"});
    return i;
  });

  const topRows  = renderValueRows(r.field, r.top_n, topIdx,  topKey,  {maxC: maxTop, total: r.total_hits, anom: false});
  const rareRows = renderValueRows(r.field, r.rare,  rareIdx, rareKey, {maxC: cfg.rare_threshold, anom: cfg.anom_hints});

  return `<div class="card" data-field="${esc(r.field)}">
    <div class="card-header" onclick="toggleCard('${cardId}')">
      <span class="card-toggle" id="${cardId}-toggle">&#9654;</span>
      <div class="card-title">${esc(r.field)}</div>
      <div class="card-summary">${fmt(r.total_unique)} unique &middot; ${fmt(r.total_hits)} hits &middot; ${fmt(r.rare.length)} rare</div>
      <div class="card-btns" onclick="event.stopPropagation()">
        <button class="btn-outline btn-sm" onclick="dlCSV('${esc(r.field)}','top')">&#x2193; Top</button>
        <button class="btn-outline btn-sm" onclick="dlCSV('${esc(r.field)}','rare')">&#x2193; Rare</button>
      </div>
    </div>
    <div class="card-body" id="${cardId}" style="display:none">
      <div class="card-sub">${fmt(r.skipped)} allowlisted value${r.skipped!==1?"s":""} hidden</div>
      <div class="stats">
        <div class="stat"><div class="stat-val">${fmt(r.total_unique)}</div><div class="stat-lbl">Unique values</div></div>
        <div class="stat"><div class="stat-val">${fmt(r.total_hits)}</div><div class="stat-lbl">Total hits</div></div>
        <div class="stat"><div class="stat-val">${fmt(r.rare.length)}</div><div class="stat-lbl">Rare values</div></div>
      </div>
      <div class="tbl-label">
        <span>Top ${cfg.top_n} by frequency</span>
        <span class="card-search"><input type="text" placeholder="Filter…" oninput="filterCard('${esc(topKey)}', this.value)"></span>
      </div>
      <table data-tbl="${esc(topKey)}">
        <thead><tr>
          <th class="chk-col"><input type="checkbox" onchange="toggleCardSel('${esc(topKey)}', this.checked)"></th>
          <th class="sortable" onclick="event.stopPropagation();sortTable('${esc(topKey)}','value')">Value <span class="sort-ind"></span></th>
          <th class="r sortable" onclick="event.stopPropagation();sortTable('${esc(topKey)}','count')">Count <span class="sort-ind">&#x25BC;</span></th>
          <th class="r">%</th><th>Bar</th><th></th>
        </tr></thead>
        <tbody>${topRows}</tbody>
      </table>
      <div class="tbl-label">
        <span>Rare values &mdash; seen &le; ${cfg.rare_threshold} times</span>
        <span class="card-search"><input type="text" placeholder="Filter…" oninput="filterCard('${esc(rareKey)}', this.value)"></span>
      </div>
      <table data-tbl="${esc(rareKey)}">
        <thead><tr>
          <th class="chk-col"><input type="checkbox" onchange="toggleCardSel('${esc(rareKey)}', this.checked)"></th>
          <th class="sortable" onclick="event.stopPropagation();sortTable('${esc(rareKey)}','value')">Value <span class="sort-ind"></span></th>
          <th class="r sortable" onclick="event.stopPropagation();sortTable('${esc(rareKey)}','count')">Count <span class="sort-ind">&#x25BC;</span></th>
          <th>Bar</th>
          ${cfg.anom_hints ? '<th class="anom-col">Anomaly</th>' : ''}
          <th></th>
        </tr></thead>
        <tbody>${rareRows}</tbody>
      </table>
    </div>
  </div>`;
}

function renderValueRows(field, rows, indices, tblKey, opts) {
  if (!rows.length) {
    const cols = opts.anom ? 6 : (tblKey.endsWith("::top") ? 6 : 5);
    return `<tr><td class="empty" colspan="${cols}">No data</td></tr>`;
  }
  return rows.map((row, i) => {
    const ri = indices[i];
    const sel = selection.has(ri) ? " sel" : "";
    const isTop = tblKey.endsWith("::top");
    const pct  = isTop && opts.total ? (row.count / opts.total * 100).toFixed(1) : null;
    const barW = Math.round(row.count / opts.maxC * 100);
    const amber = !isTop ? " amber" : "";
    const anomCell = opts.anom ? `<td class="anom-col"><span class="anom-chip loading" data-anom="${esc(field)}||${esc(row.value)}">…</span></td>` : "";
    return `<tr class="row${sel}" data-ri="${ri}" data-tbl="${esc(tblKey)}" data-value="${esc(row.value).toLowerCase()}">
      <td class="chk-col"><input type="checkbox" ${selection.has(ri)?"checked":""} onchange="toggleRowSel(${ri}, this.checked)"></td>
      <td class="val">${esc(row.value)}</td>
      <td class="num r">${fmt(row.count)}</td>
      ${isTop ? `<td class="pct r">${pct}%</td>` : ""}
      <td class="bar-col"><div class="bar-bg"><div class="bar-fg${amber}" style="width:${barW}%"></div></div></td>
      ${anomCell}
      <td class="act-col">
        <button class="act-btn" onclick="openCorrelate(${ri})" title="Cross-field correlation">&#x21C4;</button>
        <button class="act-btn" onclick="openSessions(${ri})"  title="View sessions">&#x2261;</button>
        <button class="act-btn allow" onclick="allowlistRow(${ri})" title="Add to allowlist">&#x2713;</button>
      </td>
    </tr>`;
  }).join("");
}

// ── Sort / filter / select ───────────────────────────────────────────────────
function sortTable(tblKey, col) {
  const cur = sortState[tblKey] || {col: "count", dir: "desc"};
  const dir = (cur.col === col && cur.dir === "desc") ? "asc" : (cur.col === col ? "desc" : (col === "count" ? "desc" : "asc"));
  sortState[tblKey] = {col, dir};

  const [field, bucket] = tblKey.split("::");
  const r = lastResults[field];
  if (!r) return;
  const arr = bucket === "top" ? [...r.top_n] : [...r.rare];
  arr.sort((a, b) => {
    let av = a[col], bv = b[col];
    if (col === "value") { av = String(av).toLowerCase(); bv = String(bv).toLowerCase(); }
    if (av < bv) return dir === "asc" ? -1 : 1;
    if (av > bv) return dir === "asc" ? 1 : -1;
    return 0;
  });
  // Reassign to stored results so sort persists if re-rendered
  if (bucket === "top") lastResults[field].top_n = arr; else lastResults[field].rare = arr;
  rerenderCard(field);
}

function filterCard(tblKey, q) {
  searchState[tblKey] = q.toLowerCase();
  const tbl = document.querySelector(`table[data-tbl="${cssEsc(tblKey)}"]`);
  if (!tbl) return;
  tbl.querySelectorAll("tbody tr.row").forEach(tr => {
    const v = tr.getAttribute("data-value") || "";
    tr.style.display = (!q || v.includes(searchState[tblKey])) ? "" : "none";
  });
}

function toggleCard(cardId) {
  const body = document.getElementById(cardId);
  const toggle = document.getElementById(cardId + "-toggle");
  if (!body) return;
  const show = body.style.display === "none";
  body.style.display = show ? "" : "none";
  if (toggle) toggle.innerHTML = show ? "&#9660;" : "&#9654;";
}

function expandAllCards() {
  document.querySelectorAll(".card-body").forEach(el => el.style.display = "");
  document.querySelectorAll(".card-toggle").forEach(el => el.innerHTML = "&#9660;");
}

function collapseAllCards() {
  document.querySelectorAll(".card-body").forEach(el => el.style.display = "none");
  document.querySelectorAll(".card-toggle").forEach(el => el.innerHTML = "&#9654;");
}

function rerenderCard(field) {
  if (!lastCfg || !lastResults[field]) return;
  // Re-render just this card
  const cards = document.querySelectorAll(".card");
  for (const c of cards) {
    if (c.getAttribute("data-field") === field) {
      // Preserve expanded state
      const cardBody = c.querySelector(".card-body");
      const wasExpanded = cardBody && cardBody.style.display !== "none";

      const tmp = document.createElement("div");
      tmp.innerHTML = resultCard(lastResults[field], lastCfg);
      const newCard = tmp.firstElementChild;

      // Restore expanded state
      if (wasExpanded) {
        const newBody = newCard.querySelector(".card-body");
        const newToggle = newCard.querySelector(".card-toggle");
        if (newBody) newBody.style.display = "";
        if (newToggle) newToggle.innerHTML = "&#9660;";
      }

      c.replaceWith(newCard);
      // Reapply any live filter
      const topKey  = `${field}::top`;
      const rareKey = `${field}::rare`;
      if (searchState[topKey])  filterCard(topKey,  searchState[topKey]);
      if (searchState[rareKey]) filterCard(rareKey, searchState[rareKey]);
      // Reapply anomaly hints
      applyAnomalyChips();
      break;
    }
  }
}

function toggleRowSel(ri, on) {
  if (on) selection.add(ri); else selection.delete(ri);
  document.querySelectorAll(`tr[data-ri="${ri}"]`).forEach(tr => {
    tr.classList.toggle("sel", on);
    const cb = tr.querySelector("input[type=checkbox]");
    if (cb) cb.checked = on;
  });
  updateBulkBar();
}

function toggleCardSel(tblKey, on) {
  const tbl = document.querySelector(`table[data-tbl="${cssEsc(tblKey)}"]`);
  if (!tbl) return;
  tbl.querySelectorAll("tbody tr.row").forEach(tr => {
    if (tr.style.display === "none") return;
    const ri = parseInt(tr.getAttribute("data-ri"));
    if (Number.isFinite(ri)) toggleRowSel(ri, on);
  });
}

function clearSelection() {
  for (const ri of [...selection]) toggleRowSel(ri, false);
}

function updateBulkBar() {
  const bar = document.getElementById("bulkBar");
  const cnt = document.getElementById("bulkCount");
  if (!bar || !cnt) return;
  bar.classList.toggle("on", selection.size > 0);
  cnt.textContent = `${selection.size} selected`;
}

function selectedFieldGroup() {
  // Returns {field, values: [...]} only if all selected share a field
  const items = [...selection].map(ri => rowData[ri]).filter(Boolean);
  if (!items.length) return null;
  const field = items[0].field;
  if (items.some(x => x.field !== field)) return null;
  return {field, values: items.map(x => x.value)};
}

function bulkCorrelate() {
  const g = selectedFieldGroup();
  if (!g) { toast("Select values from a single field for bulk correlate", "err"); return; }
  openCorrelateBulk(g.field, g.values);
}

function bulkSessions() {
  const g = selectedFieldGroup();
  if (!g) { toast("Select values from a single field for bulk sessions", "err"); return; }
  openSessionsBulk(g.field, g.values);
}

function bulkAllowlist() {
  const items = [...selection].map(ri => rowData[ri]).filter(Boolean);
  if (!items.length) return;
  if (!confirm(`Add ${items.length} value${items.length!==1?"s":""} to the allowlist?`)) return;
  items.forEach(x => addToAllowlist(x.field, x.value));
  clearSelection();
}

function allowlistRow(ri) {
  const r = rowData[ri];
  if (r) addToAllowlist(r.field, r.value);
}

// ── Anomaly hints (async after results render) ───────────────────────────────
async function kickOffAnomalyHints(cfg, results) {
  // Collect all rare-value pairs
  const pairs = [];
  for (const r of results) {
    if (r.error || !r.rare) continue;
    for (const row of r.rare) pairs.push({field: r.field, value: row.value});
  }
  if (!pairs.length) return;

  // Chunk to be gentle on Arkime
  const CHUNK = 20;
  for (let i = 0; i < pairs.length; i += CHUNK) {
    const chunk = pairs.slice(i, i + CHUNK);
    try {
      const data = await apiFetch("/api/anomaly-hints", {...cfg, pairs: chunk});
      if (data.hints) {
        for (const h of data.hints) {
          anomHints[`${h.field}||${h.value}`] = h;
        }
        applyAnomalyChips();
      }
    } catch(_) { /* silent */ }
  }
}

function applyAnomalyChips() {
  document.querySelectorAll("span[data-anom]").forEach(el => {
    const key = el.getAttribute("data-anom");
    const h = anomHints[key];
    if (!h) return;
    if (h.error) {
      el.textContent = "n/a";
      el.title = h.error;
      el.classList.remove("loading");
      return;
    }
    const {src_count, top_share, top_src, total_hits} = h;
    let label = `${src_count} src`;
    let cls = "anom-chip";
    // Beacon shape: many hits concentrated on one src
    if (src_count === 1 && total_hits >= 2) {
      label = "1 src";
    } else if (top_share >= 0.9 && total_hits >= 3) {
      label = `${Math.round(top_share*100)}% 1 src`;
    }
    el.textContent = label;
    el.className = cls;
    el.title = `${src_count} distinct source IP${src_count!==1?"s":""}, ${total_hits} hit${total_hits!==1?"s":""}\nTop source: ${top_src || "n/a"} (${Math.round(top_share*100)}%)`;
  });
}

// ── Report download ──────────────────────────────────────────────────────────
function downloadReport() {
  if (!lastCfg) return;
  const results = Object.values(lastResults);
  const ts = new Date().toISOString().slice(0, 19).replace(/[-:T]/g, "").slice(0, 15);
  const genTime = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";

  let html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Luxray Analysis Report - ${genTime}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; color: #333; }
    h1 { color: #1e3a5f; border-bottom: 2px solid #3b82f6; padding-bottom: 10px; }
    h2 { color: #1e3a5f; margin-top: 30px; }
    h3 { color: #374151; margin-top: 20px; font-family: monospace; background: #e5e7eb; padding: 8px 12px; border-radius: 4px; }
    .meta { background: #fff; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
    .meta p { margin: 5px 0; }
    .meta strong { color: #1e3a5f; }
    .summary { display: flex; gap: 20px; flex-wrap: wrap; margin: 15px 0; }
    .stat { background: #e0e7ff; padding: 12px 20px; border-radius: 6px; text-align: center; }
    .stat-val { font-size: 1.5rem; font-weight: bold; color: #3730a3; }
    .stat-lbl { font-size: .8rem; color: #6366f1; }
    table { width: 100%; border-collapse: collapse; margin: 10px 0 25px 0; background: #fff; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
    th { background: #1e3a5f; color: #fff; padding: 10px 12px; text-align: left; font-size: .85rem; }
    td { padding: 8px 12px; border-bottom: 1px solid #e5e7eb; font-size: .85rem; }
    tr:last-child td { border-bottom: none; }
    tr:nth-child(even) { background: #f9fafb; }
    .val { font-family: monospace; word-break: break-all; }
    .num { text-align: right; }
    .section { background: #fff; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
    .bar { background: #dbeafe; height: 8px; border-radius: 4px; }
    .bar-fill { background: #3b82f6; height: 100%; border-radius: 4px; }
    .rare-bar .bar-fill { background: #f59e0b; }
    .tbl-title { font-weight: 600; color: #374151; margin: 15px 0 8px 0; font-size: .9rem; }
    .footer { text-align: center; color: #9ca3af; font-size: .8rem; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; }
  </style>
</head>
<body>
  <h1>Luxray Analysis Report</h1>
  <div class="meta">
    <p><strong>Generated:</strong> ${genTime}</p>
    <p><strong>Time Range:</strong> ${esc(lastCfg.start_date || '')} to ${esc(lastCfg.end_date || '')}</p>
    ${lastCfg.expression ? '<p><strong>Expression:</strong> <code>' + esc(lastCfg.expression) + '</code></p>' : ''}
    ${lastCfg.tags && lastCfg.tags.length ? '<p><strong>Tags:</strong> ' + esc(lastCfg.tags.join(', ')) + ' (' + lastCfg.tags_match + ')</p>' : ''}
    <p><strong>Fields Analyzed:</strong> ${results.length}</p>
  </div>
`;

  for (const r of results) {
    if (r.error) {
      html += '<div class="section"><h3>' + esc(r.field) + '</h3><p style="color:#dc2626">Error: ' + esc(r.error) + '</p></div>';
      continue;
    }

    const maxTop = r.top_n.length ? r.top_n[0].count : 1;
    const rareThresh = lastCfg.rare_threshold || 3;

    html += `
  <div class="section">
    <h3>${esc(r.field)}</h3>
    <div class="summary">
      <div class="stat"><div class="stat-val">${fmt(r.total_unique)}</div><div class="stat-lbl">Unique Values</div></div>
      <div class="stat"><div class="stat-val">${fmt(r.total_hits)}</div><div class="stat-lbl">Total Hits</div></div>
      <div class="stat"><div class="stat-val">${fmt(r.rare.length)}</div><div class="stat-lbl">Rare Values</div></div>
      <div class="stat"><div class="stat-val">${fmt(r.skipped)}</div><div class="stat-lbl">Allowlisted</div></div>
    </div>

    <div class="tbl-title">Top ${r.top_n.length} by Frequency</div>
    <table>
      <thead><tr><th>Value</th><th class="num">Count</th><th class="num">%</th><th style="width:150px">Distribution</th></tr></thead>
      <tbody>
        ${r.top_n.map(row => {
          const pct = r.total_hits ? (row.count / r.total_hits * 100).toFixed(1) : 0;
          const barW = Math.round(row.count / maxTop * 100);
          return '<tr><td class="val">' + esc(String(row.value)) + '</td><td class="num">' + fmt(row.count) + '</td><td class="num">' + pct + '%</td><td><div class="bar"><div class="bar-fill" style="width:' + barW + '%"></div></div></td></tr>';
        }).join('')}
      </tbody>
    </table>

    <div class="tbl-title">Rare Values (seen ≤ ${rareThresh} times)</div>
    <table>
      <thead><tr><th>Value</th><th class="num">Count</th><th style="width:150px">Distribution</th></tr></thead>
      <tbody>
        ${r.rare.length ? r.rare.map(row => {
          const barW = Math.round(row.count / rareThresh * 100);
          return '<tr><td class="val">' + esc(String(row.value)) + '</td><td class="num">' + fmt(row.count) + '</td><td><div class="bar rare-bar"><div class="bar-fill" style="width:' + barW + '%"></div></div></td></tr>';
        }).join('') : '<tr><td colspan="3" style="color:#9ca3af;text-align:center">No rare values</td></tr>'}
      </tbody>
    </table>
  </div>
`;
  }

  html += `
  <div class="footer">
    Generated by Luxray - Network Traffic Analyzer
  </div>
</body>
</html>`;

  const blob = new Blob([html], {type: "text/html"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = 'luxray_report_' + ts + '.html';
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── Download Top/Rare as HTML ────────────────────────────────────────────────
function dlCSV(field, label) {
  const r = lastResults[field];
  if (!r) return;
  const rows = label === "top" ? r.top_n : r.rare;
  const safe = field.replace(/\./g, "_");
  const ts   = new Date().toISOString().slice(0, 19).replace(/[-:T]/g, "").slice(0, 15);
  const totalCount = rows.reduce((sum, row) => sum + row.count, 0);
  const maxCount = rows.length ? Math.max(...rows.map(x => x.count)) : 1;
  const isDark = document.body.classList.contains("dark");
  const labelCap = label === "top" ? "Top Values" : "Rare Values";

  let html = '<!DOCTYPE html><html><head><meta charset="UTF-8">';
  html += '<title>' + esc(field) + ' - ' + labelCap + '</title>';
  html += '<style>';
  html += 'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;padding:20px;';
  html += isDark ? 'background:#1a1a2e;color:#e0e0e0;}' : 'background:#f5f5f5;color:#333;}';
  html += '.container{max-width:900px;margin:0 auto;}';
  html += 'h1{font-size:1.5em;margin-bottom:5px;}';
  html += '.meta{font-size:0.85em;color:#888;margin-bottom:20px;}';
  html += '.summary{display:flex;gap:20px;margin-bottom:20px;}';
  html += '.stat{padding:12px 20px;border-radius:8px;' + (isDark ? 'background:#252542;' : 'background:#fff;box-shadow:0 1px 3px rgba(0,0,0,0.1);') + '}';
  html += '.stat-label{font-size:0.75em;text-transform:uppercase;color:#888;}';
  html += '.stat-value{font-size:1.3em;font-weight:600;}';
  html += 'table{width:100%;border-collapse:collapse;' + (isDark ? 'background:#252542;' : 'background:#fff;') + 'border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);}';
  html += 'th,td{padding:10px 14px;text-align:left;border-bottom:1px solid ' + (isDark ? '#3a3a5a;' : '#eee;') + '}';
  html += 'th{' + (isDark ? 'background:#1e1e36;' : 'background:#f9f9f9;') + 'font-weight:600;font-size:0.85em;text-transform:uppercase;}';
  html += 'tr:last-child td{border-bottom:none;}';
  html += 'tr:hover{' + (isDark ? 'background:#2a2a4a;' : 'background:#f5f5ff;') + '}';
  html += '.bar-cell{width:150px;}';
  html += '.bar{height:18px;border-radius:3px;' + (isDark ? 'background:#6366f1;' : 'background:#818cf8;') + '}';
  html += '.count{font-weight:600;}';
  html += '.pct{color:#888;font-size:0.9em;}';
  html += '</style></head><body><div class="container">';
  html += '<h1>' + esc(field) + ' - ' + labelCap + '</h1>';
  html += '<div class="meta">Generated: ' + new Date().toLocaleString() + '</div>';
  html += '<div class="summary">';
  html += '<div class="stat"><div class="stat-label">Total Values</div><div class="stat-value">' + fmt(rows.length) + '</div></div>';
  html += '<div class="stat"><div class="stat-label">Total Sessions</div><div class="stat-value">' + fmt(totalCount) + '</div></div>';
  html += '</div>';
  html += '<table><thead><tr><th>Value</th><th>Count</th><th>%</th><th class="bar-cell">Distribution</th></tr></thead><tbody>';

  for (const row of rows) {
    const pct = totalCount > 0 ? ((row.count / totalCount) * 100).toFixed(1) : '0.0';
    const barW = maxCount > 0 ? Math.round((row.count / maxCount) * 100) : 0;
    html += '<tr>';
    html += '<td>' + esc(row.value) + '</td>';
    html += '<td class="count">' + fmt(row.count) + '</td>';
    html += '<td class="pct">' + pct + '%</td>';
    html += '<td class="bar-cell"><div class="bar" style="width:' + barW + '%"></div></td>';
    html += '</tr>';
  }

  html += '</tbody></table></div></body></html>';

  const a = document.createElement("a");
  a.href     = URL.createObjectURL(new Blob([html], {type: "text/html"}));
  a.download = `arkime_${safe}_${label}_${ts}.html`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}
function cssEsc(s) { return String(s).replace(/"/g, '\\"'); }
function fmt(n) { return Number(n).toLocaleString(); }

async function apiFetch(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-CSRF-Token": window.__CSRF},
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Server error: HTTP ${res.status}`);
  return res.json();
}

function showError(panel, title, msg) {
  panel.innerHTML = `<div class="err-card"><div class="err-title">${esc(title)}</div>${esc(msg)}</div>`;
}

function toast(msg, kind) {
  const t = document.createElement("div");
  t.className = "toast " + (kind || "");
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .2s"; }, 2200);
  setTimeout(() => t.remove(), 2500);
}

// ── Settings persistence ─────────────────────────────────────────────────────
async function loadSettingsFromServer() {
  try {
    const res = await fetch("/api/settings");
    if (!res.ok) return;
    const saved = await res.json();
    if (saved && !saved.error && Object.keys(saved).length) {
      loadConfig(saved);
      toggleAuth();
      // Auto-connect if credentials are present
      if (saved.url && saved.username && saved.password) {
        setTimeout(() => testConn(), 100);
      }
    }
  } catch (_) {}
}

function saveSettingsToServer(cfg) {
  fetch("/api/settings", {
    method:  "POST",
    headers: {"Content-Type": "application/json", "X-CSRF-Token": window.__CSRF},
    body:    JSON.stringify(cfg),
  }).catch(() => {});
}

// ── Modal ────────────────────────────────────────────────────────────────────
function openModal() { document.getElementById("modalOverlay").classList.add("open"); }
function closeModal() {
  document.getElementById("modalOverlay").classList.remove("open");
  corrStack = [];
}
function maybeCloseModal(e) {
  if (e.target === document.getElementById("modalOverlay")) closeModal();
}
document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });

// ── Correlate (single + bulk + chained) ──────────────────────────────────────
const COMMON_FIELDS = [
  "ip.src","ip.dst","port.src","port.dst",
  "http.useragent","http.uri","http.method","http.statuscode",
  "dns.host","dns.query.type","protocols",
  "tls.ja3","tls.ja3s","cert.issuer","cert.subject","tags","node",
];

function openCorrelate(ri) {
  const row = rowData[ri];
  corrStack = [{field: row.field, values: [row.value], match: "any"}];
  showCorrelateStep();
}

function openCorrelateBulk(field, values) {
  corrStack = [{field, values, match: "any"}];
  showCorrelateStep();
}

function pushPivot(field, value) {
  corrStack.push({field, values: [value], match: "any"});
  showCorrelateStep();
}

function popToCrumb(i) {
  corrStack = corrStack.slice(0, i + 1);
  showCorrelateStep();
}

function showCorrelateStep() {
  const last = corrStack[corrStack.length - 1];
  const title = corrStack.length > 1 ? "Chained Correlation" : "Cross-field Correlation";
  const pivotDesc = last.values.length === 1
    ? `${last.field} = "${truncate(last.values[0], 60)}"`
    : `${last.field} in [${last.values.length} values]`;

  document.getElementById("modalTitle").textContent = title;
  document.getElementById("modalSub").textContent   = pivotDesc;

  const crumbs = corrStack.map((c, i) => {
    const label = c.values.length === 1 ? `${c.field}=${truncate(c.values[0], 30)}` : `${c.field}×${c.values.length}`;
    const cls = i === corrStack.length - 1 ? " active" : "";
    return `<span class="crumb${cls}" onclick="popToCrumb(${i})" style="cursor:pointer" title="Jump back to this step">${esc(label)}</span>`;
  }).join(`<span class="sep">&rsaquo;</span>`);

  const opts = [...new Set([...COMMON_FIELDS, ...fields])]
    .filter(f => f !== last.field)
    .map(f => `<option value="${esc(f)}">${esc(f)}</option>`)
    .join("");

  document.getElementById("modalBody").innerHTML = `
    <div class="breadcrumbs">${crumbs}</div>
    <div class="modal-toolbar">
      <label>Compare against:</label>
      <select id="corrSelect" style="flex:1">${opts}</select>
      <input type="text" id="corrCustom" placeholder="or type any field name" style="flex:1">
      <button class="btn-primary" style="width:auto;padding:7px 18px" onclick="runCorrelate()">Run</button>
    </div>
    <div id="corrOut"></div>`;

  openModal();
}

async function runCorrelate() {
  const last = corrStack[corrStack.length - 1];
  const target = document.getElementById("corrCustom").value.trim()
               || document.getElementById("corrSelect").value;
  if (!target) { toast("Select or type a field to correlate against.", "err"); return; }

  document.getElementById("corrOut").innerHTML =
    '<div style="text-align:center;padding:24px"><div class="spinner" style="margin:0 auto"></div></div>';

  const cfg = getConfig();
  cfg.pivot_field  = last.field;
  cfg.pivot_values = last.values;
  cfg.pivot_match  = last.match;
  cfg.target_field = target;
  // Extra pin (e.g., pinning a signature while pivoting on a port) is passed
  // as an additional clause merged into `expression`.
  if (last.extra_pin && last.extra_pin.field && last.extra_pin.value !== undefined) {
    const ev = String(last.extra_pin.value).replace(/\\/g,"\\\\").replace(/"/g,'\\"');
    const clause = `${last.extra_pin.field} == "${ev}"`;
    cfg.expression = cfg.expression ? `(${cfg.expression}) && ${clause}` : clause;
  }

  try {
    const data = await apiFetch("/api/correlate", cfg);
    if (data.error) {
      document.getElementById("corrOut").innerHTML = `<div class="err-card">${esc(data.error)}</div>`;
      return;
    }
    const res  = data.results;
    const tot  = data.total;
    const maxC = res.length ? res[0].count : 1;

    const rows = res.map(r => {
      const pct  = tot ? (r.count / tot * 100).toFixed(1) : "0.0";
      const barW = Math.round(r.count / maxC * 100);
      return `<tr>
        <td class="val">${esc(r.value)}</td>
        <td class="num r">${fmt(r.count)}</td>
        <td class="pct r">${pct}%</td>
        <td class="bar-col"><div class="bar-bg"><div class="bar-fg" style="width:${barW}%"></div></div></td>
        <td class="act-col">
          <button class="act-btn" onclick="pushPivot('${jsStr(target)}','${jsStr(r.value)}')" title="Pivot further">&#x21C4;</button>
          <button class="act-btn" onclick="openSessionsFromCorr('${jsStr(target)}','${jsStr(r.value)}')" title="View sessions">&#x2261;</button>
        </td>
      </tr>`;
    }).join("") || `<tr><td class="empty" colspan="5">No results</td></tr>`;

    document.getElementById("corrOut").innerHTML = `
      <div class="corr-expr">Expression: ${esc(data.expression)}</div>
      <div class="modal-count">Distribution of <strong>${esc(target)}</strong> — ${fmt(tot)} total hits across ${fmt(data.total_unique || res.length)} unique values</div>
      <table>
        <thead><tr><th>Value</th><th class="r">Count</th><th class="r">%</th><th>Bar</th><th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  } catch(e) {
    document.getElementById("corrOut").innerHTML = `<div class="err-card">${esc(e.message)}</div>`;
  }
}

function openSessionsFromCorr(field, value) {
  // Open sessions modal while preserving the current correlate context
  openSessionsRaw(field, [value]);
}

// ── Sessions (single + bulk) ─────────────────────────────────────────────────
function openSessions(ri) {
  const row = rowData[ri];
  openSessionsRaw(row.field, [row.value]);
}
function openSessionsBulk(field, values) {
  openSessionsRaw(field, values);
}

async function openSessionsRaw(field, values, pin) {
  const pinDesc = pin && pin.field && pin.value !== undefined ? ` (pinned ${pin.field}="${truncate(pin.value, 40)}")` : "";
  const desc = (values.length === 1 ? `${field} = "${truncate(values[0], 60)}"`
                                    : `${field} in [${values.length} values]`) + pinDesc;
  document.getElementById("modalTitle").textContent = "Session Drilldown";
  document.getElementById("modalSub").textContent   = desc;
  document.getElementById("modalBody").innerHTML    =
    '<div style="text-align:center;padding:30px"><div class="spinner" style="margin:0 auto"></div></div>';
  openModal();

  const cfg = getConfig();
  cfg.pivot_field  = field;
  cfg.pivot_values = values;
  cfg.pivot_match  = "any";
  cfg.session_limit = 200;
  if (pin && pin.field && pin.value !== undefined) {
    const ev = String(pin.value).replace(/\\/g,"\\\\").replace(/"/g,'\\"');
    const clause = `${pin.field} == "${ev}"`;
    cfg.expression = cfg.expression ? `(${cfg.expression}) && ${clause}` : clause;
  }

  try {
    const data = await apiFetch("/api/sessions", cfg);
    if (data.error) {
      document.getElementById("modalBody").innerHTML =
        `<div class="err-card"><div class="err-title">Error</div>${esc(data.error)}</div>`;
      return;
    }
    renderSessionsInto("modalBody", data);
  } catch(e) {
    document.getElementById("modalBody").innerHTML =
      `<div class="err-card"><div class="err-title">Error</div>${esc(e.message)}</div>`;
  }
}

// IP protocol number to name mapping
const IP_PROTO_MAP = {1:"ICMP",6:"TCP",17:"UDP",47:"GRE",50:"ESP",51:"AH",58:"ICMPv6",132:"SCTP"};

let sessionData = [];  // for sorting
let sessionSortCol = null;
let sessionSortDir = 1;

function renderSessionsInto(bodyId, data) {
  sessionData = data.sessions || [];
  const total = data.total || 0;

  if (!sessionData.length) {
    document.getElementById(bodyId).innerHTML =
      '<div class="empty">No sessions found for this value in the selected time range.</div>';
    return;
  }

  sessionSortCol = null;
  sessionSortDir = 1;
  renderSessionTable(bodyId, data.expression, total);
}

function renderSessionTable(bodyId, expression, total) {
  const baseUrl = document.getElementById("url").value.trim();
  const cleanBase = baseUrl.replace(/\/+$/, "");

  const rows = sessionData.map(s => {
    // Handle both flat (when fields= specified) and nested Arkime response formats
    const srcIp   = s["ip.src"] || s.source?.ip || s.srcIp || "—";
    const dstIp   = s["ip.dst"] || s.destination?.ip || s.dstIp || "—";
    const srcPort = s["port.src"] || s.source?.port || s.srcPort || "";
    const dstPort = s["port.dst"] || s.destination?.port || s.dstPort || "";
    const ipProto = s.ipProtocol;
    const proto   = Array.isArray(s.protocols) && s.protocols.length ? s.protocols.join(", ")
                  : (s.protocols || IP_PROTO_MAP[ipProto] || (ipProto ? `IP:${ipProto}` : "—"));
    const bytes   = s["network.bytes"] || s.network?.bytes || s.totDataBytes || s.totBytes || 0;
    const pkts    = s["network.packets"] || s.network?.packets || s.packets || s.totPackets || 0;
    const tagsVal = Array.isArray(s.tags) ? s.tags.join(", ") : (s.tags || "");
    const node    = s.node || "";
    const fmtB    = bytes > 1048576 ? (bytes/1048576).toFixed(1)+"M"
                  : bytes > 1024    ? (bytes/1024).toFixed(1)+"K"
                  : bytes+"B";
    const fp = s.firstPacket, lp = s.lastPacket;
    const ts = fp ? new Date(fp).toISOString().replace("T"," ").slice(0,19) : "—";
    const durMs = (fp && lp) ? (lp - fp) : 0;
    const dur = !durMs ? "—"
              : durMs < 1000     ? `${durMs}ms`
              : durMs < 60000    ? `${(durMs/1000).toFixed(1)}s`
              : durMs < 3600000  ? `${(durMs/60000).toFixed(1)}m`
              : `${(durMs/3600000).toFixed(1)}h`;

    const sid     = s.id || "";
    // Session ID format is "dbIndex@sessionId" - extract the sessionId part for search
    const sessionId = sid.includes("@") ? sid.split("@")[1] : sid;
    const sStart  = fp ? Math.floor(fp/1000) : 0;
    const sEnd    = lp ? Math.floor(lp/1000)+1 : sStart+1;
    // Link to sessions page - search by sessionId without the db prefix
    const arkLink = sessionId
      ? `${cleanBase}/sessions?date=-1&startTime=${sStart}&stopTime=${sEnd}&expression=${encodeURIComponent('id=='+sessionId)}`
      : "";

    // Store computed values for sorting
    s._bytes = bytes;
    s._pkts = pkts;
    s._dur = durMs;

    return `<tr>
      <td style="white-space:nowrap;font-size:.72rem;color:var(--text-3)">${ts}</td>
      <td class="val">${esc(srcIp)}${srcPort ? ":"+srcPort : ""}</td>
      <td class="val">${esc(dstIp)}${dstPort ? ":"+dstPort : ""}</td>
      <td style="font-size:.75rem">${esc(proto)}</td>
      <td class="num r">${fmtB}</td>
      <td class="num r">${fmt(pkts)}</td>
      <td class="num r" style="font-size:.72rem;color:var(--text-3)">${dur}</td>
      <td class="val" style="font-size:.7rem;color:var(--text-3)">${esc(tagsVal)}</td>
      <td style="font-size:.7rem;color:var(--text-4)">${esc(node)}</td>
      <td>${arkLink
        ? `<a href="${esc(arkLink)}" target="_blank" style="color:#3b82f6;text-decoration:none;font-size:.75rem" title="Open in Arkime">&#x2197;</a>`
        : ""}</td>
    </tr>`;
  }).join("");

  const countNote = total > sessionData.length
    ? `Showing ${sessionData.length} of ${fmt(total)} sessions`
    : `${fmt(total)} session${total !== 1 ? "s" : ""}`;

  const sortInd = (col) => sessionSortCol === col ? (sessionSortDir > 0 ? " &#9650;" : " &#9660;") : "";

  document.getElementById(bodyId).innerHTML = `
    <div class="corr-expr">Expression: ${esc(expression)}</div>
    <div class="modal-count">${countNote}</div>
    <table>
      <thead><tr>
        <th class="sortable" onclick="sortSessions('time','${bodyId}','${jsStr(expression)}',${total})">Time${sortInd('time')}</th>
        <th>Source</th><th>Destination</th><th>Protocol</th>
        <th class="r sortable" onclick="sortSessions('bytes','${bodyId}','${jsStr(expression)}',${total})">Bytes${sortInd('bytes')}</th>
        <th class="r sortable" onclick="sortSessions('pkts','${bodyId}','${jsStr(expression)}',${total})">Pkts${sortInd('pkts')}</th>
        <th class="r sortable" onclick="sortSessions('dur','${bodyId}','${jsStr(expression)}',${total})">Dur${sortInd('dur')}</th>
        <th>Tags</th><th>Node</th><th></th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function sortSessions(col, bodyId, expression, total) {
  if (sessionSortCol === col) {
    sessionSortDir *= -1;
  } else {
    sessionSortCol = col;
    sessionSortDir = -1;  // default descending for numeric
  }
  const key = col === 'time' ? 'firstPacket' : col === 'bytes' ? '_bytes' : col === 'pkts' ? '_pkts' : '_dur';
  sessionData.sort((a, b) => ((a[key] || 0) - (b[key] || 0)) * sessionSortDir);
  renderSessionTable(bodyId, expression, total);
}

function truncate(s, n) { return String(s).length > n ? String(s).slice(0, n-1) + "…" : String(s); }
function jsStr(s) { return String(s).replace(/\\/g,"\\\\").replace(/'/g,"\\'").replace(/\n/g,"\\n"); }

// Sort port scan tables by session count
function sortPsTable(tableId, order) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const tbody = table.querySelector("tbody");
  if (!tbody) return;
  const rows = Array.from(tbody.querySelectorAll("tr"));
  rows.sort((a, b) => {
    const aVal = parseInt(a.dataset.sessions || "0", 10);
    const bVal = parseInt(b.dataset.sessions || "0", 10);
    return order === "desc" ? bVal - aVal : aVal - bVal;
  });
  rows.forEach(row => tbody.appendChild(row));
}

// ── Port Anomaly Scan ────────────────────────────────────────────────────────
let lastPortScan = null;       // most recent mode-1 scan result (for baselining)
let baselineList = [];
const portScanCache = {};      // per-mode result cache: { mode: { data, cfg } }

function togglePortScan() {
  const body = document.getElementById("portScanBody");
  const btn  = document.getElementById("portScanToggle");
  const show = body.style.display === "none";
  body.style.display = show ? "" : "none";
  btn.textContent = show ? "Hide" : "Show";
  if (show) { refreshBaselines(); refreshPsPresets(); }
}

// ── Byte pattern helpers (mode 4) ─────────────────────────────────────────────
let bytePatternId = 0;

function addBytePattern(pattern = "", type = "hex", ports = "") {
  const id = bytePatternId++;
  const container = document.getElementById("bytePatternList");
  const div = document.createElement("div");
  div.className = "byte-pattern-row";
  div.id = `bp-${id}`;
  div.innerHTML = `
    <div style="display:flex;gap:6px;align-items:center;margin-bottom:6px">
      <select id="bpType-${id}" style="width:80px">
        <option value="hex" ${type === "hex" ? "selected" : ""}>Hex</option>
        <option value="ascii" ${type === "ascii" ? "selected" : ""}>ASCII</option>
      </select>
      <input type="text" id="bpPattern-${id}" placeholder="Pattern (e.g. 5a5a5a5a or malware.com)" value="${esc(pattern)}" style="flex:1">
      <button class="btn-icon" onclick="removeBytePattern(${id})" title="Remove">&times;</button>
    </div>
    <div style="display:flex;gap:6px;align-items:center;margin-bottom:8px">
      <span style="font-size:.75rem;color:var(--text-3);white-space:nowrap">Expected ports:</span>
      <input type="text" id="bpPorts-${id}" placeholder="e.g. 443, 8443" value="${esc(ports)}" style="flex:1">
    </div>
  `;
  container.appendChild(div);
}

function removeBytePattern(id) {
  const el = document.getElementById(`bp-${id}`);
  if (el) el.remove();
}

function getBytePatterns() {
  const patterns = [];
  document.querySelectorAll("[id^='bp-']").forEach(div => {
    const id = div.id.replace("bp-", "");
    const typeEl = document.getElementById(`bpType-${id}`);
    const patternEl = document.getElementById(`bpPattern-${id}`);
    const portsEl = document.getElementById(`bpPorts-${id}`);
    if (!typeEl || !patternEl || !portsEl) return;
    const pattern = patternEl.value.trim();
    if (!pattern) return;
    const portsStr = portsEl.value.trim();
    const ports = portsStr ? portsStr.split(/[,\\s]+/).map(p => parseInt(p.trim())).filter(p => !isNaN(p)) : [];
    patterns.push({
      pattern: pattern,
      type: typeEl.value,
      expected_ports: ports
    });
  });
  return patterns;
}

function renderPortScanMode() {
  const mode = document.getElementById("psMode").value;
  document.getElementById("psMode_sig_to_port").style.display   = mode === "sig_to_port"   ? "" : "none";
  document.getElementById("psMode_port_to_sig").style.display   = mode === "port_to_sig"   ? "" : "none";
  document.getElementById("psMode_host_diversity").style.display= mode === "host_diversity"? "" : "none";
  document.getElementById("psMode_byte_pattern").style.display  = mode === "byte_pattern"  ? "" : "none";
  document.getElementById("psBaselineBlock").style.display      = mode === "sig_to_port"   ? "" : "none";

  // Restore cached results for this mode if available
  const cached = portScanCache[mode];
  if (cached) {
    const panel = document.getElementById("results");
    renderPortScanResults(panel, cached.data, cached.cfg);
  }
}

function psSignatureField() {
  const mode = document.getElementById("psMode").value;
  if (mode === "sig_to_port") {
    return document.getElementById("psSigField").value.trim();
  }
  if (mode === "port_to_sig") {
    return document.getElementById("psSigField2").value.trim();
  }
  return "";
}

function parsePortsList() {
  return document.getElementById("psPortsList").value.split(/\s+/).map(s => s.trim()).filter(Boolean);
}

function parseExpectations() {
  const out = {};
  for (const line of document.getElementById("psExpectations").value.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const colon = t.indexOf(":");
    if (colon === -1) continue;
    const port = t.slice(0, colon).trim();
    const sigs = t.slice(colon + 1).split(",").map(x => x.trim().toLowerCase()).filter(Boolean);
    if (port && sigs.length) out[port] = sigs;
  }
  return out;
}

async function loadDefaultPorts() {
  try {
    const res = await fetch("/api/port-expectations-default");
    if (!res.ok) return;
    const data = await res.json();
    const ex = data.expectations || {};
    document.getElementById("psPortsList").value  = Object.keys(ex).sort((a,b)=>parseInt(a)-parseInt(b)).join("\n");
    document.getElementById("psExpectations").value = Object.entries(ex)
      .sort((a,b) => parseInt(a[0]) - parseInt(b[0]))
      .map(([p, sigs]) => `${p}: ${sigs.join(",")}`).join("\n");
    toast("Default ports loaded", "ok");
  } catch(e) { toast("Failed to load defaults: " + e.message, "err"); }
}

function getPortScanCfg() {
  const base = getConfig();
  const mode = document.getElementById("psMode").value;
  const out = {...base, mode};
  if (mode === "sig_to_port") {
    out.signature_field = psSignatureField();
    out.port_field      = document.getElementById("psPortField").value.trim() || "port";
    out.min_sessions    = parseInt(document.getElementById("psMinSessions").value) || 10;
    out.max_sigs        = parseInt(document.getElementById("psMaxSigs").value) || 100;
    out.dominance       = parseFloat(document.getElementById("psDominance").value) || 0.9;
    out.outlier_max     = parseInt(document.getElementById("psOutlierMax").value) || 3;
  } else if (mode === "port_to_sig") {
    out.signature_field   = psSignatureField() || "protocols";
    out.port_field        = document.getElementById("psPortField2").value.trim() || "port";
    out.ports_to_check    = parsePortsList();
    out.port_expectations = parseExpectations();
  } else if (mode === "host_diversity") {
    out.port_field            = document.getElementById("psPortField3").value.trim() || "port";
    out.signature_field       = document.getElementById("psPinField").value.trim();
    out.pinned_signature_value= document.getElementById("psPinValue").value;
    out.min_sessions          = parseInt(document.getElementById("psMinSessions3").value) || 20;
    out.min_distinct_ports    = parseInt(document.getElementById("psMinDistinctPorts").value) || 10;
    out.port_ratio_threshold  = parseFloat(document.getElementById("psPortRatio").value) || 0.4;
    out.max_hosts             = parseInt(document.getElementById("psMaxHosts").value) || 100;
  } else if (mode === "byte_pattern") {
    out.port_field       = document.getElementById("psPortField4").value.trim() || "port";
    out.patterns         = getBytePatterns();
    out.hunt_max_packets = parseInt(document.getElementById("psHuntMaxPackets").value) || 10000;
    out.hunt_timeout     = parseInt(document.getElementById("psHuntTimeout").value) || 300;
    out.cleanup_hunts    = document.getElementById("psCleanupHunts").value === "true";
  }
  return out;
}

let psXhr = null;  // track current port scan request

async function runPortScan() {
  const cfg = getPortScanCfg();
  if (!cfg.url) { toast("Please enter an Arkime URL.", "err"); return; }
  if (cfg.mode === "sig_to_port" && !cfg.signature_field) { toast("Signature field is required", "err"); return; }
  if (cfg.mode === "port_to_sig" && !cfg.ports_to_check.length) { toast("Add at least one port to check", "err"); return; }
  if (cfg.mode === "byte_pattern" && !cfg.patterns.length) { toast("Add at least one byte pattern", "err"); return; }

  const panel = document.getElementById("results");
  panel.innerHTML = `
    <div class="loading">
      <div class="spinner"></div>
      <div class="prog-wrap">
        <div class="prog-text" id="progText">Starting port scan…</div>
        <div class="prog-bar"><div class="prog-fill" id="progFill"></div></div>
        <div class="prog-done" id="progDone"></div>
      </div>
    </div>`;
  document.getElementById("psRunBtn").disabled = true;
  document.getElementById("psStopBtn").style.display = "";

  try {
    const data = await runPortScanStreaming(cfg);
    if (data.error) { showError(panel, "Port scan failed", data.error); return; }
    renderPortScanResults(panel, data, cfg);

    // Cache result for this mode
    portScanCache[cfg.mode] = { data, cfg };

    // Mode 1: if a baseline is selected, compare
    if (cfg.mode === "sig_to_port") {
      lastPortScan = data;
      const baselineName = document.getElementById("psBaselineSelect").value;
      if (baselineName) {
        await runBaselineCompare(baselineName, data);
      }
    }
  } catch(e) {
    if (e.message !== "Stopped by user") {
      showError(panel, "Port scan error", e.message);
    }
  } finally {
    document.getElementById("psRunBtn").disabled = false;
    document.getElementById("psStopBtn").style.display = "none";
    psXhr = null;
  }
}

function stopPortScan() {
  if (psXhr) {
    psXhr.abort();
    psXhr = null;
    const panel = document.getElementById("results");
    panel.innerHTML = `<div class="placeholder"><div class="ico">&#x1F6D1;</div><p>Port scan stopped.</p></div>`;
    toast("Port scan stopped", "ok");
  }
  document.getElementById("psRunBtn").disabled = false;
  document.getElementById("psStopBtn").style.display = "none";
}

function runPortScanStreaming(cfg) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    psXhr = xhr;  // store globally for stop functionality
    xhr.open("POST", "/api/port-scan-stream", true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.setRequestHeader("X-CSRF-Token", window.__CSRF);
    let lastIdx = 0;
    let finalResult = null;
    let stopped = false;

    xhr.onreadystatechange = function() {
      if (xhr.readyState >= 3) {
        const chunk = xhr.responseText.slice(lastIdx);
        lastIdx = xhr.responseText.length;
        const events = chunk.split("\n\n");
        for (const ev of events) {
          if (!ev.trim()) continue;
          const lines = ev.split("\n");
          let eventType = "message", dataStr = "";
          for (const ln of lines) {
            if (ln.startsWith("event:")) eventType = ln.slice(6).trim();
            else if (ln.startsWith("data:")) dataStr += ln.slice(5).trim();
          }
          if (!dataStr) continue;
          try {
            const payload = JSON.parse(dataStr);
            if (eventType === "progress") updatePortScanProgress(payload);
            else if (eventType === "result") finalResult = payload;
            else if (eventType === "error") { reject(new Error(payload.error || "Unknown")); xhr.abort(); return; }
          } catch(_) {}
        }
      }
      if (xhr.readyState === 4) {
        if (finalResult) resolve(finalResult);
        else if (xhr.status === 0) reject(new Error("Stopped by user"));
        else reject(new Error(`HTTP ${xhr.status}`));
      }
    };
    xhr.onerror = () => reject(new Error("Network error"));
    xhr.send(JSON.stringify(cfg));
  });
}

function updatePortScanProgress(p) {
  const total = p.total || 1;
  const done  = p.done || 0;
  const pct   = Math.round(done / total * 100);
  const pt = document.getElementById("progText");
  const pf = document.getElementById("progFill");
  const pd = document.getElementById("progDone");
  if (!pt || !pf) return;
  pf.style.width = pct + "%";
  if (done === 0) {
    pt.innerHTML = `Scanning <strong>${total}</strong> items in parallel…`;
  } else if (done === total) {
    pt.innerHTML = `<strong>${done}/${total}</strong> complete — finalising…`;
  } else {
    pt.innerHTML = `<strong>${done}/${total}</strong> scanned`;
  }
  if (p.item && pd) {
    const line = document.createElement("div");
    line.innerHTML = `&#x2713; <span class="prog-field">${esc(truncate(p.item, 60))}</span>`;
    pd.appendChild(line);
    pd.scrollTop = pd.scrollHeight;
  }
}

// ── Port scan results renderer ───────────────────────────────────────────────
function renderPortScanResults(panel, data, cfg) {
  rowData = [];
  selection.clear();
  updateBulkBar();

  const mode = data.mode;
  const fmtDate = s => (s || "").replace("T", " ");
  const header = `<div class="run-header">
    <span><strong>Port Scan</strong></span>
    <span class="run-tag">mode: ${esc(mode)}</span>
    <span><strong>From</strong> ${esc(fmtDate(cfg.start_date))}</span>
    <span><strong>To</strong> ${esc(fmtDate(cfg.end_date))}</span>
    <span class="spacer"></span>
    <button class="btn-outline" onclick="downloadPortScanReport()">&#x2193; Report</button>
  </div>
  <div id="bulkBar">
    <span class="b-count" id="bulkCount">0 selected</span>
    <span class="spacer"></span>
    <button onclick="bulkCorrelate()">&#x21C4; Correlate selected</button>
    <button onclick="bulkSessions()">&#x2261; Sessions for selected</button>
    <button onclick="clearSelection()">Clear</button>
  </div>
  <div id="baselineCmpOut"></div>`;

  let body = "";
  if (mode === "sig_to_port")          body = renderSigToPort(data, cfg);
  else if (mode === "port_to_sig")     body = renderPortToSig(data, cfg);
  else if (mode === "host_diversity")  body = renderHostDiversity(data, cfg);
  else if (mode === "byte_pattern")    body = renderBytePattern(data, cfg);
  else body = `<div class="err-card">Unknown mode: ${esc(mode)}</div>`;

  panel.innerHTML = header + body;
  updateBulkBar();
}

// Mode 1 renderer
function renderSigToPort(data, cfg) {
  const sigs = data.signatures || [];
  const flagged = sigs.filter(s => s.flagged);
  const clean   = sigs.filter(s => !s.flagged && !s.error);
  const errored = sigs.filter(s => s.error);

  let html = `<div class="card">
    <div class="card-top">
      <div>
        <div class="card-title">Signature &rarr; Port (mode 1)</div>
        <div class="card-sub">signature field: <code>${esc(data.signature_field)}</code>, port field: <code>${esc(data.port_field)}</code>, ports queried: ${data.ports_queried || 0}</div>
      </div>
    </div>
    <div class="stats">
      <div class="stat"><div class="stat-val">${fmt(data.total_signatures_seen || 0)}</div><div class="stat-lbl">Signatures seen</div></div>
      <div class="stat"><div class="stat-val">${fmt(data.eligible_signatures || 0)}</div><div class="stat-lbl">Scanned</div></div>
      <div class="stat"><div class="stat-val" style="color:#dc2626">${fmt(flagged.length)}</div><div class="stat-lbl">Flagged</div></div>
      <div class="stat"><div class="stat-val">${fmt(clean.length)}</div><div class="stat-lbl">Clean</div></div>
    </div>`;

  if (data.warning) {
    html += `<div class="err-card" style="border-left-color:#f59e0b">${esc(data.warning)}</div>`;
  }
  if (data.errors && data.errors.length) {
    html += `<div class="err-card" style="border-left-color:#f59e0b">Query errors:<br>${data.errors.map(e => esc(e)).join("<br>")}</div>`;
  }

  if (data.truncated) {
    html += `<div class="err-card" style="margin-bottom:10px;border-left:3px solid #f59e0b;background:var(--anom-bg);color:var(--anom-fg);border-color:transparent">
      &#x26A0; Only the top ${data.eligible_signatures} signatures (by volume) were scanned. Raise "max signatures" or "min sessions" to adjust.</div>`;
  }
  html += `</div>`;

  if (flagged.length) {
    html += renderSigTable(flagged, "Flagged signatures", true, data.port_field, false, "flaggedSigs");
  }
  if (clean.length) {
    html += renderSigTable(clean, `Clean signatures (${clean.length})`, false, data.port_field, true, "cleanSigs");
  }
  if (errored.length) {
    html += `<div class="card"><div class="card-title" style="color:#dc2626">Errors</div>`;
    html += errored.map(e => `<div style="font-size:.78rem;color:var(--text-3);margin-top:6px"><code>${esc(e.signature)}</code>: ${esc(e.error)}</div>`).join("");
    html += `</div>`;
  }
  return html;
}

function renderSigTable(sigs, title, isFlagged, portField, collapsed, tableId) {
  const openAttr = collapsed ? "" : " open";
  const withSessions = sigs.filter(s => (s.total || 0) > 0);
  const zeroSessions = sigs.filter(s => (s.total || 0) === 0);

  const buildRows = (arr) => arr.map(s => {
    const domBadge = s.dominant_port ? `<span class="port-chip dom">${esc(s.dominant_port)}</span> <span style="color:var(--text-4);font-size:.72rem">${(s.dominant_share*100).toFixed(1)}%</span>` : '-';
    const outlierCells = (s.outliers || []).map(o => {
      const ri = rowData.length;
      rowData.push({field: portField, value: String(o.port), count: o.count, bucket: "ps_outlier", signature_field: dataSigFieldForRow(s), signature: s.signature});
      return `<span class="port-chip out" title="${o.count} session${o.count!==1?"s":""}">
        <span class="port-val">${esc(o.port)}</span>
        <span class="port-count">${o.count}</span>
        <button class="chip-act" onclick="psPivotOutlier(${ri})" title="Pivot by this port+signature">&#x21C4;</button>
        <button class="chip-act" onclick="psSessionsOutlier(${ri})" title="Sessions for this port+signature">&#x2261;</button>
      </span>`;
    }).join("") || `<span style="color:var(--text-4);font-size:.72rem">—</span>`;

    const errBadge = s.error ? `<span style="color:#dc2626;font-size:.7rem" title="${esc(s.error)}">⚠ ${esc(s.error)}</span>` : "";
    return `<tr class="${isFlagged ? "" : "clean"}" data-sessions="${s.total || 0}">
      <td class="val" style="max-width:320px">${esc(s.signature)}${errBadge ? "<br>"+errBadge : ""}</td>
      <td class="num r">${fmt(s.total)}</td>
      <td>${domBadge}</td>
      <td class="num r">${fmt(s.distinct_ports)}</td>
      <td class="num r" style="color:var(--text-3);font-size:.72rem" title="Shannon entropy over the port distribution; low = concentrated on one port, high = spread out">${(s.entropy || 0).toFixed(2)}</td>
      <td style="min-width:260px">${outlierCells}</td>
    </tr>`;
  }).join("");

  let html = `<details class="card"${openAttr}>
    <summary class="card-title" style="cursor:pointer;list-style:revert;padding:0">${esc(title)}</summary>
    <div style="margin-top:12px">`;

  if (withSessions.length) {
    html += `<div style="margin-bottom:8px;display:flex;align-items:center;gap:8px">
      <span style="font-size:.75rem;color:var(--text-3)">Sort by sessions:</span>
      <button class="btn-sm" onclick="sortPsTable('${tableId}', 'desc')">↓ Most</button>
      <button class="btn-sm" onclick="sortPsTable('${tableId}', 'asc')">↑ Least</button>
    </div>
    <table id="${tableId}">
      <thead><tr>
        <th>Signature</th>
        <th class="r">Sessions</th>
        <th>Dominant port</th>
        <th class="r">Distinct ports</th>
        <th class="r" title="Shannon entropy">H</th>
        <th>Outlier ports</th>
      </tr></thead>
      <tbody>${buildRows(withSessions)}</tbody>
    </table>`;
  }

  if (zeroSessions.length) {
    html += `<details style="margin-top:12px">
      <summary style="cursor:pointer;font-size:.8rem;color:var(--text-3)">${zeroSessions.length} entries with 0 sessions (click to expand)</summary>
      <table style="margin-top:8px">
        <thead><tr>
          <th>Signature</th>
          <th class="r">Sessions</th>
          <th>Dominant port</th>
          <th class="r">Distinct ports</th>
          <th class="r">H</th>
          <th>Outlier ports</th>
        </tr></thead>
        <tbody>${buildRows(zeroSessions)}</tbody>
      </table>
    </details>`;
  }

  html += `</div></details>`;
  return html;
}

function dataSigFieldForRow(s) {
  // Walk up to the last scan's signature_field for this row
  return lastPortScan && lastPortScan.signature_field ? lastPortScan.signature_field : "";
}

// Outlier actions
function psPivotOutlier(ri) {
  const r = rowData[ri];
  // Build a bulk-correlate context: pivot is the SIGNATURE+PORT combo.
  // Simplest: treat signature as pivot, show distribution of port.dst — but we already know that.
  // More useful: pivot the outlier (field=port.dst, value=<port>) AND pin the signature as an extra expression.
  openCorrelateWithPin(r.field, [r.value], r.signature_field, r.signature);
}
function psSessionsOutlier(ri) {
  const r = rowData[ri];
  openSessionsWithPin(r.field, [r.value], r.signature_field, r.signature);
}

// Pinned versions of the existing modals
function openCorrelateWithPin(field, values, pinField, pinValue) {
  // Add a pre-populated extra-expression pin via the base expression trick
  // Easiest: show a dedicated correlate step that includes both pivots
  corrStack = [{field, values, match: "any", extra_pin: pinField && pinValue ? {field: pinField, value: pinValue} : null}];
  showCorrelateStep();
}
function openSessionsWithPin(field, values, pinField, pinValue) {
  openSessionsRaw(field, values, pinField && pinValue ? {field: pinField, value: pinValue} : null);
}

// Mode 2 renderer
function renderPortToSig(data, cfg) {
  const ports = data.ports || [];
  const flagged = ports.filter(p => p.flagged);
  const clean   = ports.filter(p => !p.flagged && !p.error);

  let html = `<div class="card">
    <div class="card-top">
      <div>
        <div class="card-title">Port &rarr; Signature (mode 2)</div>
        <div class="card-sub">signature field: <code>${esc(data.signature_field)}</code>, port field: <code>${esc(data.port_field)}</code></div>
      </div>
    </div>
    <div class="stats">
      <div class="stat"><div class="stat-val">${fmt(ports.length)}</div><div class="stat-lbl">Ports checked</div></div>
      <div class="stat"><div class="stat-val" style="color:#dc2626">${fmt(flagged.length)}</div><div class="stat-lbl">Flagged</div></div>
      <div class="stat"><div class="stat-val">${fmt(clean.length)}</div><div class="stat-lbl">Clean</div></div>
    </div>
  </div>`;

  const buildRows = (arr) => arr.map(p => {
    const unexp = (p.unexpected || []).map(u => {
      const ri = rowData.length;
      rowData.push({field: data.signature_field, value: u.signature, count: u.count, bucket: "ps_unexpected", pin_field: data.port_field, pin_value: String(p.port)});
      return `<span class="port-chip out">
        <span class="port-val" title="${u.count} sessions">${esc(truncate(u.signature, 40))}</span>
        <span class="port-count">${u.count}</span>
        <button class="chip-act" onclick="psPivotUnexpected(${ri})" title="Correlate">&#x21C4;</button>
        <button class="chip-act" onclick="psSessionsUnexpected(${ri})" title="Sessions">&#x2261;</button>
      </span>`;
    }).join("") || `<span style="color:var(--text-4);font-size:.72rem">—</span>`;

    const matched = (p.matches || []).map(m =>
      `<span class="port-chip dom"><span class="port-val">${esc(truncate(m.signature, 40))}</span> <span class="port-count">${m.count}</span></span>`
    ).join("") || `<span style="color:var(--text-4);font-size:.72rem">—</span>`;

    return `<tr class="${p.flagged?"":"clean"}" data-sessions="${p.total || 0}">
      <td class="num" style="font-weight:700">${esc(p.port)}</td>
      <td class="num r">${fmt(p.total || 0)}</td>
      <td style="font-size:.73rem">${p.expected.length ? p.expected.map(x=>`<code>${esc(x)}</code>`).join(" ") : '<span style="color:var(--text-4)">no expectation set</span>'}</td>
      <td style="max-width:300px">${matched}</td>
      <td style="max-width:360px">${unexp}</td>
    </tr>`;
  }).join("");

  const renderPortTable = (arr, tableTitle, tableId, isOpen) => {
    const withSessions = arr.filter(p => (p.total || 0) > 0);
    const zeroSessions = arr.filter(p => (p.total || 0) === 0);
    let thtml = `<details class="card"${isOpen ? " open" : ""}>
      <summary class="card-title" style="cursor:pointer;list-style:revert;padding:0">${esc(tableTitle)}</summary>
      <div style="margin-top:12px">`;

    if (withSessions.length) {
      thtml += `<div style="margin-bottom:8px;display:flex;align-items:center;gap:8px">
        <span style="font-size:.75rem;color:var(--text-3)">Sort by sessions:</span>
        <button class="btn-sm" onclick="sortPsTable('${tableId}', 'desc')">↓ Most</button>
        <button class="btn-sm" onclick="sortPsTable('${tableId}', 'asc')">↑ Least</button>
      </div>
      <table id="${tableId}">
        <thead><tr><th>Port</th><th class="r">Sessions</th><th>Expected</th><th>Matching</th><th>Unexpected</th></tr></thead>
        <tbody>${buildRows(withSessions)}</tbody>
      </table>`;
    }

    if (zeroSessions.length) {
      thtml += `<details style="margin-top:12px">
        <summary style="cursor:pointer;font-size:.8rem;color:var(--text-3)">${zeroSessions.length} ports with 0 sessions (click to expand)</summary>
        <table style="margin-top:8px">
          <thead><tr><th>Port</th><th class="r">Sessions</th><th>Expected</th><th>Matching</th><th>Unexpected</th></tr></thead>
          <tbody>${buildRows(zeroSessions)}</tbody>
        </table>
      </details>`;
    }

    thtml += `</div></details>`;
    return thtml;
  };

  if (flagged.length) {
    html += renderPortTable(flagged, "Flagged ports", "flaggedPorts", true);
  }
  if (clean.length) {
    html += renderPortTable(clean, `Clean ports (${clean.length})`, "cleanPorts", false);
  }
  return html;
}

function psPivotUnexpected(ri) {
  const r = rowData[ri];
  openCorrelateWithPin(r.field, [r.value], r.pin_field, r.pin_value);
}
function psSessionsUnexpected(ri) {
  const r = rowData[ri];
  openSessionsWithPin(r.field, [r.value], r.pin_field, r.pin_value);
}

// Mode 3 renderer
function renderHostDiversity(data, cfg) {
  const hosts = data.hosts || [];
  const flagged = hosts.filter(h => h.flagged);
  const errored = hosts.filter(h => h.error);
  const clean   = hosts.filter(h => !h.flagged && !h.error);

  let html = `<div class="card">
    <div class="card-top">
      <div>
        <div class="card-title">Host port diversity (mode 3)</div>
        <div class="card-sub">checking: <code>ip.src</code> + <code>ip.dst</code>, port field: <code>${esc(data.port_field)}</code>${data.signature_field ? `, pinned signature: <code>${esc(data.signature_field)}</code>` : ""}</div>
      </div>
    </div>
    <div class="stats">
      <div class="stat"><div class="stat-val">${fmt(hosts.length)}</div><div class="stat-lbl">Hosts scanned</div></div>
      <div class="stat"><div class="stat-val" style="color:#dc2626">${fmt(flagged.length)}</div><div class="stat-lbl">Flagged</div></div>
      <div class="stat"><div class="stat-val">${fmt(clean.length)}</div><div class="stat-lbl">Clean</div></div>
    </div>
  </div>`;

  const buildRows = (arr) => arr.map(h => {
    const ri = rowData.length;
    rowData.push({field: "ip", value: h.host, count: h.total, bucket: "ps_host"});
    const topPorts = (h.top_ports || []).slice(0, 8).map(tp =>
      `<span class="port-chip"><span class="port-val">${esc(tp.port)}</span> <span class="port-count">${tp.count}</span></span>`
    ).join("");
    return `<tr class="${h.flagged?"":"clean"}" data-sessions="${h.total || 0}">
      <td class="val"><input type="checkbox" ${selection.has(ri)?"checked":""} onchange="toggleRowSel(${ri}, this.checked)" style="margin-right:6px">${esc(h.host)}</td>
      <td class="num r">${fmt(h.total)}</td>
      <td class="num r">${fmt(h.distinct_ports)}</td>
      <td class="num r" style="font-weight:700;color:${h.flagged?"#dc2626":"inherit"}">${(h.ratio*100).toFixed(1)}%</td>
      <td class="num r" style="color:var(--text-3);font-size:.72rem">${(h.entropy || 0).toFixed(2)}</td>
      <td style="max-width:360px">${topPorts}</td>
      <td class="act-col">
        <button class="act-btn" onclick="openCorrelate(${ri})" title="Correlate">&#x21C4;</button>
        <button class="act-btn" onclick="openSessions(${ri})" title="Sessions">&#x2261;</button>
      </td>
    </tr>`;
  }).join("");

  const renderHostTable = (arr, tableTitle, tableId, isOpen) => {
    const withSessions = arr.filter(h => (h.total || 0) > 0);
    const zeroSessions = arr.filter(h => (h.total || 0) === 0);
    let thtml = `<details class="card"${isOpen ? " open" : ""}>
      <summary class="card-title" style="cursor:pointer;list-style:revert;padding:0">${esc(tableTitle)}</summary>
      <div style="margin-top:12px">`;

    if (withSessions.length) {
      thtml += `<div style="margin-bottom:8px;display:flex;align-items:center;gap:8px">
        <span style="font-size:.75rem;color:var(--text-3)">Sort by sessions:</span>
        <button class="btn-sm" onclick="sortPsTable('${tableId}', 'desc')">↓ Most</button>
        <button class="btn-sm" onclick="sortPsTable('${tableId}', 'asc')">↑ Least</button>
      </div>
      <table id="${tableId}">
        <thead><tr><th>Host</th><th class="r">Sessions</th><th class="r">Distinct ports</th><th class="r">Ratio</th><th class="r" title="Shannon entropy">H</th><th>Top ports</th><th></th></tr></thead>
        <tbody>${buildRows(withSessions)}</tbody>
      </table>`;
    }

    if (zeroSessions.length) {
      thtml += `<details style="margin-top:12px">
        <summary style="cursor:pointer;font-size:.8rem;color:var(--text-3)">${zeroSessions.length} hosts with 0 sessions (click to expand)</summary>
        <table style="margin-top:8px">
          <thead><tr><th>Host</th><th class="r">Sessions</th><th class="r">Distinct ports</th><th class="r">Ratio</th><th class="r">H</th><th>Top ports</th><th></th></tr></thead>
          <tbody>${buildRows(zeroSessions)}</tbody>
        </table>
      </details>`;
    }

    thtml += `</div></details>`;
    return thtml;
  };

  if (flagged.length) {
    html += renderHostTable(flagged, "Flagged hosts", "flaggedHosts", true);
  }
  if (clean.length) {
    html += renderHostTable(clean, `Clean hosts (${clean.length})`, "cleanHosts", false);
  }
  if (errored.length) {
    html += `<div class="card"><div class="card-title" style="color:#dc2626">Errors (${errored.length})</div>`;
    html += errored.map(h => `<div style="font-size:.78rem;color:var(--text-3);margin-top:6px"><code>${esc(h.host)}</code>: ${esc(h.error)}</div>`).join("");
    html += `</div>`;
  }
  return html;
}

function renderBytePattern(data, cfg) {
  const patterns = data.patterns || [];
  const flagged = patterns.filter(p => p.flagged);
  const clean = patterns.filter(p => !p.flagged && !p.error);
  const errors = patterns.filter(p => p.error);

  let html = `<div class="card">
    <div class="card-top">
      <div>
        <div class="card-title">Byte pattern scan (mode 4)</div>
        <div class="card-sub">port field: <code>${esc(data.port_field)}</code> · Uses Arkime Hunt API</div>
      </div>
    </div>
    <div class="stats">
      <div class="stat"><div class="stat-val">${fmt(patterns.length)}</div><div class="stat-lbl">Patterns</div></div>
      <div class="stat"><div class="stat-val" style="color:#dc2626">${fmt(flagged.length)}</div><div class="stat-lbl">Flagged</div></div>
      <div class="stat"><div class="stat-val">${fmt(clean.length)}</div><div class="stat-lbl">Clean</div></div>
      ${errors.length ? `<div class="stat"><div class="stat-val" style="color:#f59e0b">${fmt(errors.length)}</div><div class="stat-lbl">Errors</div></div>` : ""}
    </div>
    <div style="font-size:.75rem;color:var(--text-3);margin-top:8px">Note: Ephemeral ports (49152-65535) are excluded from "unexpected" flagging.</div>
  </div>`;

  const buildRow = (p) => {
    const portsHtml = (p.ports || []).slice(0, 10).map(pt => {
      const isUnexpected = p.expected_ports && p.expected_ports.length && !p.expected_ports.includes(pt.port);
      return `<span class="port-chip${isUnexpected ? " flagged" : ""}"><span class="port-val">${esc(pt.port)}</span> <span class="port-count">${pt.count}</span></span>`;
    }).join("");
    const expectedStr = (p.expected_ports || []).join(", ") || "(any)";
    const unexpectedPorts = (p.unexpected_ports || []).map(u => u.port).join(", ");
    return `<tr class="${p.flagged ? "" : "clean"}" data-sessions="${p.matched_sessions || 0}">
      <td><code style="font-size:.8rem">${esc(p.pattern)}</code></td>
      <td>${esc(p.type)}</td>
      <td class="num r">${fmt(p.matched_sessions || 0)}</td>
      <td style="font-size:.75rem">${esc(expectedStr)}</td>
      <td style="max-width:300px">${portsHtml}</td>
      <td style="color:#dc2626;font-size:.75rem">${unexpectedPorts ? esc(unexpectedPorts) : "-"}</td>
    </tr>`;
  };

  const renderPatternTable = (arr, tableTitle, tableId, isOpen) => {
    const withSessions = arr.filter(p => (p.matched_sessions || 0) > 0);
    const zeroSessions = arr.filter(p => (p.matched_sessions || 0) === 0);
    let thtml = `<details class="card"${isOpen ? " open" : ""}>
      <summary class="card-title" style="cursor:pointer;list-style:revert;padding:0">${esc(tableTitle)}</summary>
      <div style="margin-top:12px">`;

    if (withSessions.length) {
      thtml += `<div style="margin-bottom:8px;display:flex;align-items:center;gap:8px">
        <span style="font-size:.75rem;color:var(--text-3)">Sort by sessions:</span>
        <button class="btn-sm" onclick="sortPsTable('${tableId}', 'desc')">↓ Most</button>
        <button class="btn-sm" onclick="sortPsTable('${tableId}', 'asc')">↑ Least</button>
      </div>
      <table id="${tableId}">
        <thead><tr><th>Pattern</th><th>Type</th><th class="r">Sessions</th><th>Expected ports</th><th>Actual ports</th><th>Unexpected</th></tr></thead>
        <tbody>${withSessions.map(buildRow).join("")}</tbody>
      </table>`;
    }

    if (zeroSessions.length) {
      thtml += `<details style="margin-top:12px">
        <summary style="cursor:pointer;font-size:.8rem;color:var(--text-3)">${zeroSessions.length} patterns with 0 sessions (click to expand)</summary>
        <table style="margin-top:8px">
          <thead><tr><th>Pattern</th><th>Type</th><th class="r">Sessions</th><th>Expected ports</th><th>Actual ports</th><th>Unexpected</th></tr></thead>
          <tbody>${zeroSessions.map(buildRow).join("")}</tbody>
        </table>
      </details>`;
    }

    thtml += `</div></details>`;
    return thtml;
  };

  if (flagged.length) {
    html += renderPatternTable(flagged, `Flagged patterns (${flagged.length})`, "flaggedPatterns", true);
  }

  if (clean.length) {
    html += renderPatternTable(clean, `Clean patterns (${clean.length})`, "cleanPatterns", false);
  }

  if (errors.length) {
    html += `<details class="card">
      <summary class="card-title" style="cursor:pointer;list-style:revert;padding:0;color:#f59e0b">Errors (${errors.length})</summary>
      <div style="margin-top:12px"><table>
        <thead><tr><th>Pattern</th><th>Type</th><th>Error</th></tr></thead>
        <tbody>${errors.map(p => `<tr><td><code>${esc(p.pattern)}</code></td><td>${esc(p.type)}</td><td style="color:#dc2626">${esc(p.error)}</td></tr>`).join("")}</tbody>
      </table></div>
    </details>`;
  }

  return html;
}

// ── Baselines ────────────────────────────────────────────────────────────────
async function refreshBaselines() {
  try {
    const res = await fetch("/api/baselines");
    if (!res.ok) return;
    const data = await res.json();
    baselineList = data.baselines || [];
    const sel = document.getElementById("psBaselineSelect");
    if (!sel) return;
    const current = sel.value;
    sel.innerHTML = `<option value="">— none, just run the scan —</option>` +
      baselineList.map(b => `<option value="${esc(b.name)}">${esc(b.name)}</option>`).join("");
    if (baselineList.some(b => b.name === current)) sel.value = current;
    updateBaselineInfo();
    sel.onchange = updateBaselineInfo;
  } catch(_) {}
}

function updateBaselineInfo() {
  const name = document.getElementById("psBaselineSelect").value;
  const info = document.getElementById("psBaselineInfo");
  if (!name || !info) { if (info) info.textContent = ""; return; }
  const b = baselineList.find(x => x.name === name);
  if (!b) { info.textContent = ""; return; }
  const window = b.built_from ? `${(b.built_from.start||"").replace("T"," ")} → ${(b.built_from.end||"").replace("T"," ")}` : "unknown window";
  info.innerHTML = `<strong>${b.signature_count}</strong> sigs · field <code>${esc(b.signature_field||"?")}</code> · built ${esc(b.built_at||"?")}<br><span style="color:var(--text-4)">${esc(b.description||"(no description)")}</span><br><span style="color:var(--text-4)">window: ${esc(window)}</span>`;
}

async function saveBaselineFromLastScan() {
  if (!lastPortScan || lastPortScan.mode !== "sig_to_port") {
    toast("Run a mode-1 port scan first, then save it as baseline", "err");
    return;
  }
  const name = prompt("Name this baseline:\n(tip: include the date/segment, e.g. 'dmz-clean-apr-2026')");
  if (!name || !name.trim()) return;
  const desc = prompt("Optional description (what is this baseline, where did it come from?):", "") || "";
  try {
    const data = await apiFetch("/api/baseline/save", {
      name: name.trim(),
      description: desc.trim(),
      scan_result: lastPortScan,
      built_from: {start: getConfig().start_date, end: getConfig().end_date},
    });
    if (data.error) { toast(data.error, "err"); return; }
    await refreshBaselines();
    document.getElementById("psBaselineSelect").value = name.trim();
    updateBaselineInfo();
    toast(`Baseline saved: ${name.trim()} (${data.signature_count} sigs)`, "ok");
  } catch(e) { toast("Save failed: " + e.message, "err"); }
}

async function deleteBaseline() {
  const name = document.getElementById("psBaselineSelect").value;
  if (!name) { toast("Pick a baseline first", "err"); return; }
  if (!confirm(`Delete baseline "${name}"?`)) return;
  try {
    await apiFetch("/api/baseline/delete", {name});
    await refreshBaselines();
    toast(`Deleted: ${name}`, "ok");
  } catch(e) { toast("Delete failed: " + e.message, "err"); }
}

async function runBaselineCompare(name, scanResult) {
  const out = document.getElementById("baselineCmpOut");
  if (!out) return;
  out.innerHTML = `<div class="card"><div class="card-sub">Comparing against baseline <strong>${esc(name)}</strong>…</div></div>`;
  try {
    const data = await apiFetch("/api/baseline/compare", {name, scan_result: scanResult});
    if (data.error) { out.innerHTML = `<div class="err-card">${esc(data.error)}</div>`; return; }

    const diffs = data.diffs || [];
    const sevColor = {high: "#dc2626", medium: "#f59e0b", low: "#6b7280"};
    const sevLabel = {high: "HIGH", medium: "MED", low: "LOW"};
    const kindLabel = {
      new_signature: "New signature",
      known_signature_new_ports: "New ports",
      dominance_shift: "Dominance shift",
    };

    const rows = diffs.map(d => {
      const newPortsStr = d.new_ports.length ? d.new_ports.map(p=>`<code>${esc(p)}</code>`).join(" ") : "—";
      const shift = d.shifted_dominant ? `<code>${esc(d.shifted_dominant.baseline)}</code> &rarr; <code>${esc(d.shifted_dominant.scan)}</code>` : "—";
      return `<tr>
        <td style="font-weight:700;color:${sevColor[d.severity] || "inherit"};white-space:nowrap">${sevLabel[d.severity]||"—"}</td>
        <td style="font-size:.72rem">${esc(kindLabel[d.kind]||d.kind)}</td>
        <td class="val" style="max-width:320px">${esc(d.signature)}</td>
        <td class="num r">${fmt(d.total||0)}</td>
        <td style="font-size:.72rem">${newPortsStr}</td>
        <td style="font-size:.72rem">${shift}</td>
      </tr>`;
    }).join("") || `<tr><td class="empty" colspan="6">No differences — all signatures match the baseline &#x2713;</td></tr>`;

    const summary = `
      <div class="stats">
        <div class="stat"><div class="stat-val" style="color:#dc2626">${fmt(data.new_count)}</div><div class="stat-lbl">New signatures</div></div>
        <div class="stat"><div class="stat-val" style="color:#f59e0b">${fmt(data.changed_count)}</div><div class="stat-lbl">Changed signatures</div></div>
        <div class="stat"><div class="stat-val">${fmt(data.disappeared_count)}</div><div class="stat-lbl">Disappeared</div></div>
      </div>`;

    out.innerHTML = `<div class="card">
      <div class="card-top">
        <div>
          <div class="card-title">Baseline comparison: ${esc(name)}</div>
          <div class="card-sub">${esc(data.baseline.description || "(no description)")} · built ${esc(data.baseline.built_at || "?")}</div>
        </div>
      </div>
      ${summary}
      <div class="tbl-label"><span>Differences</span></div>
      <table>
        <thead><tr><th>Sev</th><th>Kind</th><th>Signature</th><th class="r">Sessions</th><th>New ports</th><th>Dominance shift</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  } catch(e) {
    out.innerHTML = `<div class="err-card">${esc(e.message)}</div>`;
  }
}

function downloadPortScanReport() {
  // Find the most recent scan from cache
  const modes = ["sig_to_port", "port_to_sig", "host_diversity", "byte_pattern"];
  let data = null;
  let cfg = null;
  for (const m of modes) {
    if (portScanCache[m]) {
      data = portScanCache[m].data;
      cfg = portScanCache[m].cfg;
      break;
    }
  }
  if (!data) { toast("No scan to export", "err"); return; }

  const ts = new Date().toISOString().slice(0, 19).replace(/[-:T]/g, "").slice(0, 15);
  const genTime = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
  const mode = data.mode || "unknown";

  const styles = `
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; color: #333; }
    h1 { color: #1e3a5f; border-bottom: 2px solid #3b82f6; padding-bottom: 10px; }
    h2 { color: #1e3a5f; margin-top: 30px; }
    h3 { color: #374151; margin-top: 20px; }
    .meta { background: #fff; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
    .meta p { margin: 5px 0; }
    .meta strong { color: #1e3a5f; }
    .summary { display: flex; gap: 20px; flex-wrap: wrap; margin: 15px 0; }
    .stat { background: #e0e7ff; padding: 12px 20px; border-radius: 6px; text-align: center; min-width: 100px; }
    .stat-val { font-size: 1.5rem; font-weight: bold; color: #3730a3; }
    .stat-lbl { font-size: .8rem; color: #6366f1; }
    .stat-flagged .stat-val { color: #dc2626; }
    table { width: 100%; border-collapse: collapse; margin: 10px 0 25px 0; background: #fff; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
    th { background: #1e3a5f; color: #fff; padding: 10px 12px; text-align: left; font-size: .85rem; }
    td { padding: 8px 12px; border-bottom: 1px solid #e5e7eb; font-size: .85rem; }
    tr:last-child td { border-bottom: none; }
    tr:nth-child(even) { background: #f9fafb; }
    .val { font-family: monospace; word-break: break-all; }
    .num { text-align: right; }
    .section { background: #fff; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
    .flagged { background: #fef2f2; }
    .flagged td:first-child { border-left: 3px solid #dc2626; }
    .port-chip { display: inline-block; background: #dbeafe; color: #1e40af; padding: 2px 8px; border-radius: 4px; margin: 2px; font-size: .8rem; font-family: monospace; }
    .port-chip.unexpected { background: #fee2e2; color: #991b1b; }
    .footer { text-align: center; color: #9ca3af; font-size: .8rem; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; }
  `;

  let html = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Luxray Port Scan Report - ' + genTime + '</title><style>' + styles + '</style></head><body>';
  html += '<h1>Luxray Port Anomaly Scan Report</h1>';
  html += '<div class="meta">';
  html += '<p><strong>Generated:</strong> ' + genTime + '</p>';
  html += '<p><strong>Mode:</strong> ' + esc(mode) + '</p>';
  if (cfg) {
    html += '<p><strong>Time Range:</strong> ' + esc(cfg.start_date || '') + ' to ' + esc(cfg.end_date || '') + '</p>';
    if (cfg.expression) html += '<p><strong>Expression:</strong> <code>' + esc(cfg.expression) + '</code></p>';
  }
  html += '</div>';

  if (mode === "sig_to_port") {
    const sigs = data.signatures || [];
    const flagged = sigs.filter(s => s.flagged);
    const clean = sigs.filter(s => !s.flagged);
    html += '<div class="summary">';
    html += '<div class="stat"><div class="stat-val">' + fmt(data.total_signatures_seen || 0) + '</div><div class="stat-lbl">Signatures Seen</div></div>';
    html += '<div class="stat"><div class="stat-val">' + fmt(sigs.length) + '</div><div class="stat-lbl">Scanned</div></div>';
    html += '<div class="stat stat-flagged"><div class="stat-val">' + fmt(flagged.length) + '</div><div class="stat-lbl">Flagged</div></div>';
    html += '<div class="stat"><div class="stat-val">' + fmt(clean.length) + '</div><div class="stat-lbl">Clean</div></div>';
    html += '</div>';

    if (flagged.length) {
      html += '<div class="section"><h3>Flagged Signatures (' + flagged.length + ')</h3>';
      html += '<table><thead><tr><th>Signature</th><th class="num">Sessions</th><th>Dominant Port</th><th class="num">Distinct Ports</th><th>Outlier Ports</th></tr></thead><tbody>';
      for (const s of flagged) {
        const outliers = (s.outliers || []).map(o => '<span class="port-chip unexpected">' + o.port + ' (' + o.count + ')</span>').join(' ');
        html += '<tr class="flagged"><td class="val">' + esc(s.signature) + '</td><td class="num">' + fmt(s.total) + '</td><td>' + (s.dominant_port || '-') + ' (' + ((s.dominant_share||0)*100).toFixed(1) + '%)</td><td class="num">' + fmt(s.distinct_ports) + '</td><td>' + (outliers || '-') + '</td></tr>';
      }
      html += '</tbody></table></div>';
    }
    if (clean.length) {
      html += '<div class="section"><h3>Clean Signatures (' + clean.length + ')</h3>';
      html += '<table><thead><tr><th>Signature</th><th class="num">Sessions</th><th>Dominant Port</th><th class="num">Distinct Ports</th></tr></thead><tbody>';
      for (const s of clean) {
        html += '<tr><td class="val">' + esc(s.signature) + '</td><td class="num">' + fmt(s.total) + '</td><td>' + (s.dominant_port || '-') + ' (' + ((s.dominant_share||0)*100).toFixed(1) + '%)</td><td class="num">' + fmt(s.distinct_ports) + '</td></tr>';
      }
      html += '</tbody></table></div>';
    }
  } else if (mode === "port_to_sig") {
    const ports = data.ports || [];
    const flagged = ports.filter(p => p.flagged);
    const clean = ports.filter(p => !p.flagged);
    html += '<div class="summary">';
    html += '<div class="stat"><div class="stat-val">' + fmt(ports.length) + '</div><div class="stat-lbl">Ports Checked</div></div>';
    html += '<div class="stat stat-flagged"><div class="stat-val">' + fmt(flagged.length) + '</div><div class="stat-lbl">Flagged</div></div>';
    html += '<div class="stat"><div class="stat-val">' + fmt(clean.length) + '</div><div class="stat-lbl">Clean</div></div>';
    html += '</div>';

    if (flagged.length) {
      html += '<div class="section"><h3>Flagged Ports (' + flagged.length + ')</h3>';
      html += '<table><thead><tr><th>Port</th><th class="num">Sessions</th><th>Expected</th><th>Matching</th><th>Unexpected</th></tr></thead><tbody>';
      for (const p of flagged) {
        const matching = (p.matches || []).map(m => '<span class="port-chip">' + esc(m.signature) + ' (' + m.count + ')</span>').join(' ');
        const unexpected = (p.unexpected || []).map(u => '<span class="port-chip unexpected">' + esc(u.signature) + ' (' + u.count + ')</span>').join(' ');
        html += '<tr class="flagged"><td>' + p.port + '</td><td class="num">' + fmt(p.total) + '</td><td>' + (p.expected || []).join(', ') + '</td><td>' + (matching || '-') + '</td><td>' + (unexpected || '-') + '</td></tr>';
      }
      html += '</tbody></table></div>';
    }
    if (clean.length) {
      html += '<div class="section"><h3>Clean Ports (' + clean.length + ')</h3>';
      html += '<table><thead><tr><th>Port</th><th class="num">Sessions</th><th>Expected</th><th>Matching</th></tr></thead><tbody>';
      for (const p of clean) {
        const matching = (p.matches || []).map(m => '<span class="port-chip">' + esc(m.signature) + ' (' + m.count + ')</span>').join(' ');
        html += '<tr><td>' + p.port + '</td><td class="num">' + fmt(p.total) + '</td><td>' + (p.expected || []).join(', ') + '</td><td>' + (matching || '-') + '</td></tr>';
      }
      html += '</tbody></table></div>';
    }
  } else if (mode === "host_diversity") {
    const hosts = data.hosts || [];
    const flagged = hosts.filter(h => h.flagged);
    const clean = hosts.filter(h => !h.flagged && !h.error);
    html += '<div class="summary">';
    html += '<div class="stat"><div class="stat-val">' + fmt(hosts.length) + '</div><div class="stat-lbl">Hosts Scanned</div></div>';
    html += '<div class="stat stat-flagged"><div class="stat-val">' + fmt(flagged.length) + '</div><div class="stat-lbl">Flagged</div></div>';
    html += '<div class="stat"><div class="stat-val">' + fmt(clean.length) + '</div><div class="stat-lbl">Clean</div></div>';
    html += '</div>';

    if (flagged.length) {
      html += '<div class="section"><h3>Flagged Hosts (' + flagged.length + ')</h3>';
      html += '<table><thead><tr><th>Host</th><th class="num">Sessions</th><th class="num">Distinct Ports</th><th class="num">Ratio</th><th>Top Ports</th></tr></thead><tbody>';
      for (const h of flagged) {
        const topPorts = (h.top_ports || []).slice(0, 5).map(tp => '<span class="port-chip">' + tp.port + ' (' + tp.count + ')</span>').join(' ');
        html += '<tr class="flagged"><td class="val">' + esc(h.host) + '</td><td class="num">' + fmt(h.total) + '</td><td class="num">' + fmt(h.distinct_ports) + '</td><td class="num">' + ((h.ratio||0)*100).toFixed(1) + '%</td><td>' + topPorts + '</td></tr>';
      }
      html += '</tbody></table></div>';
    }
    if (clean.length) {
      html += '<div class="section"><h3>Clean Hosts (' + clean.length + ')</h3>';
      html += '<table><thead><tr><th>Host</th><th class="num">Sessions</th><th class="num">Distinct Ports</th><th class="num">Ratio</th><th>Top Ports</th></tr></thead><tbody>';
      for (const h of clean) {
        const topPorts = (h.top_ports || []).slice(0, 5).map(tp => '<span class="port-chip">' + tp.port + ' (' + tp.count + ')</span>').join(' ');
        html += '<tr><td class="val">' + esc(h.host) + '</td><td class="num">' + fmt(h.total) + '</td><td class="num">' + fmt(h.distinct_ports) + '</td><td class="num">' + ((h.ratio||0)*100).toFixed(1) + '%</td><td>' + topPorts + '</td></tr>';
      }
      html += '</tbody></table></div>';
    }
  } else if (mode === "byte_pattern") {
    const patterns = data.patterns || [];
    const flagged = patterns.filter(p => p.flagged);
    const clean = patterns.filter(p => !p.flagged && !p.error);
    html += '<div class="summary">';
    html += '<div class="stat"><div class="stat-val">' + fmt(patterns.length) + '</div><div class="stat-lbl">Patterns</div></div>';
    html += '<div class="stat stat-flagged"><div class="stat-val">' + fmt(flagged.length) + '</div><div class="stat-lbl">Flagged</div></div>';
    html += '<div class="stat"><div class="stat-val">' + fmt(clean.length) + '</div><div class="stat-lbl">Clean</div></div>';
    html += '</div>';

    if (flagged.length) {
      html += '<div class="section"><h3>Flagged Patterns (' + flagged.length + ')</h3>';
      html += '<table><thead><tr><th>Pattern</th><th>Type</th><th class="num">Sessions</th><th>Expected Ports</th><th>Actual Ports</th><th>Unexpected</th></tr></thead><tbody>';
      for (const p of flagged) {
        const actualPorts = (p.ports || []).slice(0, 10).map(pt => '<span class="port-chip">' + pt.port + ' (' + pt.count + ')</span>').join(' ');
        const unexpPorts = (p.unexpected_ports || []).slice(0, 10).map(pt => '<span class="port-chip unexpected">' + pt.port + ' (' + pt.count + ')</span>').join(' ');
        html += '<tr class="flagged"><td class="val">' + esc(p.pattern) + '</td><td>' + esc(p.type) + '</td><td class="num">' + fmt(p.matched_sessions) + '</td><td>' + (p.expected_ports || []).join(', ') + '</td><td>' + actualPorts + '</td><td>' + unexpPorts + '</td></tr>';
      }
      html += '</tbody></table></div>';
    }
    if (clean.length) {
      html += '<div class="section"><h3>Clean Patterns (' + clean.length + ')</h3>';
      html += '<table><thead><tr><th>Pattern</th><th>Type</th><th class="num">Sessions</th><th>Expected Ports</th><th>Actual Ports</th></tr></thead><tbody>';
      for (const p of clean) {
        const actualPorts = (p.ports || []).slice(0, 10).map(pt => '<span class="port-chip">' + pt.port + ' (' + pt.count + ')</span>').join(' ');
        html += '<tr><td class="val">' + esc(p.pattern) + '</td><td>' + esc(p.type) + '</td><td class="num">' + fmt(p.matched_sessions) + '</td><td>' + (p.expected_ports || []).join(', ') + '</td><td>' + actualPorts + '</td></tr>';
      }
      html += '</tbody></table></div>';
    }
  }

  html += '<div class="footer">Generated by Luxray - Network Traffic Analyzer</div></body></html>';

  const blob = new Blob([html], {type: "text/html"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = 'luxray_port_scan_' + ts + '.html';
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── Dark mode ────────────────────────────────────────────────────────────────
function toggleDark() {
  const dark = document.body.classList.toggle("dark");
  localStorage.setItem("arkime_dark", dark ? "1" : "0");
  document.getElementById("darkToggle").textContent = dark ? "\u2600\uFE0F" : "\u{1F319}";
}
</script>
</body>
</html>"""


# ==============================================================================
# HTTP request handler
# ==============================================================================

DEV_MODE = False  # set via --dev
HTML_PATH_OVERRIDE = None


def _render_html():
    """Return the HTML, with CSRF token injected. In --dev, re-read from disk."""
    if DEV_MODE and HTML_PATH_OVERRIDE and os.path.exists(HTML_PATH_OVERRIDE):
        with open(HTML_PATH_OVERRIDE, "r", encoding="utf-8") as f:
            page = f.read()
    else:
        page = HTML_PAGE
    return page.replace("__CSRF_TOKEN__", CSRF_TOKEN).encode("utf-8")


def _render_iana_ports_html():
    """Generate an HTML page showing the loaded IANA port expectations with descriptions."""
    import html as html_mod
    port_info = _load_port_info_for_html()
    sorted_ports = sorted(port_info.keys(), key=lambda p: int(p))

    rows = []
    for port in sorted_ports:
        info = port_info[port]
        services = info["services"]
        descriptions = info["descriptions"]
        transports = sorted(info["transports"]) if info["transports"] else []

        services_str = html_mod.escape(", ".join(services))
        transport_str = "/".join(transports) if transports else ""
        desc_str = html_mod.escape(descriptions[0]) if descriptions else ""

        rows.append(
            f'<tr>'
            f'<td class="port">{port}</td>'
            f'<td class="transport">{transport_str}</td>'
            f'<td class="services">{services_str}</td>'
            f'<td class="desc">{desc_str}</td>'
            f'</tr>'
        )

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IANA Port Reference - Luxray</title>
<style>
:root {{
  --bg: #0f172a;
  --card: #1e293b;
  --border: #334155;
  --text-1: #f1f5f9;
  --text-2: #cbd5e1;
  --text-3: #64748b;
  --accent: #3b82f6;
  --green: #22c55e;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text-1);
  padding: 2rem;
  line-height: 1.5;
}}
.container {{
  max-width: 1200px;
  margin: 0 auto;
}}
h1 {{
  margin-bottom: 0.5rem;
  font-size: 1.5rem;
}}
.subtitle {{
  color: var(--text-3);
  margin-bottom: 1.5rem;
  font-size: 0.875rem;
}}
.search-box {{
  width: 100%;
  padding: 0.75rem 1rem;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-1);
  font-size: 1rem;
  margin-bottom: 1rem;
}}
.search-box:focus {{
  outline: none;
  border-color: var(--accent);
}}
.stats {{
  color: var(--text-3);
  font-size: 0.75rem;
  margin-bottom: 1rem;
}}
table {{
  width: 100%;
  border-collapse: collapse;
  background: var(--card);
  border-radius: 8px;
  overflow: hidden;
}}
th, td {{
  padding: 0.75rem 1rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
}}
th {{
  background: var(--border);
  font-weight: 600;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-2);
  position: sticky;
  top: 0;
}}
td.port {{
  font-family: monospace;
  font-weight: 600;
  color: var(--accent);
  width: 80px;
  white-space: nowrap;
}}
td.transport {{
  font-family: monospace;
  font-size: 0.75rem;
  color: var(--green);
  width: 70px;
  white-space: nowrap;
}}
td.services {{
  font-family: monospace;
  font-size: 0.875rem;
  color: var(--text-1);
  width: 200px;
}}
td.desc {{
  font-size: 0.875rem;
  color: var(--text-2);
}}
tr:hover {{
  background: rgba(59, 130, 246, 0.1);
}}
tr:last-child td {{
  border-bottom: none;
}}
.hidden {{
  display: none;
}}
.note {{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1rem;
  margin-bottom: 1.5rem;
  font-size: 0.875rem;
  color: var(--text-2);
}}
.note strong {{
  color: var(--text-1);
}}
.note code {{
  background: var(--border);
  padding: 0.125rem 0.375rem;
  border-radius: 3px;
  font-size: 0.8rem;
}}
a {{
  color: var(--accent);
  text-decoration: none;
}}
a:hover {{
  text-decoration: underline;
}}
</style>
</head>
<body>
<div class="container">
  <h1>IANA Port Reference</h1>
  <p class="subtitle">Port-to-service mappings used by Luxray Mode 2 (Unexpected Protocol Detection)</p>

  <div class="note">
    <strong>How this is used:</strong> In Mode 2, when you scan a port, Luxray checks if the observed
    protocol signatures (from the <code>protocols</code> field) match the expected services listed here.
    For example, if port 53 shows traffic with <code>http</code> instead of <code>dns</code>, it gets flagged as unexpected.
    <br><br>
    <strong>Expected Services:</strong> These are the protocol names that Arkime might report in its <code>protocols</code> field.
    If traffic on a port uses a protocol not in this list, it may indicate tunneling, misconfiguration, or malicious activity.
    <br><br>
    <strong>Source:</strong> <a href="https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml" target="_blank">IANA Service Name and Transport Protocol Port Number Registry</a>,
    plus common Arkime protocol additions (TLS, QUIC, etc.).
  </div>

  <input type="text" class="search-box" placeholder="Search by port, protocol, or description..." oninput="filterTable(this.value)">
  <div class="stats" id="stats">Showing {len(sorted_ports)} ports</div>

  <table>
    <thead>
      <tr>
        <th>Port</th>
        <th>Proto</th>
        <th>Expected Services</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody id="tableBody">
      {"".join(rows)}
    </tbody>
  </table>
</div>

<script>
function filterTable(query) {{
  const rows = document.querySelectorAll('#tableBody tr');
  const q = query.toLowerCase().trim();
  let visible = 0;

  rows.forEach(row => {{
    const text = row.textContent.toLowerCase();
    const match = !q || text.includes(q);
    row.classList.toggle('hidden', !match);
    if (match) visible++;
  }});

  document.getElementById('stats').textContent =
    q ? `Showing ${{visible}} of {len(sorted_ports)} ports` : `Showing {len(sorted_ports)} ports`;
}}
</script>
</body>
</html>'''


class Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        try:
            msg = " ".join(str(a) for a in args)
        except Exception:
            msg = "(log format error)"
        print(f"  {msg}")

    # ---- routing ----

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", _render_html())
        elif self.path == "/api/settings":
            try:    self._json(200, do_load_settings())
            except Exception as e: self._json(200, {"error": str(e)})
        elif self.path == "/api/presets":
            try:    self._json(200, do_list_presets())
            except Exception as e: self._json(200, {"error": str(e)})
        elif self.path == "/api/ps-presets":
            try:    self._json(200, do_list_ps_presets())
            except Exception as e: self._json(200, {"error": str(e)})
        elif self.path == "/api/baselines":
            try:    self._json(200, do_baseline_list())
            except Exception as e: self._json(200, {"error": str(e)})
        elif self.path == "/api/port-expectations-default":
            self._json(200, {"expectations": PORT_EXPECTATIONS_DEFAULT})
        elif self.path == "/iana-ports":
            self._send(200, "text/html; charset=utf-8", _render_iana_ports_html().encode("utf-8"))
        else:
            self._send(404, "text/plain", b"Not found")

    def do_POST(self):
        # CSRF check for all mutating endpoints
        if self.path != "/api/test":  # test is a POST too — still require token
            if self.headers.get("X-CSRF-Token", "") != CSRF_TOKEN:
                self._json(403, {"error": "CSRF token missing or invalid"})
                return

        # Special: SSE streaming analyze
        if self.path == "/api/analyze-stream":
            self._handle_analyze_stream()
            return

        length = int(self.headers.get("Content-Length", 0))
        raw    = self.rfile.read(length) if length else b""
        try:
            cfg = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            self._json(400, {"error": "Invalid JSON body"})
            return

        if self.path == "/api/test":
            self._json(200, do_test(cfg))

        elif self.path == "/api/analyze":
            # Non-streaming fallback
            try:
                cached = CACHE.get("analyze", cfg)
                if cached is not None:
                    self._json(200, {"results": cached, "cached": True})
                else:
                    results = do_analyze(cfg)
                    CACHE.put("analyze", cfg, results)
                    self._json(200, {"results": results})
            except Exception as e:
                self._json(200, {"error": str(e)})

        elif self.path == "/api/arkime-fields":
            try:    self._json(200, do_arkime_fields(cfg))
            except Exception as e: self._json(200, {"error": str(e)})

        elif self.path == "/api/arkime-tags":
            try:    self._json(200, do_arkime_tags(cfg))
            except Exception as e: self._json(200, {"error": str(e)})

        elif self.path == "/api/settings":
            try:    self._json(200, do_save_settings(cfg))
            except Exception as e: self._json(200, {"error": str(e)})

        elif self.path == "/api/preset/save":
            try:    self._json(200, do_save_preset(cfg))
            except Exception as e: self._json(200, {"error": str(e)})

        elif self.path == "/api/preset/load":
            try:    self._json(200, do_load_preset(cfg))
            except Exception as e: self._json(200, {"error": str(e)})

        elif self.path == "/api/preset/delete":
            try:    self._json(200, do_delete_preset(cfg))
            except Exception as e: self._json(200, {"error": str(e)})

        elif self.path == "/api/ps-preset/save":
            try:    self._json(200, do_save_ps_preset(cfg))
            except Exception as e: self._json(200, {"error": str(e)})

        elif self.path == "/api/ps-preset/load":
            try:    self._json(200, do_load_ps_preset(cfg))
            except Exception as e: self._json(200, {"error": str(e)})

        elif self.path == "/api/ps-preset/delete":
            try:    self._json(200, do_delete_ps_preset(cfg))
            except Exception as e: self._json(200, {"error": str(e)})

        elif self.path == "/api/correlate":
            extras = {
                "pivot_field": cfg.get("pivot_field"),
                "pivot_values": sorted(cfg.get("pivot_values") or ([cfg.get("pivot_value")] if cfg.get("pivot_value") else [])),
                "pivot_match": cfg.get("pivot_match", "any"),
                "target_field": cfg.get("target_field"),
            }
            try:
                cached = CACHE.get("correlate", cfg, extras)
                if cached is not None:
                    out = dict(cached); out["cached"] = True
                    self._json(200, out)
                else:
                    out = do_correlate(cfg)
                    CACHE.put("correlate", cfg, out, extras)
                    self._json(200, out)
            except Exception as e:
                self._json(200, {"error": str(e)})

        elif self.path == "/api/sessions":
            extras = {
                "extra_expr": cfg.get("extra_expr", ""),
                "pivot_field": cfg.get("pivot_field"),
                "pivot_values": sorted(cfg.get("pivot_values") or []),
                "pivot_match": cfg.get("pivot_match", "any"),
                "session_limit": cfg.get("session_limit"),
            }
            try:
                cached = CACHE.get("sessions", cfg, extras)
                if cached is not None:
                    out = dict(cached); out["cached"] = True
                    self._json(200, out)
                else:
                    out = do_sessions(cfg)
                    CACHE.put("sessions", cfg, out, extras)
                    self._json(200, out)
            except Exception as e:
                self._json(200, {"error": str(e)})

        elif self.path == "/api/anomaly-hints":
            extras = {"pairs": sorted([(p.get("field",""), p.get("value","")) for p in (cfg.get("pairs") or [])])}
            try:
                cached = CACHE.get("anomaly", cfg, extras)
                if cached is not None:
                    out = dict(cached); out["cached"] = True
                    self._json(200, out)
                else:
                    out = do_anomaly_hints(cfg)
                    CACHE.put("anomaly", cfg, out, extras)
                    self._json(200, out)
            except Exception as e:
                self._json(200, {"error": str(e)})

        elif self.path == "/api/port-scan":
            mode = cfg.get("mode", "sig_to_port")
            extras = {
                "mode":           mode,
                "sig_field":      cfg.get("signature_field"),
                "port_field":     cfg.get("port_field"),
                "host_field":     cfg.get("host_field"),
                "min_sessions":   cfg.get("min_sessions"),
                "max_sigs":       cfg.get("max_sigs"),
                "dominance":      cfg.get("dominance"),
                "outlier_max":    cfg.get("outlier_max"),
                "ports_to_check": sorted(cfg.get("ports_to_check") or []),
                "port_expectations": cfg.get("port_expectations"),
                "min_distinct_ports": cfg.get("min_distinct_ports"),
                "port_ratio_threshold": cfg.get("port_ratio_threshold"),
                "pinned_signature_value": cfg.get("pinned_signature_value"),
            }
            try:
                cached = CACHE.get("port_scan", cfg, extras)
                if cached is not None:
                    out = dict(cached); out["cached"] = True
                    self._json(200, out)
                    return
                if mode == "sig_to_port":
                    out = do_port_scan_sig_to_port(cfg)
                elif mode == "port_to_sig":
                    out = do_port_scan_port_to_sig(cfg)
                elif mode == "host_diversity":
                    out = do_port_scan_host_diversity(cfg)
                elif mode == "byte_pattern":
                    out = do_port_scan_byte_pattern(cfg)
                else:
                    self._json(200, {"error": f"Unknown scan mode: {mode}"})
                    return
                CACHE.put("port_scan", cfg, out, extras)
                self._json(200, out)
            except Exception as e:
                self._json(200, {"error": str(e)})

        elif self.path == "/api/port-scan-stream":
            # SSE variant, handled separately
            self._handle_port_scan_stream_body(cfg)

        elif self.path == "/api/baseline/save":
            try:    self._json(200, do_baseline_save(cfg))
            except Exception as e: self._json(200, {"error": str(e)})

        elif self.path == "/api/baseline/delete":
            try:    self._json(200, do_baseline_delete(cfg))
            except Exception as e: self._json(200, {"error": str(e)})

        elif self.path == "/api/baseline/compare":
            try:    self._json(200, do_baseline_compare(cfg))
            except Exception as e: self._json(200, {"error": str(e)})

        else:
            self._send(404, "text/plain", b"Not found")

    # ---- SSE streaming helpers ----

    def _sse_stream(self, worker_fn, progress_key="field", on_done=None):
        """Common SSE scaffolding: headers, queue, heartbeat loop."""
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
        except Exception:
            return

        def send_event(event, data):
            try:
                payload = f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
                self.wfile.write(payload.encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                raise

        import queue
        q = queue.Queue()

        def progress(done, total, item):
            q.put(("progress", done, total, item))

        def worker():
            try:
                result = worker_fn(progress)
                q.put(("done", result))
            except Exception as e:
                q.put(("error", str(e)))

        try:
            t = threading.Thread(target=worker, daemon=True)
            t.start()

            while True:
                try:
                    item = q.get(timeout=15)
                except queue.Empty:
                    try:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    continue

                kind = item[0]
                if kind == "progress":
                    _, done, total, cur = item
                    send_event("progress", {"done": done, "total": total, progress_key: cur})
                elif kind == "done":
                    result = item[1]
                    if on_done:
                        on_done(result)
                    send_event("result", result)
                    return
                elif kind == "error":
                    send_event("error", {"error": item[1]})
                    return
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as e:
            try:
                send_event("error", {"error": str(e)})
            except Exception:
                pass

    def _handle_analyze_stream(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            cfg = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            self._json(400, {"error": "Invalid JSON body"})
            return

        cached = CACHE.get("analyze", cfg)
        if cached is not None:
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()
                total = len(cfg.get("fields") or [])
                for ev, data in [
                    ("progress", {"done": total, "total": total, "field": None, "cached": True}),
                    ("result", {"results": cached, "cached": True}),
                ]:
                    payload = f"event: {ev}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
                    self.wfile.write(payload.encode("utf-8"))
                    self.wfile.flush()
            except Exception:
                pass
            return

        fields = [f for f in (cfg.get("fields") or []) if f.strip()]
        if not fields:
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(b'event: result\ndata: {"results": []}\n\n')
                self.wfile.flush()
            except Exception:
                pass
            return

        def worker_fn(progress):
            results = do_analyze(cfg, progress=progress)
            return {"results": results}

        def on_done(result):
            CACHE.put("analyze", cfg, result.get("results"))

        self._sse_stream(worker_fn, progress_key="field", on_done=on_done)

    def _handle_port_scan_stream_body(self, cfg):
        mode = cfg.get("mode", "sig_to_port")

        def worker_fn(progress):
            if mode == "sig_to_port":
                return do_port_scan_sig_to_port(cfg, progress=progress)
            elif mode == "port_to_sig":
                return do_port_scan_port_to_sig(cfg, progress=progress)
            elif mode == "host_diversity":
                return do_port_scan_host_diversity(cfg, progress=progress)
            elif mode == "byte_pattern":
                return do_port_scan_byte_pattern(cfg, progress=progress)
            else:
                raise ValueError(f"Unknown mode: {mode}")

        self._sse_stream(worker_fn, progress_key="item")

    # ---- low-level ----

    def _send(self, code, content_type, body):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._send(code, "application/json; charset=utf-8", body)


class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    """Threaded server so progress stream doesn't block other requests."""
    daemon_threads = True
    allow_reuse_address = True


# ==============================================================================
# Entry point
# ==============================================================================

def _check_required_files():
    """Verify required data files exist before starting. Returns True if OK."""
    base = os.path.dirname(os.path.abspath(__file__))
    required = [
        ("arkime_ports.json", "Port/protocol mappings (required for port scan and reference page)"),
    ]
    optional = [
        ("service-names-port-numbers.csv", "IANA port registry (optional - enriches port descriptions if present)"),
    ]
    missing = [(name, desc) for name, desc in required if not os.path.exists(os.path.join(base, name))]

    print()
    print("  Required files:")
    for name, desc in required:
        status = "OK " if os.path.exists(os.path.join(base, name)) else "MISSING"
        print(f"    [{status}] {name}")
        print(f"           {desc}")
    print()
    print("  Optional files:")
    for name, desc in optional:
        status = "found  " if os.path.exists(os.path.join(base, name)) else "not found"
        print(f"    [{status}] {name}")
        print(f"           {desc}")
    print()

    if missing:
        print("  ERROR: Missing required file(s):")
        for name, desc in missing:
            print(f"    - {name}: {desc}")
        print()
        return False
    return True


def main():
    global DEV_MODE, HTML_PATH_OVERRIDE
    p = argparse.ArgumentParser(description="Luxray — local web UI")
    p.add_argument("--port",       type=int, default=8080,        help="Port to listen on (default: 8080)")
    p.add_argument("--host",       default="127.0.0.1",           help="Bind address (default: 127.0.0.1; use 0.0.0.0 in Docker)")
    p.add_argument("--no-browser", action="store_true",           help="Don't auto-open the browser")
    p.add_argument("--dev",        action="store_true",           help="Dev mode: read HTML from index.html on disk if present")
    args = p.parse_args()

    DEV_MODE = args.dev
    if DEV_MODE:
        HTML_PATH_OVERRIDE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
        if os.path.exists(HTML_PATH_OVERRIDE):
            print(f"[dev] Will serve HTML from: {HTML_PATH_OVERRIDE}")
        else:
            print(f"[dev] No {HTML_PATH_OVERRIDE} found — using embedded HTML")
            HTML_PATH_OVERRIDE = None

    print()
    print("=" * 50)
    print("  Luxray - startup check")
    print("=" * 50)
    if not _check_required_files():
        sys.exit(1)

    host = args.host
    url  = f"http://localhost:{args.port}"

    try:
        server = ThreadingHTTPServer((host, args.port), Handler)
    except OSError as e:
        print(f"Error: cannot bind to {host}:{args.port} — {e}")
        print(f"Try a different port:  python arkime_web.py --port 9090")
        sys.exit(1)

    print()
    print("=" * 50)
    print("  Luxray v3")
    print(f"  Running at: {url}")
    print("  Press Ctrl+C to stop")
    print("=" * 50)
    print()

    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
