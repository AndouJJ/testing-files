#!/usr/bin/env python3
"""
Arkime Analyzer — Web UI (v3)
=============================
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


def _ssl_ctx(cfg):
    if cfg.get("skip_tls_verify"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
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
    Arkime expressions use double-quoted strings; backslash and double-quote
    must be escaped.
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
    max_unique = int(cfg.get("max_unique", 0))
    if max_unique > 0:
        params["maxvaluesperfield"] = str(max_unique)

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

    workers = min(max(1, len(fields)), int(cfg.get("max_workers", 6)))
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

def _pivot_expression(pivot_field, pivot_values, match="any"):
    """Build an expression clause for one or more pivot values."""
    if not pivot_values:
        return ""
    if isinstance(pivot_values, str):
        pivot_values = [pivot_values]
    op = " || " if match == "any" else " && "
    parts = [f'{pivot_field} == "{_esc_val(v)}"' for v in pivot_values]
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
        "fields": "ip.src,ip.dst,port.src,port.dst,firstPacket,lastPacket,"
                  "totBytes,network.packets,protocols,node,tags",
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

def do_anomaly_hints(cfg):
    """
    For a list of (field, value) pairs, return the source-IP concentration for
    each — i.e. how many distinct src IPs contacted that value, and the top
    src IP's share. High concentration + low volume = classic beaconing shape.
    """
    pairs = cfg.get("pairs") or []
    if not pairs:
        return {"hints": []}

    base_expr = _build_expr(cfg)
    hints = []

    def _one(pair):
        field = pair.get("field", "")
        value = pair.get("value", "")
        try:
            pivot = f'{field} == "{_esc_val(value)}"'
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
    max_workers = min(len(pairs), int(cfg.get("max_workers", 6)))
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

# Default expected signatures for well-known ports (used by mode 2).
# These are hints, not strict rules. Users can edit.
PORT_EXPECTATIONS_DEFAULT = {
    "53":   ["dns"],
    "80":   ["http", "tcp"],
    "443":  ["tls", "http", "tcp"],
    "22":   ["ssh", "tcp"],
    "25":   ["smtp", "tcp"],
    "110":  ["pop3", "tcp"],
    "143":  ["imap", "tcp"],
    "993":  ["imaps", "tls", "tcp"],
    "995":  ["pop3s", "tls", "tcp"],
    "3389": ["rdp", "tcp"],
    "445":  ["smb", "tcp"],
    "139":  ["smb", "netbios", "tcp"],
    "21":   ["ftp", "tcp"],
    "23":   ["telnet", "tcp"],
    "389":  ["ldap", "tcp"],
    "636":  ["ldaps", "tls", "tcp"],
}


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
    Mode 1: For each signature with >= min_sessions hits, fetch its port
    distribution and score it.

    cfg keys used:
      signature_field, port_field, min_sessions, max_sigs,
      dominance, outlier_max
    Plus the usual time/expression/allowlist.
    """
    sig_field  = cfg.get("signature_field") or "tls.ja3"
    port_field = cfg.get("port_field") or "port.dst"
    min_sess   = int(cfg.get("min_sessions", 10))
    max_sigs   = int(cfg.get("max_sigs", 100))
    dominance  = float(cfg.get("dominance", 0.9))
    outlier_max= int(cfg.get("outlier_max", 3))

    _ = _time_params(cfg)  # validate
    base_expr = _build_expr(cfg)

    # Step A: get the top signatures by volume
    sigs_raw = _fetch_unique(cfg, sig_field, base_expr)
    eligible = [(v, c) for v, c in sigs_raw if c >= min_sess]
    truncated = len(eligible) > max_sigs
    eligible = eligible[:max_sigs]

    if not eligible:
        return {
            "mode": "sig_to_port",
            "signature_field": sig_field,
            "port_field": port_field,
            "signatures": [],
            "total_signatures_seen": len(sigs_raw),
            "eligible_signatures": 0,
            "truncated": truncated,
        }

    # Step B: for each signature, fetch its port distribution
    def one(sig_val, sig_count):
        try:
            pivot = f'{sig_field} == "{_esc_val(sig_val)}"'
            full  = f'{pivot} && {base_expr}' if base_expr else pivot
            port_raw = _fetch_unique(cfg, port_field, full)
            port_counts = {v: c for v, c in port_raw}
            dom, dom_share, entropy, total = _port_share_stats(port_counts)
            ports_sorted = sorted(port_counts.items(), key=lambda kv: kv[1], reverse=True)
            outliers = [(p, c) for p, c in ports_sorted
                        if p != dom and c <= outlier_max]
            flagged = (
                dom_share >= dominance and len(outliers) > 0
                and total >= min_sess
            )
            return {
                "signature":       sig_val,
                "total":           total,
                "dominant_port":   dom,
                "dominant_share":  dom_share,
                "distinct_ports":  len(port_counts),
                "entropy":         entropy,
                "ports":           [{"port": p, "count": c} for p, c in ports_sorted],
                "outliers":        [{"port": p, "count": c} for p, c in outliers],
                "flagged":         flagged,
            }
        except Exception as e:
            return {"signature": sig_val, "total": sig_count, "error": str(e)}

    workers = min(len(eligible), int(cfg.get("max_workers", 6)))
    results = []
    done = 0
    total_n = len(eligible)
    if progress:
        progress(0, total_n, None)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(one, v, c): v for v, c in eligible}
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            done += 1
            if progress:
                progress(done, total_n, r.get("signature"))

    # Sort: flagged first (by total desc), then by distinct_ports desc
    results.sort(key=lambda r: (
        0 if r.get("flagged") else 1,
        -(r.get("total") or 0),
    ))

    return {
        "mode":                   "sig_to_port",
        "signature_field":        sig_field,
        "port_field":             port_field,
        "signatures":             results,
        "total_signatures_seen":  len(sigs_raw),
        "eligible_signatures":    len(eligible),
        "truncated":              truncated,
        "thresholds": {
            "min_sessions": min_sess,
            "max_sigs":     max_sigs,
            "dominance":    dominance,
            "outlier_max":  outlier_max,
        },
    }


def do_port_scan_port_to_sig(cfg, progress=None):
    """
    Mode 2: For each port in cfg['ports_to_check'], fetch the distribution of
    cfg['signature_field'] on that port, and compare against expected
    signatures.
    """
    sig_field  = cfg.get("signature_field") or "protocols"
    port_field = cfg.get("port_field") or "port.dst"
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

    workers = min(len(ports), int(cfg.get("max_workers", 6)))
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
    Mode 3: For each src IP seen in the window (optionally filtered to a
    signature), compute distinct dst ports used and the port-per-session
    ratio. Flag hosts where the ratio is high and distinct ports exceeds
    a threshold.
    """
    sig_field   = cfg.get("signature_field") or ""   # optional
    port_field  = cfg.get("port_field") or "port.dst"
    host_field  = cfg.get("host_field") or "ip.src"
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

    hosts_raw = _fetch_unique(cfg, host_field, base_expr)
    eligible = [(h, c) for h, c in hosts_raw if c >= min_sess][:max_hosts]
    truncated = len([h for h, c in hosts_raw if c >= min_sess]) > max_hosts

    if not eligible:
        return {
            "mode":            "host_diversity",
            "signature_field": sig_field,
            "port_field":      port_field,
            "host_field":      host_field,
            "hosts":           [],
            "truncated":       truncated,
        }

    def one(host, count):
        try:
            pivot = f'{host_field} == "{_esc_val(host)}"'
            full  = f'{pivot} && {base_expr}' if base_expr else pivot
            port_raw = _fetch_unique(cfg, port_field, full)
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

    workers = min(len(eligible), int(cfg.get("max_workers", 6)))
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
        "host_field":      host_field,
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
    store["current"] = _strip_password(data)
    _save_store(store)
    return {"ok": True}


def do_load_settings():
    store = _load_store()
    return store.get("current", {})


def do_list_presets():
    store = _load_store()
    presets = store.get("presets", {})
    return {"names": sorted(presets.keys())}


def do_save_preset(data):
    name = (data.get("name") or "").strip()
    if not name:
        raise ValueError("Preset name is required")
    cfg = data.get("config") or {}
    store = _load_store()
    store.setdefault("presets", {})[name] = _strip_password(cfg)
    _save_store(store)
    return {"ok": True, "name": name}


def do_load_preset(data):
    name = (data.get("name") or "").strip()
    store = _load_store()
    presets = store.get("presets", {})
    if name not in presets:
        raise ValueError(f"Preset not found: {name}")
    return {"config": presets[name]}


def do_delete_preset(data):
    name = (data.get("name") or "").strip()
    store = _load_store()
    presets = store.get("presets", {})
    if name in presets:
        del presets[name]
        store["presets"] = presets
        _save_store(store)
    return {"ok": True}


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


CACHE = _Cache()


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
<title>Arkime Analyzer</title>
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
.tag-add-row{display:flex;gap:6px;margin-top:5px}
.tag-add-row input{flex:1}
.tag-add-row .srch-wrap{flex:1}
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
#tagList{display:flex;flex-wrap:wrap;gap:5px;margin-top:7px;min-height:20px}
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

.run-header{background:var(--surface);border-radius:9px;padding:12px 16px;margin-bottom:14px;font-size:.78rem;color:var(--text-3);display:flex;flex-wrap:wrap;gap:10px;align-items:center;box-shadow:0 1px 3px rgba(0,0,0,.06)}
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
.card-top{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px;gap:12px;flex-wrap:wrap}
.card-title{font-weight:700;font-size:.95rem;color:var(--text-1);font-family:'SFMono-Regular',Consolas,monospace}
.card-sub{font-size:.72rem;color:var(--text-4);margin-top:2px}
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
  <h1>Arkime Analyzer</h1>
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
    <div class="srch-wrap" data-mode="tag">
      <input type="text" id="tagInput" class="srch-inp" placeholder="Search or type a tag…"
             oninput="_srchRender(this,arkimeTags,this.value)"
             onfocus="_srchRender(this,arkimeTags,this.value)"
             onblur="_srchClose(this)"
             onkeydown="if(event.key==='Enter')addTag()">
      <button class="srch-arrow" onmousedown="event.preventDefault()" onclick="_srchToggle(this.previousElementSibling,arkimeTags)">▾</button>
      <div class="srch-list"></div>
    </div>
    <button class="add-btn" onclick="addTag()">+ Add tag</button>
    <div id="tagList"></div>
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
        <input type="number" id="maxWorkers" value="6" min="1" max="16">
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
      <label class="no-mt">Mode</label>
      <select id="psMode" onchange="renderPortScanMode()">
        <option value="sig_to_port">1 &mdash; Signature on unexpected port</option>
        <option value="port_to_sig">2 &mdash; Unexpected protocol on known port</option>
        <option value="host_diversity">3 &mdash; Host using many ports (scan/beacon)</option>
      </select>

      <div id="psMode_sig_to_port">
        <label>Signature field</label>
        <select id="psSigField" onchange="syncPsCustom('psSigField','psSigFieldCustom')">
          <option value="tls.ja3">tls.ja3</option>
          <option value="tls.ja3s">tls.ja3s</option>
          <option value="http.useragent">http.useragent</option>
          <option value="protocols">protocols</option>
          <option value="cert.issuer">cert.issuer</option>
          <option value="__custom__">Custom&hellip;</option>
        </select>
        <input type="text" id="psSigFieldCustom" placeholder="custom field name" style="display:none;margin-top:4px">
        <label>Port field</label>
        <input type="text" id="psPortField" value="port.dst">
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
          Flags signatures where one port handles &ge; dominance share AND
          outlier ports have &le; outlier-max sessions.
        </div>
      </div>

      <div id="psMode_port_to_sig" style="display:none">
        <label>Signature field</label>
        <select id="psSigField2" onchange="syncPsCustom('psSigField2','psSigField2Custom')">
          <option value="protocols">protocols</option>
          <option value="tls.ja3">tls.ja3</option>
          <option value="http.useragent">http.useragent</option>
          <option value="__custom__">Custom&hellip;</option>
        </select>
        <input type="text" id="psSigField2Custom" placeholder="custom field name" style="display:none;margin-top:4px">
        <label>Port field</label>
        <input type="text" id="psPortField2" value="port.dst">
        <label>Ports to check <span style="font-weight:400;color:#9ca3af">(one per line)</span></label>
        <textarea id="psPortsList" rows="4" placeholder="53&#10;80&#10;443&#10;22"></textarea>
        <div class="btn-row" style="margin-top:4px">
          <button class="btn-outline" onclick="loadDefaultPorts()" style="flex:1">Load default port list</button>
        </div>
        <label>Expected signatures <span style="font-weight:400;color:#9ca3af">(port: sig1,sig2)</span></label>
        <textarea id="psExpectations" rows="5" placeholder="53: dns&#10;443: tls,http&#10;80: http,tcp"></textarea>
      </div>

      <div id="psMode_host_diversity" style="display:none">
        <label>Host field</label>
        <input type="text" id="psHostField" value="ip.src">
        <label>Port field</label>
        <input type="text" id="psPortField3" value="port.dst">
        <label>Pin to signature value <span style="font-weight:400;color:#9ca3af">(optional)</span></label>
        <div class="row2">
          <input type="text" id="psPinField" placeholder="field (e.g. tls.ja3)">
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

      <button class="btn-primary" id="psRunBtn" onclick="runPortScan()" style="margin-top:10px">&#9654; Run Port Scan</button>
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
  inp.value  = el.dataset.val;
  wrap.querySelector('.srch-list').style.display = 'none';
  const mode = wrap.dataset.mode;
  if (mode === 'field') {
    fields[parseInt(wrap.dataset.idx)] = el.dataset.val;
  } else if (mode === 'tag') {
    addTag();
  }
}

function _srchClose(inp) {
  setTimeout(() => {
    const list = inp.parentElement && inp.parentElement.querySelector('.srch-list');
    if (list) list.style.display = 'none';
  }, 150);
}

// ── Tags ─────────────────────────────────────────────────────────────────────
function addTag() {
  const inp = document.getElementById("tagInput");
  const val = inp.value.trim();
  if (val && !tags.includes(val)) { tags.push(val); renderTags(); }
  inp.value = "";
  const list = inp.parentElement && inp.parentElement.querySelector('.srch-list');
  if (list) list.style.display = 'none';
  inp.focus();
}
function removeTag(i) { tags.splice(i, 1); renderTags(); }
function renderTags() {
  document.getElementById("tagList").innerHTML = tags.map((t, i) =>
    `<span class="pill">${esc(t)}<button onclick="removeTag(${i})" title="Remove">&#x2715;</button></span>`
  ).join("");
}

// ── Fields ───────────────────────────────────────────────────────────────────
function addField(val) { fields.push(val || (arkimeFields[0] || "")); renderFields(); }
function removeField(i) { fields.splice(i, 1); renderFields(); }
function renderFields() {
  document.getElementById("fieldList").innerHTML = fields.map((f, i) => {
    if (arkimeFields.length) {
      return `<div class="field-row">
        <div class="srch-wrap" data-mode="field" data-idx="${i}">
          <input type="text" class="srch-inp" value="${esc(f)}" placeholder="Search fields…"
                 oninput="_srchRender(this,arkimeFields,this.value);fields[${i}]=this.value"
                 onfocus="_srchRender(this,arkimeFields,this.value)"
                 onblur="_srchClose(this)"
                 onchange="fields[${i}]=this.value">
          <button class="srch-arrow" onmousedown="event.preventDefault()" onclick="_srchToggle(this.previousElementSibling,arkimeFields)">▾</button>
          <div class="srch-list"></div>
        </div>
        <button class="rm-btn" onclick="removeField(${i})" title="Remove">&#x2715;</button>
      </div>`;
    }
    return `<div class="field-row">
      <input type="text" value="${esc(f)}" placeholder="e.g. http.useragent"
             oninput="fields[${i}]=this.value">
      <button class="rm-btn" onclick="removeField(${i})" title="Remove">&#x2715;</button>
    </div>`;
  }).join("");
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
    max_workers:      parseInt(document.getElementById("maxWorkers").value) || 6,
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

// ── Test connection ──────────────────────────────────────────────────────────
async function testConn() {
  setConn("busy", "Testing…");
  document.getElementById("testBtn").disabled = true;
  try {
    const cfg = getConfig();
    const res = await apiFetch("/api/test", cfg);
    setConn(res.ok ? "ok" : "err", res.message);
    if (res.ok) { loadArkimeFields(cfg); loadArkimeTags(cfg); }
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
    if (res.ok && res.tags.length) arkimeTags = res.tags;
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

  const toSave = {...cfg}; delete toSave.password;
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
  const maxTop  = r.top_n.length ? r.top_n[0].count : 1;
  const topKey  = `${r.field}::top`;
  const rareKey = `${r.field}::rare`;

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
    <div class="card-top">
      <div>
        <div class="card-title">${esc(r.field)}</div>
        <div class="card-sub">${fmt(r.skipped)} allowlisted value${r.skipped!==1?"s":""} hidden</div>
      </div>
      <div class="card-btns">
        <button class="btn-outline" onclick="dlCSV('${esc(r.field)}','top')">&#x2193; Top CSV</button>
        <button class="btn-outline" onclick="dlCSV('${esc(r.field)}','rare')">&#x2193; Rare CSV</button>
      </div>
    </div>
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
        <th class="sortable" onclick="sortTable('${esc(topKey)}','value')">Value <span class="sort-ind"></span></th>
        <th class="r sortable" onclick="sortTable('${esc(topKey)}','count')">Count <span class="sort-ind">&#x25BC;</span></th>
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
        <th class="sortable" onclick="sortTable('${esc(rareKey)}','value')">Value <span class="sort-ind"></span></th>
        <th class="r sortable" onclick="sortTable('${esc(rareKey)}','count')">Count <span class="sort-ind">&#x25BC;</span></th>
        <th>Bar</th>
        ${cfg.anom_hints ? '<th class="anom-col">Anomaly</th>' : ''}
        <th></th>
      </tr></thead>
      <tbody>${rareRows}</tbody>
    </table>
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

function rerenderCard(field) {
  if (!lastCfg || !lastResults[field]) return;
  // Re-render just this card
  const cards = document.querySelectorAll(".card");
  for (const c of cards) {
    if (c.getAttribute("data-field") === field) {
      const tmp = document.createElement("div");
      tmp.innerHTML = resultCard(lastResults[field], lastCfg);
      c.replaceWith(tmp.firstElementChild);
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
  const safeCfg = {...lastCfg};
  delete safeCfg.password;
  delete safeCfg.api_key;
  const report = {
    generated_at: new Date().toISOString(),
    config: safeCfg,
    results: Object.values(lastResults),
    anomaly_hints: anomHints,
  };
  const ts = new Date().toISOString().slice(0, 19).replace(/[-:T]/g, "").slice(0, 15);
  const blob = new Blob([JSON.stringify(report, null, 2)], {type: "application/json"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `arkime_report_${ts}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── CSV download ─────────────────────────────────────────────────────────────
function dlCSV(field, label) {
  const r = lastResults[field];
  if (!r) return;
  const rows = label === "top" ? r.top_n : r.rare;
  const safe = field.replace(/\./g, "_");
  const ts   = new Date().toISOString().slice(0, 19).replace(/[-:T]/g, "").slice(0, 15);
  const csv  = ["value,count", ...rows.map(row =>
    `"${String(row.value).replace(/"/g, '""')}",${row.count}`
  )].join("\r\n");
  const a = document.createElement("a");
  a.href     = URL.createObjectURL(new Blob([csv], {type: "text/csv"}));
  a.download = `arkime_${safe}_${label}_${ts}.csv`;
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
    if (saved && !saved.error && Object.keys(saved).length) loadConfig(saved);
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

function renderSessionsInto(bodyId, data) {
  const sessions = data.sessions || [];
  const total    = data.total    || 0;

  if (!sessions.length) {
    document.getElementById(bodyId).innerHTML =
      '<div class="empty">No sessions found for this value in the selected time range.</div>';
    return;
  }

  const baseUrl = document.getElementById("url").value.trim();

  const rows = sessions.map(s => {
    const srcIp   = s["ip.src"]   || s.srcIp   || "—";
    const dstIp   = s["ip.dst"]   || s.dstIp   || "—";
    const srcPort = s["port.src"] || s.srcPort  || "";
    const dstPort = s["port.dst"] || s.dstPort  || "";
    const proto   = Array.isArray(s.protocols) ? s.protocols.join(", ")
                  : (s.protocols || s.ipProtocol || "—");
    const bytes   = s.totBytes || s.totDataBytes || 0;
    const pkts    = s["network.packets"] || s.packets || s.totPackets || 0;
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
    const sStart  = fp ? Math.floor(fp/1000) : 0;
    const sEnd    = lp ? Math.floor(lp/1000)+1 : sStart+1;
    const arkLink = sid
      ? `${baseUrl}/sessions?date=-1&startTime=${sStart}&stopTime=${sEnd}&expression=${encodeURIComponent("id=="+sid)}`
      : "";

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

  const countNote = total > sessions.length
    ? `Showing ${sessions.length} of ${fmt(total)} sessions`
    : `${fmt(total)} session${total !== 1 ? "s" : ""}`;

  document.getElementById(bodyId).innerHTML = `
    <div class="corr-expr">Expression: ${esc(data.expression)}</div>
    <div class="modal-count">${countNote}</div>
    <table>
      <thead><tr>
        <th>Time (UTC)</th><th>Source</th><th>Destination</th><th>Protocol</th>
        <th class="r">Bytes</th><th class="r">Pkts</th><th class="r">Dur</th>
        <th>Tags</th><th>Node</th><th></th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function truncate(s, n) { return String(s).length > n ? String(s).slice(0, n-1) + "…" : String(s); }
function jsStr(s) { return String(s).replace(/\\/g,"\\\\").replace(/'/g,"\\'").replace(/\n/g,"\\n"); }

// ── Port Anomaly Scan ────────────────────────────────────────────────────────
let lastPortScan = null;       // most recent mode-1 scan result (for baselining)
let baselineList = [];

function togglePortScan() {
  const body = document.getElementById("portScanBody");
  const btn  = document.getElementById("portScanToggle");
  const show = body.style.display === "none";
  body.style.display = show ? "" : "none";
  btn.textContent = show ? "Hide" : "Show";
  if (show) refreshBaselines();
}

function renderPortScanMode() {
  const mode = document.getElementById("psMode").value;
  document.getElementById("psMode_sig_to_port").style.display   = mode === "sig_to_port"   ? "" : "none";
  document.getElementById("psMode_port_to_sig").style.display   = mode === "port_to_sig"   ? "" : "none";
  document.getElementById("psMode_host_diversity").style.display= mode === "host_diversity"? "" : "none";
  document.getElementById("psBaselineBlock").style.display      = mode === "sig_to_port"   ? "" : "none";
}

function syncPsCustom(selId, customId) {
  const sel = document.getElementById(selId);
  const custom = document.getElementById(customId);
  custom.style.display = sel.value === "__custom__" ? "" : "none";
}

function psSignatureField() {
  const mode = document.getElementById("psMode").value;
  if (mode === "sig_to_port") {
    const s = document.getElementById("psSigField").value;
    return s === "__custom__" ? document.getElementById("psSigFieldCustom").value.trim() : s;
  }
  if (mode === "port_to_sig") {
    const s = document.getElementById("psSigField2").value;
    return s === "__custom__" ? document.getElementById("psSigField2Custom").value.trim() : s;
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
    out.port_field      = document.getElementById("psPortField").value.trim() || "port.dst";
    out.min_sessions    = parseInt(document.getElementById("psMinSessions").value) || 10;
    out.max_sigs        = parseInt(document.getElementById("psMaxSigs").value) || 100;
    out.dominance       = parseFloat(document.getElementById("psDominance").value) || 0.9;
    out.outlier_max     = parseInt(document.getElementById("psOutlierMax").value) || 3;
  } else if (mode === "port_to_sig") {
    out.signature_field   = psSignatureField() || "protocols";
    out.port_field        = document.getElementById("psPortField2").value.trim() || "port.dst";
    out.ports_to_check    = parsePortsList();
    out.port_expectations = parseExpectations();
  } else if (mode === "host_diversity") {
    out.host_field            = document.getElementById("psHostField").value.trim() || "ip.src";
    out.port_field            = document.getElementById("psPortField3").value.trim() || "port.dst";
    out.signature_field       = document.getElementById("psPinField").value.trim();
    out.pinned_signature_value= document.getElementById("psPinValue").value;
    out.min_sessions          = parseInt(document.getElementById("psMinSessions3").value) || 20;
    out.min_distinct_ports    = parseInt(document.getElementById("psMinDistinctPorts").value) || 10;
    out.port_ratio_threshold  = parseFloat(document.getElementById("psPortRatio").value) || 0.4;
    out.max_hosts             = parseInt(document.getElementById("psMaxHosts").value) || 100;
  }
  return out;
}

async function runPortScan() {
  const cfg = getPortScanCfg();
  if (!cfg.url) { toast("Please enter an Arkime URL.", "err"); return; }
  if (cfg.mode === "sig_to_port" && !cfg.signature_field) { toast("Signature field is required", "err"); return; }
  if (cfg.mode === "port_to_sig" && !cfg.ports_to_check.length) { toast("Add at least one port to check", "err"); return; }

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

  try {
    const data = await runPortScanStreaming(cfg);
    if (data.error) { showError(panel, "Port scan failed", data.error); return; }
    renderPortScanResults(panel, data, cfg);

    // Mode 1: if a baseline is selected, compare
    if (cfg.mode === "sig_to_port") {
      lastPortScan = data;
      const baselineName = document.getElementById("psBaselineSelect").value;
      if (baselineName) {
        await runBaselineCompare(baselineName, data);
      }
    }
  } catch(e) {
    showError(panel, "Port scan error", e.message);
  } finally {
    document.getElementById("psRunBtn").disabled = false;
  }
}

function runPortScanStreaming(cfg) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/port-scan-stream", true);
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
        else if (xhr.status === 0) reject(new Error("Connection closed"));
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
        <div class="card-sub">signature field: <code>${esc(data.signature_field)}</code>, port field: <code>${esc(data.port_field)}</code></div>
      </div>
    </div>
    <div class="stats">
      <div class="stat"><div class="stat-val">${fmt(data.total_signatures_seen || 0)}</div><div class="stat-lbl">Signatures seen</div></div>
      <div class="stat"><div class="stat-val">${fmt(data.eligible_signatures || 0)}</div><div class="stat-lbl">Scanned</div></div>
      <div class="stat"><div class="stat-val" style="color:#dc2626">${fmt(flagged.length)}</div><div class="stat-lbl">Flagged</div></div>
      <div class="stat"><div class="stat-val">${fmt(clean.length)}</div><div class="stat-lbl">Clean</div></div>
    </div>`;

  if (data.truncated) {
    html += `<div class="err-card" style="margin-bottom:10px;border-left:3px solid #f59e0b;background:var(--anom-bg);color:var(--anom-fg);border-color:transparent">
      &#x26A0; Only the top ${data.eligible_signatures} signatures (by volume) were scanned. Raise "max signatures" or "min sessions" to adjust.</div>`;
  }
  html += `</div>`;

  if (flagged.length) {
    html += renderSigTable(flagged, "Flagged signatures", true, data.port_field);
  }
  if (clean.length) {
    html += renderSigTable(clean, `Clean signatures (${clean.length})`, false, data.port_field, true);
  }
  if (errored.length) {
    html += `<div class="card"><div class="card-title" style="color:#dc2626">Errors</div>`;
    html += errored.map(e => `<div style="font-size:.78rem;color:var(--text-3);margin-top:6px"><code>${esc(e.signature)}</code>: ${esc(e.error)}</div>`).join("");
    html += `</div>`;
  }
  return html;
}

function renderSigTable(sigs, title, isFlagged, portField, collapsed) {
  const openAttr = collapsed ? "" : " open";
  const rowsHtml = sigs.map(s => {
    const domBadge = `<span class="port-chip dom">${esc(s.dominant_port)}</span> <span style="color:var(--text-4);font-size:.72rem">${(s.dominant_share*100).toFixed(1)}%</span>`;
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

    return `<tr class="${isFlagged ? "" : "clean"}">
      <td class="val" style="max-width:320px">${esc(s.signature)}</td>
      <td class="num r">${fmt(s.total)}</td>
      <td>${domBadge}</td>
      <td class="num r">${fmt(s.distinct_ports)}</td>
      <td class="num r" style="color:var(--text-3);font-size:.72rem" title="Shannon entropy over the port distribution; low = concentrated on one port, high = spread out">${s.entropy.toFixed(2)}</td>
      <td style="min-width:260px">${outlierCells}</td>
    </tr>`;
  }).join("");

  return `<details class="card"${openAttr}>
    <summary class="card-title" style="cursor:pointer;list-style:revert;padding:0">${esc(title)}</summary>
    <div style="margin-top:12px">
      <table>
        <thead><tr>
          <th>Signature</th>
          <th class="r">Sessions</th>
          <th>Dominant port</th>
          <th class="r">Distinct ports</th>
          <th class="r" title="Shannon entropy">H</th>
          <th>Outlier ports</th>
        </tr></thead>
        <tbody>${rowsHtml}</tbody>
      </table>
    </div>
  </details>`;
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

    return `<tr class="${p.flagged?"":"clean"}">
      <td class="num" style="font-weight:700">${esc(p.port)}</td>
      <td class="num r">${fmt(p.total || 0)}</td>
      <td style="font-size:.73rem">${p.expected.length ? p.expected.map(x=>`<code>${esc(x)}</code>`).join(" ") : '<span style="color:var(--text-4)">no expectation set</span>'}</td>
      <td style="max-width:300px">${matched}</td>
      <td style="max-width:360px">${unexp}</td>
    </tr>`;
  }).join("");

  if (flagged.length) {
    html += `<details class="card" open>
      <summary class="card-title" style="cursor:pointer;list-style:revert;padding:0">Flagged ports</summary>
      <div style="margin-top:12px"><table>
        <thead><tr><th>Port</th><th class="r">Sessions</th><th>Expected</th><th>Matching</th><th>Unexpected</th></tr></thead>
        <tbody>${buildRows(flagged)}</tbody>
      </table></div>
    </details>`;
  }
  if (clean.length) {
    html += `<details class="card">
      <summary class="card-title" style="cursor:pointer;list-style:revert;padding:0">Clean ports (${clean.length})</summary>
      <div style="margin-top:12px"><table>
        <thead><tr><th>Port</th><th class="r">Sessions</th><th>Expected</th><th>Matching</th><th>Unexpected</th></tr></thead>
        <tbody>${buildRows(clean)}</tbody>
      </table></div>
    </details>`;
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
  const clean   = hosts.filter(h => !h.flagged && !h.error);

  let html = `<div class="card">
    <div class="card-top">
      <div>
        <div class="card-title">Host port diversity (mode 3)</div>
        <div class="card-sub">host field: <code>${esc(data.host_field)}</code>, port field: <code>${esc(data.port_field)}</code>${data.signature_field ? `, pinned signature: <code>${esc(data.signature_field)}</code>` : ""}</div>
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
    rowData.push({field: data.host_field, value: h.host, count: h.total, bucket: "ps_host"});
    const topPorts = (h.top_ports || []).slice(0, 8).map(tp =>
      `<span class="port-chip"><span class="port-val">${esc(tp.port)}</span> <span class="port-count">${tp.count}</span></span>`
    ).join("");
    return `<tr class="${h.flagged?"":"clean"}">
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

  if (flagged.length) {
    html += `<details class="card" open>
      <summary class="card-title" style="cursor:pointer;list-style:revert;padding:0">Flagged hosts</summary>
      <div style="margin-top:12px"><table>
        <thead><tr><th>Host</th><th class="r">Sessions</th><th class="r">Distinct ports</th><th class="r">Ratio</th><th class="r" title="Shannon entropy">H</th><th>Top ports</th><th></th></tr></thead>
        <tbody>${buildRows(flagged)}</tbody>
      </table></div>
    </details>`;
  }
  if (clean.length) {
    html += `<details class="card">
      <summary class="card-title" style="cursor:pointer;list-style:revert;padding:0">Clean hosts (${clean.length})</summary>
      <div style="margin-top:12px"><table>
        <thead><tr><th>Host</th><th class="r">Sessions</th><th class="r">Distinct ports</th><th class="r">Ratio</th><th class="r">H</th><th>Top ports</th><th></th></tr></thead>
        <tbody>${buildRows(clean)}</tbody>
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
  if (!lastPortScan) { toast("No scan to export", "err"); return; }
  const ts = new Date().toISOString().slice(0, 19).replace(/[-:T]/g, "").slice(0, 15);
  const blob = new Blob([JSON.stringify(lastPortScan, null, 2)], {type: "application/json"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `arkime_port_scan_${ts}.json`;
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
        elif self.path == "/api/baselines":
            try:    self._json(200, do_baseline_list())
            except Exception as e: self._json(200, {"error": str(e)})
        elif self.path == "/api/port-expectations-default":
            self._json(200, {"expectations": PORT_EXPECTATIONS_DEFAULT})
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

    # ---- SSE streaming analyze ----

    def _handle_analyze_stream(self):
        length = int(self.headers.get("Content-Length", 0))
        raw    = self.rfile.read(length) if length else b""
        try:
            cfg = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            self._json(400, {"error": "Invalid JSON body"})
            return

        # SSE headers
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

        try:
            # Check cache first — still emit a single progress event then result
            cached = CACHE.get("analyze", cfg)
            if cached is not None:
                total = len(cfg.get("fields") or [])
                send_event("progress", {"done": total, "total": total, "field": None, "cached": True})
                send_event("result", {"results": cached, "cached": True})
                return

            fields = [f for f in (cfg.get("fields") or []) if f.strip()]
            if not fields:
                send_event("result", {"results": []})
                return

            total = len(fields)

            # Shared progress state; worker thread emits events from the main thread
            # via a queue is overkill here — we'll use a lock + inline emit since
            # the HTTP response is single-threaded per request.
            import queue
            q = queue.Queue()

            def progress(done, t, field):
                q.put(("progress", done, t, field))

            def worker():
                try:
                    results = do_analyze(cfg, progress=progress)
                    q.put(("done", results))
                except Exception as e:
                    q.put(("error", str(e)))

            t = threading.Thread(target=worker, daemon=True)
            t.start()

            # Heartbeat / progress relay
            while True:
                try:
                    item = q.get(timeout=15)
                except queue.Empty:
                    # Heartbeat comment to keep the connection alive
                    try:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    continue

                kind = item[0]
                if kind == "progress":
                    _, done, tot, field = item
                    send_event("progress", {"done": done, "total": tot, "field": field})
                elif kind == "done":
                    results = item[1]
                    CACHE.put("analyze", cfg, results)
                    send_event("result", {"results": results})
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

    # ---- SSE streaming port scan ----

    def _handle_port_scan_stream_body(self, cfg):
        """SSE-stream a port anomaly scan with per-signature progress."""
        mode = cfg.get("mode", "sig_to_port")

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

        try:
            import queue
            q = queue.Queue()

            def progress(done, total, item):
                q.put(("progress", done, total, item))

            def worker():
                try:
                    if mode == "sig_to_port":
                        res = do_port_scan_sig_to_port(cfg, progress=progress)
                    elif mode == "port_to_sig":
                        res = do_port_scan_port_to_sig(cfg, progress=progress)
                    elif mode == "host_diversity":
                        res = do_port_scan_host_diversity(cfg, progress=progress)
                    else:
                        q.put(("error", f"Unknown mode: {mode}"))
                        return
                    q.put(("done", res))
                except Exception as e:
                    q.put(("error", str(e)))

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
                    send_event("progress", {"done": done, "total": total, "item": cur})
                elif kind == "done":
                    send_event("result", item[1])
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

def main():
    global DEV_MODE, HTML_PATH_OVERRIDE
    p = argparse.ArgumentParser(description="Arkime Analyzer — local web UI")
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
    print("  Arkime Analyzer v3")
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
