#!/usr/bin/env python3
"""Backend-only tests for port anomaly scan modes + baselines."""
import http.server
import threading
import json
import time
import urllib.request
import importlib.util
import os

# ───── Enhanced mock: returns port distributions keyed on signature ─────
# The scenario we're simulating:
#   - JA3 hash "normal-browser-ja3"  lives almost entirely on port 443
#     with two suspicious sessions on port 8443 and one on 31337
#   - JA3 hash "scanner-ja3" hits ports 1-1000 (port scan shape)
#   - JA3 hash "evil-c2" appears ONLY on port 8443 (a weird port for TLS)
#   - Port 53 has mostly dns + a rogue signature "not-dns" (protocol mismatch)
#   - Host 10.0.0.99 hits 200 different dst ports with same JA3 (scan shape)

class Scenario(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a, **kw): pass

    def do_GET(self):
        path = self.path.split("?")[0]
        qs_raw = self.path.split("?", 1)[1] if "?" in self.path else ""
        import urllib.parse as up
        qs = dict(up.parse_qsl(qs_raw))

        if path == "/api/fields":
            self._json([]); return

        if path in ("/api/unique", "/unique.txt"):
            exp = qs.get("exp", "")
            expression = qs.get("expression", "")
            body = self._unique(exp, expression)
            self._raw(body, "text/plain"); return

        self.send_response(404); self.end_headers()

    def _unique(self, exp, expression):
        # Dispatch on what the query wants

        # Signature field list: unique tls.ja3 values
        if exp == "tls.ja3" and "tls.ja3" not in expression:
            # Top-level list of signatures
            return "normal-browser-ja3,5000\nscanner-ja3,300\nevil-c2,25\nrare-sig,2\n"

        # Port distribution for a specific JA3
        if exp == "port.dst" and 'tls.ja3 == "normal-browser-ja3"' in expression:
            # Dominated by 443, tiny outliers
            return "443,4995\n8443,3\n31337,1\n22222,1\n"
        if exp == "port.dst" and 'tls.ja3 == "scanner-ja3"' in expression:
            # Spread across many ports (scan shape)
            return "\n".join(f"{p},{1 + (p % 4)}" for p in range(1, 201))
        if exp == "port.dst" and 'tls.ja3 == "evil-c2"' in expression:
            return "8443,25\n"
        if exp == "port.dst" and 'tls.ja3 == "rare-sig"' in expression:
            return "443,2\n"

        # Mode 2: on a given port, distribution of signatures (protocols)
        if exp == "protocols" and "port.dst == 53" in expression:
            # dns is expected; "not-dns" is the anomaly
            return "dns,10000\nnot-dns,42\n"
        if exp == "protocols" and "port.dst == 443" in expression:
            return "tls,http,45000\ntls,30000\nhttp,100\n"  # all TLS-ish
        if exp == "protocols" and "port.dst == 80" in expression:
            return "http,tcp,20000\nhttp,500\ntls,5\n"  # tiny unexpected tls on 80
        if exp == "protocols" and "port.dst == " in expression:
            # Default for any other port in the default expectations
            return "tcp,50\n"

        # Mode 3: host list
        if exp == "ip.src" and "ip.src" not in expression:
            return ("10.0.0.99,400\n"   # scanner host
                    "10.0.0.5,1000\n"    # normal
                    "10.0.0.6,50\n")
        # port distribution for a specific host
        if exp == "port.dst" and 'ip.src == "10.0.0.99"' in expression:
            # Hits 200 different ports
            return "\n".join(f"{p},{1 + (p % 3)}" for p in range(1, 201))
        if exp == "port.dst" and 'ip.src == "10.0.0.5"' in expression:
            return "443,950\n80,50\n"  # normal
        if exp == "port.dst" and 'ip.src == "10.0.0.6"' in expression:
            return "443,45\n8443,5\n"

        # Mode 3: "distinct hosts using this signature" (for ip.src under a pin)
        if exp == "ip.src" and 'tls.ja3 == "evil-c2"' in expression:
            return "10.0.0.66,25\n"

        return ""  # no data

    def _json(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def _raw(self, s, ct):
        b = s.encode()
        self.send_response(200); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)


class TS(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


mock = TS(("127.0.0.1", 8770), Scenario)
threading.Thread(target=mock.serve_forever, daemon=True).start()

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("app", os.path.join(here, "arkime_web_v3.py"))
app = importlib.util.module_from_spec(spec); spec.loader.exec_module(app)

# Clean out any test baselines from previous runs
if os.path.exists(app.SETTINGS_FILE):
    try:
        s = json.load(open(app.SETTINGS_FILE))
        s.pop("baselines", None)
        open(app.SETTINGS_FILE, "w").write(json.dumps(s))
    except Exception:
        pass

app_srv = app.ThreadingHTTPServer(("127.0.0.1", 8091), app.Handler)
threading.Thread(target=app_srv.serve_forever, daemon=True).start()
time.sleep(0.3)

CSRF = app.CSRF_TOKEN

def post(path, body):
    req = urllib.request.Request(
        f"http://127.0.0.1:8091{path}", data=json.dumps(body).encode(),
        headers={"Content-Type":"application/json","X-CSRF-Token":CSRF},
    )
    return json.loads(urllib.request.urlopen(req, timeout=15).read())

def get(path):
    return json.loads(urllib.request.urlopen(f"http://127.0.0.1:8091{path}", timeout=5).read())

# Common cfg
BASE_CFG = {
    "url": "http://127.0.0.1:8770",
    "auth_type": "none",
    "timeout_secs": 10,
    "max_workers": 6,
    "start_date": "2025-01-01 00:00:00",
    "end_date":   "2025-01-02 00:00:00",
    "allowlist": {},
    "tags": [], "tags_match": "any", "expression": "",
}

print("\n=== Test 1: Mode 1 (sig → port) ===")
cfg = dict(BASE_CFG, mode="sig_to_port",
           signature_field="tls.ja3", port_field="port.dst",
           min_sessions=10, max_sigs=100, dominance=0.9, outlier_max=3)
r = post("/api/port-scan", cfg)
assert "signatures" in r, r
sigs = {s["signature"]: s for s in r["signatures"]}
# normal-browser-ja3 should be flagged (99.9% on 443, outliers on 8443/31337/22222)
n = sigs["normal-browser-ja3"]
assert n["flagged"] is True, n
assert n["dominant_port"] == "443"
assert n["dominant_share"] >= 0.99
assert len(n["outliers"]) >= 2
print(f"  ✓ normal-browser-ja3 flagged: dom={n['dominant_port']}@{n['dominant_share']*100:.1f}%, {len(n['outliers'])} outliers")
# scanner-ja3: spread across many ports, dominance < threshold → NOT flagged
s = sigs["scanner-ja3"]
assert s["distinct_ports"] >= 100, s
assert s["dominant_share"] < 0.9
assert s["flagged"] is False
print(f"  ✓ scanner-ja3 not flagged (port-spread): {s['distinct_ports']} distinct ports, dom share {s['dominant_share']*100:.1f}%")
# evil-c2: only on 8443 → 100% dominance, no outliers → NOT flagged under this mode
e = sigs["evil-c2"]
assert e["dominant_port"] == "8443"
assert e["flagged"] is False  # no outlier ports
print(f"  ✓ evil-c2 single-port: dom={e['dominant_port']}@100% (not flagged in mode 1, as expected)")
# rare-sig: total=2 < min_sessions=10 → not in results
assert "rare-sig" not in sigs
print(f"  ✓ rare-sig (below min_sessions floor) correctly excluded")

print("\n=== Test 2: Mode 2 (port → sig) ===")
cfg2 = dict(BASE_CFG, mode="port_to_sig",
            signature_field="protocols", port_field="port.dst",
            ports_to_check=["53", "443", "80"], max_other_sigs=10)
r = post("/api/port-scan", cfg2)
ports = {str(p["port"]): p for p in r["ports"]}
p53 = ports["53"]
assert p53["flagged"] is True, p53
assert p53["unexpected_total"] == 42, p53
print(f"  ✓ port 53 flagged: {p53['unexpected_total']} unexpected sessions (not-dns)")
p443 = ports["443"]
assert p443["flagged"] is False, p443  # all signatures contain tls or http
print(f"  ✓ port 443 not flagged (all TLS/HTTP)")
p80 = ports["80"]
# Port 80 has a tiny bit of "tls" which isn't in expected [http, tcp] → flagged
assert p80["flagged"] is True, p80
print(f"  ✓ port 80 flagged: unexpected={p80['unexpected_total']} (small amount of tls)")

print("\n=== Test 3: Mode 3 (host diversity) ===")
cfg3 = dict(BASE_CFG, mode="host_diversity",
            port_field="port.dst", host_field="ip.src",
            min_sessions=10, min_distinct_ports=50,
            port_ratio_threshold=0.3, max_hosts=50)
r = post("/api/port-scan", cfg3)
hosts = {h["host"]: h for h in r["hosts"]}
h99 = hosts["10.0.0.99"]
assert h99["flagged"] is True, h99
assert h99["distinct_ports"] >= 100
print(f"  ✓ 10.0.0.99 flagged: {h99['distinct_ports']} distinct ports, ratio={h99['ratio']}")
h5 = hosts.get("10.0.0.5")
assert h5["flagged"] is False
print(f"  ✓ 10.0.0.5 not flagged: only {h5['distinct_ports']} distinct ports")

print("\n=== Test 4: Baseline save ===")
# Use the mode 1 scan result we got in test 1
saved = post("/api/baseline/save", {
    "name": "test-clean-week",
    "description": "synthetic clean baseline for testing",
    "scan_result": r if False else json.loads(json.dumps({  # use the mode-1 result
        **{"mode":"sig_to_port","signature_field":"tls.ja3","port_field":"port.dst"},
        "signatures": [
            {"signature":"normal-browser-ja3","total":5000,
             "ports":[{"port":"443","count":4995},{"port":"8443","count":3},{"port":"31337","count":1},{"port":"22222","count":1}],
             "dominant_port":"443","dominant_share":0.999,"distinct_ports":4,"flagged":True,"outliers":[]},
            {"signature":"evil-c2","total":25,
             "ports":[{"port":"8443","count":25}],
             "dominant_port":"8443","dominant_share":1.0,"distinct_ports":1,"flagged":False,"outliers":[]}
        ],
        "thresholds": {"min_sessions": 10}
    })),
    "built_from": {"start": BASE_CFG["start_date"], "end": BASE_CFG["end_date"]},
})
assert saved.get("ok"), saved
assert saved["signature_count"] == 2
print(f"  ✓ Baseline saved: {saved['name']}, {saved['signature_count']} signatures")

print("\n=== Test 5: Baseline list ===")
bl = get("/api/baselines")
names = [b["name"] for b in bl["baselines"]]
assert "test-clean-week" in names
print(f"  ✓ Baseline listed: {names}")

print("\n=== Test 6: Baseline compare — detect new port on known signature ===")
# Build a fresh scan where normal-browser-ja3 has gained a new port 12345
new_scan = {
    "mode":"sig_to_port","signature_field":"tls.ja3","port_field":"port.dst",
    "signatures": [
        {"signature":"normal-browser-ja3","total":5500,
         "ports":[{"port":"443","count":5000},{"port":"8443","count":3},{"port":"31337","count":1},{"port":"22222","count":1},{"port":"12345","count":500}],
         "dominant_port":"443","dominant_share":0.909,"distinct_ports":5,"flagged":True,"outliers":[]},
        {"signature":"new-sig-never-seen","total":100,
         "ports":[{"port":"443","count":100}],
         "dominant_port":"443","dominant_share":1.0,"distinct_ports":1,"flagged":False,"outliers":[]},
        {"signature":"evil-c2","total":25,
         "ports":[{"port":"8443","count":25}],
         "dominant_port":"8443","dominant_share":1.0,"distinct_ports":1,"flagged":False,"outliers":[]},
    ],
    "thresholds": {"min_sessions": 10}
}
cmp_res = post("/api/baseline/compare", {"name": "test-clean-week", "scan_result": new_scan})
diffs = cmp_res["diffs"]
kinds = [d["kind"] for d in diffs]
sigs_diffed = {d["signature"]: d for d in diffs}
assert "new-sig-never-seen" in sigs_diffed
assert sigs_diffed["new-sig-never-seen"]["kind"] == "new_signature"
print(f"  ✓ Detected new signature: new-sig-never-seen")
assert "normal-browser-ja3" in sigs_diffed
assert sigs_diffed["normal-browser-ja3"]["kind"] == "known_signature_new_ports"
assert "12345" in sigs_diffed["normal-browser-ja3"]["new_ports"]
print(f"  ✓ Detected new port on known signature: normal-browser-ja3 gained {sigs_diffed['normal-browser-ja3']['new_ports']}")
# evil-c2 unchanged → should NOT be in diffs
assert "evil-c2" not in sigs_diffed
print(f"  ✓ Unchanged signature (evil-c2) correctly excluded from diffs")

print("\n=== Test 7: Baseline compare — dominance shift ===")
shift_scan = {
    "mode":"sig_to_port","signature_field":"tls.ja3","port_field":"port.dst",
    "signatures": [
        {"signature":"normal-browser-ja3","total":5000,
         "ports":[{"port":"443","count":100},{"port":"8443","count":4800},{"port":"31337","count":50},{"port":"22222","count":50}],
         "dominant_port":"8443","dominant_share":0.96,"distinct_ports":4,"flagged":False,"outliers":[]},
    ],
    "thresholds": {"min_sessions": 10}
}
cmp2 = post("/api/baseline/compare", {"name": "test-clean-week", "scan_result": shift_scan})
d = {x["signature"]: x for x in cmp2["diffs"]}
# No new ports, but dominance shifted from 443 → 8443
nb = d["normal-browser-ja3"]
assert nb["shifted_dominant"] is not None
assert nb["shifted_dominant"]["baseline"] == "443"
assert nb["shifted_dominant"]["scan"] == "8443"
print(f"  ✓ Dominance shift detected: 443 → 8443")

print("\n=== Test 8: Baseline mismatch error ===")
bad = dict(new_scan); bad["signature_field"] = "http.useragent"
try:
    post("/api/baseline/compare", {"name": "test-clean-week", "scan_result": bad})
    assert False, "should have errored"
except Exception:
    pass
# The endpoint swallows into {error: ...} — let's check that
res = post("/api/baseline/compare", {"name": "test-clean-week", "scan_result": bad})
assert "error" in res, res
assert "field mismatch" in res["error"].lower(), res
print(f"  ✓ Mismatch rejected: {res['error']}")

print("\n=== Test 9: Baseline delete ===")
post("/api/baseline/delete", {"name": "test-clean-week"})
bl = get("/api/baselines")
assert "test-clean-week" not in [b["name"] for b in bl["baselines"]]
print(f"  ✓ Baseline deleted")

print("\n=== Test 10: Port expectations endpoint ===")
pe = get("/api/port-expectations-default")
assert "53" in pe["expectations"]
assert "dns" in pe["expectations"]["53"]
print(f"  ✓ Default expectations returned ({len(pe['expectations'])} ports)")

print("\n=== Test 11: port_share_stats helper ===")
dom, share, entropy, total = app._port_share_stats({"443": 999, "8443": 1})
assert dom == "443"
assert share == 0.999
assert entropy > 0.0 and entropy < 0.5  # very skewed → low entropy
assert total == 1000
print(f"  ✓ Skewed: dom={dom}, share={share}, entropy={entropy}")
dom, share, entropy, total = app._port_share_stats({"a":1,"b":1,"c":1,"d":1})
assert abs(entropy - 2.0) < 0.01  # 4 equal buckets → 2 bits
print(f"  ✓ Uniform 4-way: entropy={entropy} (expected 2.0)")

print("\n🎉 All port anomaly scan tests passed!")
