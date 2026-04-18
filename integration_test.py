#!/usr/bin/env python3
"""Integration test: mock Arkime + actual app, all in one process via threads."""
import http.server
import http.client
import json
import threading
import time
import urllib.request
import importlib.util
import sys
import os
import re

# ────── Mock Arkime ──────
class MockArkime(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a, **kw): pass
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/api/fields":
            self._json([{"name":"http.uri"}])
            return
        if path in ("/api/unique", "/unique.txt"):
            exp = ""
            if "exp=" in self.path:
                exp = self.path.split("exp=")[1].split("&")[0]
            # Simulate slow queries so parallelization is observable
            time.sleep(0.4 if exp == "http.useragent" else 0.15)
            if exp == "port.dst":
                body = "443,1250\n80,890\n8080,23\n3389,1\n9999,1\n"
            elif exp == "http.useragent":
                body = "Mozilla/5.0,450\ncurl/7.68.0,12\nevil-bot/1.0,2\n"
            elif exp == "http.uri":
                body = "/index.html,300\n/api/login,150\n/weird/path,1\n/other,2\n"
            elif exp == "port.src":
                body = "54321,100\n54322,3\n54323,1\n"
            elif exp == "ip.src":
                body = "10.0.0.5,30\n10.0.0.6,8\n192.168.1.100,1\n"
            else:
                body = "sample_a,10\nsample_b,3\nsample_c,1\n"
            self._raw(body, "text/plain")
            return
        if path in ("/api/sessions", "/sessions.json"):
            now = int(time.time() * 1000)
            sessions = [{
                "id": f"sess{i}",
                "ip.src": "10.0.0.5",
                "ip.dst": "1.2.3.4",
                "port.src": 54321 + i,
                "port.dst": 443,
                "firstPacket": now - 60000 - i*1000,
                "lastPacket":  now - 30000 - i*1000,
                "totBytes": 1500 * (i+1),
                "network.packets": 10 + i,
                "protocols": ["tcp", "tls"],
                "node": "node-01",
                "tags": ["seen", "outbound"],
            } for i in range(3)]
            self._json({"data": sessions, "recordsFiltered": 3})
            return
        self.send_response(404); self.end_headers()

    def _json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def _raw(self, s, ct):
        body = s.encode()
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

class ThreadedServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

# Start mock Arkime
mock = ThreadedServer(("127.0.0.1", 8766), MockArkime)
threading.Thread(target=mock.serve_forever, daemon=True).start()
print("[mock] listening on :8766")

# Load the app module (without running main)
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("appmod", os.path.join(here, "arkime_web_v3.py"))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

# Start the app server ourselves
app_srv = app.ThreadingHTTPServer(("127.0.0.1", 8092), app.Handler)
threading.Thread(target=app_srv.serve_forever, daemon=True).start()
print("[app]  listening on :8092")
time.sleep(0.8)

# ────── Tests ──────

CSRF = app.CSRF_TOKEN

def post_json(path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:8092{path}", data=data,
        headers={"Content-Type": "application/json", "X-CSRF-Token": CSRF},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

def get_text(path):
    with urllib.request.urlopen(f"http://127.0.0.1:8092{path}", timeout=5) as r:
        return r.read().decode()

# 1. Home page
print("\n=== Test 1: Home page ===")
page = get_text("/")
assert "Arkime Analyzer" in page
assert f'window.__CSRF = "{CSRF}"' in page
print(f"  ✓ Home page renders, CSRF injected ({len(page)} bytes)")

# 2. CSRF rejection
print("\n=== Test 2: CSRF rejection ===")
try:
    req = urllib.request.Request(
        "http://127.0.0.1:8092/api/analyze", data=b'{}',
        headers={"Content-Type": "application/json"},  # no token
    )
    urllib.request.urlopen(req, timeout=5)
    print("  ✗ expected 403 without token")
except urllib.error.HTTPError as e:
    assert e.code == 403, f"expected 403 got {e.code}"
    print(f"  ✓ 403 without CSRF token")

# 3. Connection test
print("\n=== Test 3: /api/test ===")
r = post_json("/api/test", {"url": "http://127.0.0.1:8766", "auth_type": "none", "timeout_secs": 5})
assert r["ok"] is True, r
print(f"  ✓ Connection test: {r['message']}")

# 4. Non-streaming analyze with parallelization benchmark
print("\n=== Test 4: /api/analyze (parallel) ===")
cfg = {
    "url": "http://127.0.0.1:8766",
    "auth_type": "none",
    "timeout_secs": 10,
    "max_workers": 6,
    "start_date": "2025-01-01 00:00:00",
    "end_date":   "2025-01-02 00:00:00",
    "fields": ["port.dst", "port.src", "http.useragent", "http.uri"],
    "top_n": 10, "rare_threshold": 3, "max_rare_display": 20,
    "allowlist": {"port.dst": ["443", "80"]},
}
t0 = time.time()
r = post_json("/api/analyze", cfg)
elapsed = time.time() - t0
assert "results" in r, r
assert len(r["results"]) == 4
print(f"  ✓ 4 fields analyzed in {elapsed:.2f}s (serial would be ~0.85s, parallel ~0.4s)")
for fr in r["results"]:
    print(f"    - {fr['field']}: unique={fr.get('total_unique')}, top={len(fr.get('top_n',[]))}, rare={len(fr.get('rare',[]))}, skipped={fr.get('skipped')}")

# Verify allowlist worked (port.dst should have 443 and 80 filtered)
pd = next(f for f in r["results"] if f["field"] == "port.dst")
vals = [t["value"] for t in pd["top_n"]]
assert "443" not in vals and "80" not in vals, f"allowlist failed: {vals}"
assert pd["skipped"] == 2
print(f"  ✓ Allowlist: dropped 443 and 80 from port.dst")

# 5. Cache hit
print("\n=== Test 5: cache hit ===")
t0 = time.time()
r2 = post_json("/api/analyze", cfg)
elapsed2 = time.time() - t0
assert r2.get("cached") is True, r2
print(f"  ✓ Cache hit in {elapsed2*1000:.1f}ms (was {elapsed*1000:.1f}ms uncached)")

# 6. Correlate (single value)
print("\n=== Test 6: /api/correlate single ===")
ccfg = dict(cfg, pivot_field="http.useragent", pivot_value="curl/7.68.0", target_field="ip.dst", top_n=20)
r = post_json("/api/correlate", ccfg)
assert "results" in r, r
assert "expression" in r
print(f"  ✓ Correlate returned {len(r['results'])} rows, expr: {r['expression']}")

# 7. Correlate (bulk values)
print("\n=== Test 7: /api/correlate bulk ===")
ccfg2 = dict(cfg, pivot_field="http.useragent", pivot_values=["curl/7.68.0", "evil-bot/1.0"], pivot_match="any", target_field="ip.dst", top_n=20)
r = post_json("/api/correlate", ccfg2)
assert "||" in r["expression"], r["expression"]
print(f"  ✓ Bulk correlate expr: {r['expression']}")

# 8. Sessions with pivot
print("\n=== Test 8: /api/sessions bulk pivot ===")
scfg = dict(cfg, pivot_field="http.useragent", pivot_values=["curl/7.68.0", "evil-bot/1.0"], pivot_match="any")
r = post_json("/api/sessions", scfg)
assert r["total"] == 3
print(f"  ✓ Sessions returned {r['total']} rows, expr: {r['expression']}")

# 9. Anomaly hints
print("\n=== Test 9: /api/anomaly-hints ===")
acfg = dict(cfg, pairs=[{"field":"http.uri", "value":"/weird/path"}, {"field":"port.dst", "value":"3389"}])
r = post_json("/api/anomaly-hints", acfg)
assert "hints" in r
assert len(r["hints"]) == 2
for h in r["hints"]:
    print(f"    - {h['field']}={h['value']}: src_count={h.get('src_count')} top_share={h.get('top_share')} top_src={h.get('top_src')}")
print(f"  ✓ Anomaly hints returned")

# 10. Presets round-trip
print("\n=== Test 10: presets round-trip ===")
# Save
pr = post_json("/api/preset/save", {"name": "test-preset", "config": {"url": "http://x", "password": "SECRET"}})
assert pr.get("ok"), pr
# List
lst = urllib.request.urlopen("http://127.0.0.1:8092/api/presets", timeout=3).read()
lst = json.loads(lst)
assert "test-preset" in lst["names"]
print(f"  ✓ Saved and listed preset: {lst['names']}")
# Load — password must NOT be present
ld = post_json("/api/preset/load", {"name": "test-preset"})
assert "password" not in ld["config"], f"password leaked: {ld}"
assert ld["config"]["url"] == "http://x"
print(f"  ✓ Loaded preset, password stripped")
# Delete
post_json("/api/preset/delete", {"name": "test-preset"})
lst = json.loads(urllib.request.urlopen("http://127.0.0.1:8092/api/presets", timeout=3).read())
assert "test-preset" not in lst["names"]
print(f"  ✓ Deleted preset")

# 11. Settings round-trip
print("\n=== Test 11: settings round-trip ===")
post_json("/api/settings", {"url": "http://stored", "password": "NEVERSAVE", "top_n": 42})
s = json.loads(urllib.request.urlopen("http://127.0.0.1:8092/api/settings", timeout=3).read())
assert "password" not in s, f"password leaked: {s}"
assert s["url"] == "http://stored"
assert s["top_n"] == 42
print(f"  ✓ Settings saved without password, read back")

# 12. Expression escaping
print("\n=== Test 12: expression escaping ===")
# Tag with quote shouldn't break the expression
expr = app._build_expr({"tags": ['foo"bar', "baz\\qux"], "tags_match": "any"})
assert '\\"' in expr, expr
assert '\\\\' in expr, expr
print(f"  ✓ Escaped tag expression: {expr}")

# 13. SSE streaming analyze (use distinct config to miss cache)
print("\n=== Test 13: /api/analyze-stream (SSE) ===")
stream_cfg = dict(cfg, expression="port.dst != 22")  # different expr => different cache key
conn = http.client.HTTPConnection("127.0.0.1", 8092, timeout=15)
conn.request("POST", "/api/analyze-stream",
             body=json.dumps(stream_cfg),
             headers={"Content-Type": "application/json", "X-CSRF-Token": CSRF})
resp = conn.getresponse()
assert resp.status == 200
assert "text/event-stream" in resp.getheader("Content-Type", ""), resp.getheader("Content-Type")
events = []
buf = b""
deadline = time.time() + 10
while time.time() < deadline:
    chunk = resp.read(4096)
    if not chunk:
        break
    buf += chunk
    while b"\n\n" in buf:
        raw, buf = buf.split(b"\n\n", 1)
        if not raw.strip(): continue
        ev = {"type": "message"}
        for ln in raw.decode().split("\n"):
            if ln.startswith("event:"): ev["type"] = ln[6:].strip()
            elif ln.startswith("data:"): ev["data"] = ln[5:].strip()
            elif ln.startswith(":"): ev["type"] = "heartbeat"
        events.append(ev)
        if ev["type"] == "result":
            deadline = 0  # stop
            break
progress = [e for e in events if e["type"] == "progress"]
results  = [e for e in events if e["type"] == "result"]
print(f"  ✓ Got {len(progress)} progress events and {len(results)} result event")
assert len(progress) >= 2, f"expected multiple progress events, got {len(progress)}"
assert len(results) == 1
final = json.loads(results[0]["data"])
assert "results" in final
print(f"  ✓ Final result has {len(final['results'])} fields")
conn.close()

# 14. Invalid date
print("\n=== Test 14: error handling (bad date) ===")
bad = dict(cfg, start_date="not-a-date")
r = post_json("/api/analyze", bad)
assert "error" in r, r
print(f"  ✓ Bad date returned error: {r['error'][:80]}")

# 15. Basic auth now always includes colon
print("\n=== Test 15: basic auth encoding ===")
import base64
h = app._auth_header({"auth_type": "basic", "username": "user", "password": ""})
decoded = base64.b64decode(h.split(" ", 1)[1]).decode()
assert decoded == "user:", f"expected 'user:' got {decoded!r}"
print(f"  ✓ Basic auth with empty password encodes as 'user:'")

# Cleanup
print("\n=== Cleanup ===")
if os.path.exists(app.SETTINGS_FILE):
    os.remove(app.SETTINGS_FILE)
    print("  ✓ Removed test settings file")

print("\n🎉 All tests passed!")
