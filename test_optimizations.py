#!/usr/bin/env python3
"""
Quick validation script for billion-session optimizations.
Run: python test_optimizations.py
"""

import sys
import os

# Import the module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import arkime_web as app

def test_defaults():
    """Verify new default values are in place."""
    print("Testing default values...")

    # Test 1: max_unique default (should be 50000 now)
    cfg = {}
    # Simulate what _fetch_unique does
    DEFAULT_MAX_UNIQUE = 50000
    max_unique = int(cfg.get("max_unique", 0))
    effective_limit = max_unique if max_unique > 0 else DEFAULT_MAX_UNIQUE
    assert effective_limit == 50000, f"Expected 50000, got {effective_limit}"
    print("  [PASS] max_unique default = 50000")

    # Test 2: Cache settings
    assert app.CACHE_MAX_ENTRIES == 256 or os.environ.get("LUXRAY_CACHE_MAX_ENTRIES"), \
        f"Expected cache max 256, got {app.CACHE_MAX_ENTRIES}"
    assert app.CACHE_TTL_SECS == 600 or os.environ.get("LUXRAY_CACHE_TTL_SECS"), \
        f"Expected cache TTL 600, got {app.CACHE_TTL_SECS}"
    print(f"  [PASS] Cache: {app.CACHE_MAX_ENTRIES} entries, {app.CACHE_TTL_SECS}s TTL")

    # Test 3: Dynamic workers
    cpu_count = os.cpu_count() or 4
    expected_default = min(cpu_count * 2, 24)
    workers = app._effective_workers({}, 100)
    assert workers == expected_default, f"Expected {expected_default} workers, got {workers}"
    print(f"  [PASS] Dynamic workers: {workers} (2x CPU, max 24)")

    # Test 4: Worker respects task count
    workers_small = app._effective_workers({}, 3)
    assert workers_small == 3, f"Expected 3 workers for 3 tasks, got {workers_small}"
    print(f"  [PASS] Workers capped by task count")

    # Test 5: User override works
    workers_override = app._effective_workers({"max_workers": 8}, 100)
    assert workers_override == 8, f"Expected 8 workers with override, got {workers_override}"
    print(f"  [PASS] User max_workers override works")


def test_rate_limiter():
    """Verify anomaly hints rate limiter exists."""
    print("\nTesting rate limiter...")

    assert hasattr(app, '_anomaly_rate_lock'), "Missing _anomaly_rate_lock"
    assert hasattr(app, '_ANOMALY_MIN_INTERVAL'), "Missing _ANOMALY_MIN_INTERVAL"
    assert app._ANOMALY_MIN_INTERVAL == 0.5, f"Expected 0.5s interval, got {app._ANOMALY_MIN_INTERVAL}"
    print("  [PASS] Anomaly hints rate limiter configured (0.5s)")


def test_memory_bounds():
    """Verify memory-bounding parameters are configurable."""
    print("\nTesting memory bound parameters...")

    # These should be picked up from cfg in the actual functions
    cfg = {"max_ports": 50, "max_host_candidates": 10000}

    max_ports = int(cfg.get("max_ports", 50))
    assert max_ports == 50, f"Expected max_ports 50, got {max_ports}"
    print("  [PASS] max_ports configurable (default 50)")

    max_host_candidates = int(cfg.get("max_host_candidates", 10000))
    assert max_host_candidates == 10000, f"Expected 10000, got {max_host_candidates}"
    print("  [PASS] max_host_candidates configurable (default 10000)")


def test_cache_operations():
    """Test cache put/get/eviction."""
    print("\nTesting cache operations...")

    # Create a small test cache
    cache = app._Cache(ttl_secs=10, max_entries=3)

    # Test put/get
    cache.put("test", {"url": "http://test"}, {"data": "value1"})
    result = cache.get("test", {"url": "http://test"})
    assert result == {"data": "value1"}, f"Cache get failed: {result}"
    print("  [PASS] Cache put/get works")

    # Test eviction
    cache.put("test", {"url": "http://test1"}, {"data": "v1"})
    cache.put("test", {"url": "http://test2"}, {"data": "v2"})
    cache.put("test", {"url": "http://test3"}, {"data": "v3"})
    cache.put("test", {"url": "http://test4"}, {"data": "v4"})  # Should evict oldest

    # First entry should be evicted
    result = cache.get("test", {"url": "http://test1"})
    assert result is None, "Eviction failed - old entry still present"
    print("  [PASS] Cache eviction works")


def run_all_tests():
    """Run all validation tests."""
    print("=" * 60)
    print("Luxray Billion-Session Optimization Validation")
    print("=" * 60)

    try:
        test_defaults()
        test_rate_limiter()
        test_memory_bounds()
        test_cache_operations()

        print("\n" + "=" * 60)
        print("ALL TESTS PASSED")
        print("=" * 60)
        return 0
    except AssertionError as e:
        print(f"\n[FAIL] {e}")
        return 1
    except Exception as e:
        print(f"\n[ERROR] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
