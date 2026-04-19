#!/usr/bin/env python3
"""
Tests for the merged port scan modes.

Mode 1: Protocol Anomaly (merges old modes 1, 2, 4)
Mode 2: Host Behavior (old mode 3)
"""
import sys
import json
import unittest
from unittest.mock import patch, MagicMock

# Import the module
import arkime_web as aw


class TestProtocolAnomalyMode(unittest.TestCase):
    """Test the merged Protocol Anomaly mode."""

    def test_function_exists(self):
        """The merged function should exist."""
        self.assertTrue(hasattr(aw, 'do_port_scan_protocol_anomaly'))

    def test_returns_correct_mode(self):
        """Result should have mode='protocol_anomaly'."""
        # Mock the network calls
        with patch.object(aw, '_fetch_unique') as mock_fetch:
            with patch.object(aw, '_time_params') as mock_time:
                with patch.object(aw, '_build_expr') as mock_expr:
                    mock_time.return_value = {"startTime": "0", "stopTime": "1"}
                    mock_expr.return_value = ""
                    mock_fetch.return_value = []  # No ports found

                    cfg = {
                        "arkime_url": "http://test",
                        "username": "test",
                        "password": "test",
                        "start_date": "2026-04-01",
                        "end_date": "2026-04-19",
                        "signature_field": "http.useragent",
                        "port_field": "port",
                    }
                    result = aw.do_port_scan_protocol_anomaly(cfg)

                    self.assertEqual(result["mode"], "protocol_anomaly")

    def test_returns_both_views(self):
        """Result should include both signature_view and port_view."""
        with patch.object(aw, '_fetch_unique') as mock_fetch:
            with patch.object(aw, '_time_params') as mock_time:
                with patch.object(aw, '_build_expr') as mock_expr:
                    mock_time.return_value = {"startTime": "0", "stopTime": "1"}
                    mock_expr.return_value = ""
                    mock_fetch.return_value = []

                    cfg = {
                        "arkime_url": "http://test",
                        "username": "test",
                        "password": "test",
                        "start_date": "2026-04-01",
                        "end_date": "2026-04-19",
                        "signature_field": "http.useragent",
                        "port_field": "port",
                    }
                    result = aw.do_port_scan_protocol_anomaly(cfg)

                    self.assertIn("signature_view", result)
                    self.assertIn("port_view", result)


class TestLegacyWrappers(unittest.TestCase):
    """Test that legacy mode wrappers still work."""

    def test_sig_to_port_wrapper_exists(self):
        """Legacy wrapper should exist."""
        self.assertTrue(hasattr(aw, 'do_port_scan_sig_to_port'))

    def test_port_to_sig_wrapper_exists(self):
        """Legacy wrapper should exist."""
        self.assertTrue(hasattr(aw, 'do_port_scan_port_to_sig'))

    def test_sig_to_port_returns_legacy_format(self):
        """Legacy wrapper should return old format."""
        with patch.object(aw, '_fetch_unique') as mock_fetch:
            with patch.object(aw, '_time_params') as mock_time:
                with patch.object(aw, '_build_expr') as mock_expr:
                    mock_time.return_value = {"startTime": "0", "stopTime": "1"}
                    mock_expr.return_value = ""
                    mock_fetch.return_value = []

                    cfg = {
                        "arkime_url": "http://test",
                        "username": "test",
                        "password": "test",
                        "start_date": "2026-04-01",
                        "end_date": "2026-04-19",
                        "signature_field": "http.useragent",
                        "port_field": "port",
                    }
                    result = aw.do_port_scan_sig_to_port(cfg)

                    # Should have old format keys
                    self.assertEqual(result["mode"], "sig_to_port")
                    self.assertIn("signatures", result)
                    self.assertIn("total_signatures_seen", result)


class TestHostBehaviorMode(unittest.TestCase):
    """Test the Host Behavior mode (unchanged from old mode 3)."""

    def test_function_exists(self):
        """Host diversity function should exist."""
        self.assertTrue(hasattr(aw, 'do_port_scan_host_diversity'))

    def test_returns_correct_mode(self):
        """Result should have mode='host_diversity'."""
        with patch.object(aw, '_fetch_unique') as mock_fetch:
            with patch.object(aw, '_time_params') as mock_time:
                with patch.object(aw, '_build_expr') as mock_expr:
                    mock_time.return_value = {"startTime": "0", "stopTime": "1"}
                    mock_expr.return_value = ""
                    mock_fetch.return_value = []

                    cfg = {
                        "arkime_url": "http://test",
                        "username": "test",
                        "password": "test",
                        "start_date": "2026-04-01",
                        "end_date": "2026-04-19",
                        "port_field": "port.dst",
                    }
                    result = aw.do_port_scan_host_diversity(cfg)

                    self.assertEqual(result["mode"], "host_diversity")


class TestBytePatternHelper(unittest.TestCase):
    """Test the byte pattern helper function."""

    def test_helper_exists(self):
        """Helper function should exist."""
        self.assertTrue(hasattr(aw, '_run_byte_patterns'))


class TestBaselineCompatibility(unittest.TestCase):
    """Test that baselines work with new format."""

    def test_baseline_data_extraction_new_format(self):
        """Should extract signature data from protocol_anomaly format."""
        scan_result = {
            "mode": "protocol_anomaly",
            "signature_view": {
                "signatures": [
                    {"signature": "test-sig", "ports": [{"port": 443, "count": 100}]}
                ]
            }
        }
        data = aw._sig_to_port_as_baseline_data(scan_result)
        self.assertIn("test-sig", data)
        self.assertEqual(data["test-sig"], {443: 100})

    def test_baseline_data_extraction_legacy_format(self):
        """Should extract signature data from legacy format."""
        scan_result = {
            "mode": "sig_to_port",
            "signatures": [
                {"signature": "legacy-sig", "ports": [{"port": 80, "count": 50}]}
            ]
        }
        data = aw._sig_to_port_as_baseline_data(scan_result)
        self.assertIn("legacy-sig", data)
        self.assertEqual(data["legacy-sig"], {80: 50})


if __name__ == "__main__":
    unittest.main()
