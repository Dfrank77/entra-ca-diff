import json
import unittest
import sys
import os

# Adjust paths so the test runner can locate the 'src' directory natively
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from engine import CADiffEngine

class TestConditionalAccessDiffEngine(unittest.TestCase):
    
    def setUp(self):
        """Executed before every individual test run to establish baseline data."""
        self.old_path = "tests/test_samples/old_mfa_policy.json"
        self.new_path = "tests/test_samples/new_mfa_policy.json"
        
        with open(self.old_path, "r") as f:
            self.old_raw = json.load(f)
        with open(self.new_path, "r") as f:
            self.new_raw = json.load(f)

    def test_engine_catches_all_regressions(self):
        """Verify the engine flags the critical state downshift and universal exclusion leak."""
        alerts = CADiffEngine.evaluate(self.old_raw, self.new_raw)
        
        # We expect exactly 2 security violations to be surfaced by file #11
        self.assertEqual(len(alerts), 2)
        
        # Verify the explicit error strings match our engine's logical outputs
        self.assertTrue(any("STATE DOWNGRADE" in alert for alert in alerts))
        self.assertTrue(any("CRITICAL CONFIGURATION FAULT" in alert for alert in alerts))

    def test_engine_passes_identical_data(self):
        """Verify that comparing a policy against itself triggers zero security alerts."""
        alerts = CADiffEngine.evaluate(self.old_raw, self.old_raw)
        self.assertEqual(len(alerts), 0)

if __name__ == "__main__":
    unittest.main()
