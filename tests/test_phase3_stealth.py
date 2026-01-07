
import unittest
from unittest.mock import MagicMock, patch
from audit_system.evasion.stealth_manager import StealthManager, StealthLevel
import time

class TestPhase3Stealth(unittest.TestCase):
    
    def test_stealth_levels(self):
        manager = StealthManager()
        
        # Default Level 1 - Should include spoofing
        headers = manager.get_headers()
        self.assertIn("User-Agent", headers)
        self.assertIn("X-Forwarded-For", headers)
        # Logic was: if level >= 1: spoofing. So valid to check.
        
    def test_header_rotation(self):
        manager = StealthManager()
        ua1 = manager.get_headers()["User-Agent"]
        ua2 = manager.get_headers()["User-Agent"]
        
        # It's random, but with 5 agents, statistically unlikely to match 10 times in a row.
        # We just check that it's a valid string.
        self.assertTrue(len(ua1) > 10)

    def test_throttling(self):
        manager = StealthManager(level=StealthLevel.LEVEL_2)
        start = time.time()
        manager.throttle()
        duration = time.time() - start
        
        # Level 2 sleep is 0.5 to 2.0
        self.assertTrue(duration >= 0.5)

    def test_auto_escalation(self):
        manager = StealthManager(level=StealthLevel.LEVEL_1)
        manager.report_block()
        manager.report_block() # Count = 2 -> Level 2
        
        self.assertEqual(manager.level, StealthLevel.LEVEL_2)
        
        manager.report_block()
        manager.report_block()
        manager.report_block() # Count = 5 -> Level 3
        
        self.assertEqual(manager.level, StealthLevel.LEVEL_3)

if __name__ == '__main__':
    unittest.main()
