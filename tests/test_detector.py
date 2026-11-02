import unittest
from datetime import datetime, timedelta
from src.detector import detect_suspicious_activity

class DetectorTests(unittest.TestCase):
    def test_five_failures_trigger_alert(self):
        start = datetime(2026, 11, 2, 9, 0)
        events = [{"timestamp": start + timedelta(seconds=30*i), "source_ip": "192.0.2.10", "status": "failed"} for i in range(5)]
        self.assertEqual(len(detect_suspicious_activity(events, 5, 5)), 1)

    def test_two_failures_do_not_trigger_alert(self):
        start = datetime(2026, 11, 2, 9, 0)
        events = [{"timestamp": start + timedelta(seconds=30*i), "source_ip": "192.0.2.11", "status": "failed"} for i in range(2)]
        self.assertEqual(detect_suspicious_activity(events, 5, 5), [])

if __name__ == "__main__":
    unittest.main()
