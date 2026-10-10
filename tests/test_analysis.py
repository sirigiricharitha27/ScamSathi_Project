import unittest
from app import analyze_text


class AnalysisTests(unittest.TestCase):
    def test_urgent_account_message_gets_indicators(self):
        result = analyze_text("URGENT! Your account will be suspended. Verify your account immediately.")
        self.assertGreaterEqual(result["score"], 30)
        self.assertTrue(result["indicators"])

    def test_low_indicator_text_does_not_claim_safe(self):
        result = analyze_text("Hello, are we still meeting at 5?")
        self.assertEqual(result["score"], 0)
        self.assertIn("does not mean the message is safe", result["advice"])

    def test_http_url_flagged(self):
        result = analyze_text("Check this link http://example.invalid/login")
        self.assertTrue(any("does not use HTTPS" in item["label"] for item in result["indicators"]))


if __name__ == "__main__":
    unittest.main()
