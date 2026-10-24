import unittest
from src.ledger import make_chain, make_checkpoint, verify_chain, simulate_tampering


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.chain = make_chain([{"event_id": "E1", "username": "alice"}, {"event_id": "E2", "username": "bob"}])
        self.checkpoint = make_checkpoint(self.chain)

    def test_original_chain_is_valid(self):
        self.assertTrue(verify_chain(self.chain, self.checkpoint)[0])

    def test_changed_event_detected(self):
        altered = simulate_tampering(self.chain, "Change a recorded event")
        self.assertFalse(verify_chain(altered, self.checkpoint)[0])

    def test_deleted_event_detected(self):
        altered = simulate_tampering(self.chain, "Delete a recorded event")
        self.assertFalse(verify_chain(altered, self.checkpoint)[0])

    def test_full_rewrite_detected_by_checkpoint(self):
        altered = simulate_tampering(self.chain, "Rewrite all hashes")
        valid, reason = verify_chain(altered, self.checkpoint)
        self.assertFalse(valid)
        self.assertIn("checkpoint", reason)

    def test_tamper_does_not_touch_original(self):
        simulate_tampering(self.chain, "Change a recorded event")
        self.assertTrue(verify_chain(self.chain, self.checkpoint)[0])


if __name__ == "__main__":
    unittest.main()
