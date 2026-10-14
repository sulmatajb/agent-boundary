"""Bounded deterministic adversarial HTTP campaigns, not model evaluations."""

import unittest

from scripts.adversarial_campaign import DEFAULT_SEEDS, run_campaign


class GenerativeProcessTests(unittest.TestCase):
    def test_two_seeded_stateful_campaigns_have_exact_durable_effects(self):
        report = run_campaign()
        self.assertEqual(report["total_requests"], 2000)
        self.assertEqual(report["admitted_actions"], 228)
        self.assertEqual(report["denied_effects"], 0)
        self.assertEqual([case["seed"] for case in report["cases"]], list(DEFAULT_SEEDS))
        for case in report["cases"]:
            with self.subTest(seed=case["seed"]):
                self.assertEqual(case["requests"], 1000)
                self.assertEqual(case["state"]["maximum_depth"], 32)
                self.assertEqual(case["state"]["shared_root_spent"], 112)
                self.assertGreater(case["outcomes"]["denied"], 400)
                self.assertGreater(case["outcomes"]["replayed"], 90)
                self.assertGreaterEqual(case["state"]["literal_injection_appends"], 19)
                self.assertGreaterEqual(case["state"]["successful_replays_after_revocation"], 4)
                self.assertGreater(case["sql_reconciliations"], 850)
                self.assertTrue(all(case["invariants"].values()))
                for category in ("malformed_action", "capability_theft", "nested_delegation",
                                 "depth_amplification", "scope_amplification", "budget_amplification",
                                 "replay_mutation", "revoked_lineage", "cooperative_budget_spend",
                                 "cooperative_overrun", "literal_injection", "direct_tool_bypass"):
                    self.assertGreater(case["categories"][category], 0)


if __name__ == "__main__":
    unittest.main()
