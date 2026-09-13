import time
import unittest

from attack_matrix import Lab, run_cases


class EffectPermitTests(unittest.TestCase):
    def test_resource_trusting_faulty_adapter_accepts_unsafe_effects(self):
        rows = {row["case"]: row for row in run_cases("trust-adapter")}
        self.assertEqual(rows["arguments_changed_via_agent_runtime"]["effects_committed"], 1)
        self.assertEqual(rows["concurrent_retry_16x_via_agent_runtime"]["effects_committed"], 16)
        self.assertEqual(rows["forged_permit"]["effects_committed"], 1)

    def test_effect_permit_enforces_all_cases(self):
        rows = {row["case"]: row for row in run_cases("permit")}
        self.assertTrue(all(row["passed"] for row in rows.values()), rows)
        self.assertEqual(sum(row["effects_committed"] for row in rows.values()), 3)
        concurrent_ids = [body["effect_id"] for body in rows["concurrent_retry_16x_via_agent_runtime"]["responses"]]
        self.assertEqual(len(set(concurrent_ids)), 1)

    def test_identical_retry_returns_same_effect_without_duplicate(self):
        lab = Lab("permit")
        try:
            _, allowed = lab.authorize(ttl_ms=200)
            first_status, first = lab.execute(allowed["permit"])
            time.sleep(0.25)
            retry_status, retry = lab.execute(allowed["permit"])
            self.assertEqual((first_status, retry_status), (200, 200))
            self.assertEqual(first["effect_id"], retry["effect_id"])
            self.assertEqual(lab.effect_count(), 1)
        finally:
            lab.close()


if __name__ == "__main__":
    unittest.main()
