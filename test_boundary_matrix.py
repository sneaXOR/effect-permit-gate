import asyncio
import unittest

from boundary_matrix import run_case


class BoundaryMatrixTests(unittest.TestCase):
    def test_parallel_agent_guard_can_commit_before_tripwire(self):
        row = asyncio.run(run_case("agent_parallel", 1, 50))
        self.assertEqual(row.effects_committed, 1)
        self.assertEqual(row.final_exception, "InputGuardrailTripwireTriggered")

    def test_blocking_agent_guard_prevents_model_and_tools(self):
        row = asyncio.run(run_case("agent_blocking", 1, 50))
        self.assertEqual(row.effects_committed, 0)
        self.assertEqual(row.model_calls, 0)

    def test_tool_input_guard_prevents_effects(self):
        row = asyncio.run(run_case("tool_input", 1, 50))
        self.assertEqual(row.effects_committed, 0)
        self.assertIn("Tripwire", row.final_exception or "")

    def test_tool_output_guard_is_after_side_effect(self):
        row = asyncio.run(run_case("tool_output", 1, 50))
        self.assertEqual(row.effects_committed, 1)
        self.assertIn("Tripwire", row.final_exception or "")


if __name__ == "__main__":
    unittest.main()
