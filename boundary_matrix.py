from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict, dataclass
from importlib.metadata import version
import json
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import time
from urllib.request import Request as HttpRequest, urlopen

from agents import (
    Agent,
    GuardrailFunctionOutput,
    Runner,
    ToolGuardrailFunctionOutput,
    function_tool,
    input_guardrail,
    set_tracing_disabled,
)
from agents.decorators import tool_input_guardrail, tool_output_guardrail
from agents.testing.model import ScriptedModel, assistant_message, function_call

set_tracing_disabled(True)


@dataclass
class CaseResult:
    mode: str
    calls_requested: int
    guard_delay_ms: int
    effects_committed: int
    effect_times_ms: list[float]
    final_exception: str | None
    model_calls: int


async def run_case(mode: str, calls: int, guard_delay_ms: int) -> CaseResult:
    wall_started_ns = time.time_ns()
    temp = tempfile.TemporaryDirectory(prefix="boundary-matrix-", ignore_cleanup_errors=True)
    ledger_path = Path(temp.name) / "effects.jsonl"
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    sink = subprocess.Popen(
        [sys.executable, str(Path(__file__).with_name("effect_sink.py")), "--port", str(port), "--ledger", str(ledger_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(100):
        try:
            urlopen(f"http://127.0.0.1:{port}/ready", timeout=0.2).read()
            break
        except Exception:
            await asyncio.sleep(0.01)
    else:
        sink.terminate()
        temp.cleanup()
        raise RuntimeError("effect sink did not start")

    @tool_input_guardrail
    async def reject_before_tool(data):
        return ToolGuardrailFunctionOutput.raise_exception({"boundary": "tool-input"})

    @tool_output_guardrail
    async def reject_after_tool(data):
        return ToolGuardrailFunctionOutput.raise_exception({"boundary": "tool-output"})

    input_tool_guards = [reject_before_tool] if mode == "tool_input" else None
    output_tool_guards = [reject_after_tool] if mode == "tool_output" else None

    @function_tool(
        tool_input_guardrails=input_tool_guards,
        tool_output_guardrails=output_tool_guards,
    )
    async def external_write(record_id: int) -> str:
        """Commit one write to an out-of-process HTTP service."""
        payload = json.dumps({"record_id": record_id}).encode()
        request = HttpRequest(
            f"http://127.0.0.1:{port}/effects",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        await asyncio.to_thread(lambda: urlopen(request, timeout=2).read())
        return f"wrote:{record_id}"

    @input_guardrail(run_in_parallel=mode == "agent_parallel")
    async def reject_agent_input(ctx, agent, user_input):
        await asyncio.sleep(guard_delay_ms / 1000)
        return GuardrailFunctionOutput(
            output_info={"boundary": "agent-input"},
            tripwire_triggered=True,
        )

    first_step = [
        function_call("external_write", {"record_id": i}, call_id=f"call-{i}")
        for i in range(calls)
    ]
    model = ScriptedModel([first_step, [assistant_message("done")]])
    agent = Agent(
        name="boundary-matrix",
        model=model,
        tools=[external_write],
        input_guardrails=[reject_agent_input] if mode.startswith("agent_") else [],
    )
    final_exception = None
    try:
        try:
            await Runner.run(agent, "perform all writes")
        except BaseException as exc:
            final_exception = type(exc).__name__
        # asyncio.to_thread work is not cancelled with its awaiting coroutine.
        # Let already-started HTTP commits settle before observing the ledger.
        await asyncio.sleep(0.25)
        rows = []
        if ledger_path.exists():
            rows = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
    finally:
        sink.terminate()
        sink.wait(timeout=3)
        temp.cleanup()
    return CaseResult(
        mode=mode,
        calls_requested=calls,
        guard_delay_ms=guard_delay_ms,
        effects_committed=len(rows),
        effect_times_ms=[round((row["sink_time_ns"] - wall_started_ns) / 1_000_000, 3) for row in rows],
        final_exception=final_exception,
        model_calls=len(model.calls),
    )


async def canonical_matrix() -> dict:
    cases = []
    for calls in (1, 4, 16):
        for mode in ("agent_parallel", "agent_blocking", "tool_input", "tool_output"):
            cases.append(await run_case(mode, calls, 50))
    delay_sweep = []
    for delay in (0, 1, 5, 10, 20, 50):
        repetitions = [await run_case("agent_parallel", 1, delay) for _ in range(10)]
        delay_sweep.append({
            "guard_delay_ms": delay,
            "runs": len(repetitions),
            "runs_with_effect": sum(r.effects_committed > 0 for r in repetitions),
            "effects_committed": sum(r.effects_committed for r in repetitions),
        })
    fanout_repetitions = []
    for mode in ("agent_parallel", "agent_blocking", "tool_input", "tool_output"):
        repetitions = [await run_case(mode, 16, 50) for _ in range(10)]
        values = [r.effects_committed for r in repetitions]
        fanout_repetitions.append({
            "mode": mode,
            "calls_requested_per_run": 16,
            "guard_delay_ms": 50,
            "runs": len(values),
            "committed_per_run": values,
            "min_committed": min(values),
            "max_committed": max(values),
        })
    return {
        "runtime": "OpenAI Agents SDK",
        "runtime_version": version("openai-agents"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "claim": "A final guardrail tripwire does not imply that external side effects were prevented; prevention depends on boundary placement and execution mode.",
        "cases": [asdict(case) for case in cases],
        "delay_sweep": delay_sweep,
        "fanout_repetitions": fanout_repetitions,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="results/canonical.json")
    args = parser.parse_args()
    result = asyncio.run(canonical_matrix())
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    summary = [
        {
            "mode": row["mode"],
            "calls": row["calls_requested"],
            "effects": row["effects_committed"],
            "final": row["final_exception"],
        }
        for row in result["cases"]
    ]
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
