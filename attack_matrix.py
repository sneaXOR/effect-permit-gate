from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import socket
import statistics
import subprocess
import sys
import tempfile
import time

from agent_adapter import run_agent_action
from common import b64url_decode, b64url_encode, http_json

REVISION = "policy-2026-09-13"
AUDIENCE = "payments-eu"
SAFE_ARGS = {"vendor": "approved-vendor", "amount": 100, "currency": "EUR"}


def free_port() -> int:
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def wait_ready(url: str, process: subprocess.Popen) -> None:
    for _ in range(50):
        if process.poll() is not None:
            error = process.stderr.read().strip() if process.stderr else ""
            raise RuntimeError(f"service exited during startup: {error}")
        try:
            if http_json("GET", url, timeout=0.1)[0] == 200:
                return
        except Exception:
            time.sleep(0.02)
    raise RuntimeError(f"service did not start: {url}")


def start_service(command_for_port) -> tuple[int, subprocess.Popen]:
    errors = []
    for _ in range(5):
        port = free_port()
        process = subprocess.Popen(
            command_for_port(port),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            wait_ready(f"http://127.0.0.1:{port}/ready", process)
            return port, process
        except RuntimeError as exc:
            errors.append(str(exc))
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=3)
            if process.stderr:
                process.stderr.close()
    raise RuntimeError("could not start service after five attempts: " + " | ".join(errors))


class Lab:
    def __init__(self, mode: str, revision: str = REVISION):
        self.mode = mode
        self.temp = tempfile.TemporaryDirectory(prefix="effect-permit-", ignore_cleanup_errors=True)
        self.policy_port, self.policy = start_service(
            lambda port: [sys.executable, str(Path(__file__).with_name("policy_service.py")), "--port", str(port), "--revision", REVISION, "--audience", AUDIENCE]
        )
        _, key = http_json("GET", f"http://127.0.0.1:{self.policy_port}/public-key")
        self.effect_port, self.effect = start_service(
            lambda port: [
                sys.executable,
                str(Path(__file__).with_name("effect_service.py")),
                "--port", str(port),
                "--database", str(Path(self.temp.name) / "effects.sqlite"),
                "--mode", mode,
                "--public-key", key["public_key"],
                "--revision", revision,
                "--audience", AUDIENCE,
            ]
        )

    def close(self) -> None:
        for process in (self.effect, self.policy):
            process.terminate()
            process.wait(timeout=3)
            if process.stderr:
                process.stderr.close()
        self.temp.cleanup()

    def authorize(self, arguments: dict = SAFE_ARGS, ttl_ms: int = 5000) -> tuple[int, dict]:
        return http_json("POST", f"http://127.0.0.1:{self.policy_port}/authorize", {
            "principal": "purchasing-agent", "tool": "wire_payment", "tool_version": "v1", "arguments": arguments, "ttl_ms": ttl_ms,
        })

    def execute(self, permit: str = "", arguments: dict = SAFE_ARGS, principal: str = "purchasing-agent", tool: str = "wire_payment", tool_version: str = "v1") -> tuple[int, dict]:
        return http_json("POST", f"http://127.0.0.1:{self.effect_port}/execute", {
            "principal": principal, "tool": tool, "tool_version": tool_version, "arguments": arguments, "permit": permit,
        })

    def effect_count(self) -> int:
        return len(http_json("GET", f"http://127.0.0.1:{self.effect_port}/effects")[1]["effects"])


def run_cases(mode: str) -> list[dict]:
    results = []

    def record(name: str, responses: list[tuple[int, dict]], committed: int, allowed_commits: int, expected_reason: str | None = None) -> None:
        statuses = [status for status, _ in responses]
        response_bodies = [body for _, body in responses]
        protocol_ok = True
        if mode == "permit" and expected_reason is not None:
            protocol_ok = all(
                status == 403 and body.get("reason") == expected_reason
                for status, body in responses
            )
        elif mode == "permit":
            effect_ids = [body.get("effect_id") for status, body in responses if status == 200]
            protocol_ok = len(effect_ids) == len(responses) and len(set(effect_ids)) == 1
        results.append({
            "case": name,
            "statuses": statuses,
            "responses": response_bodies,
            "effects_committed": committed,
            "allowed_commits": allowed_commits,
            "passed": committed == allowed_commits and protocol_ok,
        })

    lab = Lab(mode)
    try:
        before = lab.effect_count()
        responses = asyncio.run(run_agent_action(
            f"http://127.0.0.1:{lab.policy_port}",
            f"http://127.0.0.1:{lab.effect_port}",
        ))
        record("approved_action_via_agent_runtime", responses, lab.effect_count() - before, 1)

        before = lab.effect_count()
        response = lab.execute("")
        record("missing_permit", [response], lab.effect_count() - before, 0, "invalid_signature")

        before = lab.effect_count()
        responses = asyncio.run(run_agent_action(
            f"http://127.0.0.1:{lab.policy_port}",
            f"http://127.0.0.1:{lab.effect_port}",
            "mutate-amount",
        ))
        record("arguments_changed_via_agent_runtime", responses, lab.effect_count() - before, 0, "arguments_mismatch")

        _, allowed = lab.authorize()
        before = lab.effect_count()
        responses = [lab.execute(allowed["permit"]), lab.execute(allowed["permit"])]
        record("sequential_retry", responses, lab.effect_count() - before, 1)

        before = lab.effect_count()
        responses = asyncio.run(run_agent_action(
            f"http://127.0.0.1:{lab.policy_port}",
            f"http://127.0.0.1:{lab.effect_port}",
            "replay-16",
        ))
        record("concurrent_retry_16x_via_agent_runtime", responses, lab.effect_count() - before, 1)

        _, allowed = lab.authorize(ttl_ms=1)
        time.sleep(0.02)
        before = lab.effect_count()
        response = lab.execute(allowed["permit"])
        record("expired_permit", [response], lab.effect_count() - before, 0, "expired")

        _, allowed = lab.authorize()
        encoded_claims, encoded_signature = allowed["permit"].split(".", 1)
        changed_signature = bytearray(b64url_decode(encoded_signature))
        changed_signature[0] ^= 1
        forged = f"{encoded_claims}.{b64url_encode(bytes(changed_signature))}"
        before = lab.effect_count()
        response = lab.execute(forged)
        record("forged_permit", [response], lab.effect_count() - before, 0, "invalid_signature")

        _, allowed = lab.authorize()
        before = lab.effect_count()
        response = lab.execute(allowed["permit"], principal="another-agent")
        record("wrong_principal_label", [response], lab.effect_count() - before, 0, "principal_mismatch")

        _, allowed = lab.authorize()
        before = lab.effect_count()
        response = lab.execute(allowed["permit"], tool_version="v2")
        record("wrong_tool_version", [response], lab.effect_count() - before, 0, "tool_version_mismatch")
    finally:
        lab.close()

    stale_lab = Lab(mode, revision="policy-new-revision")
    try:
        _, allowed = stale_lab.authorize()
        before = stale_lab.effect_count()
        response = stale_lab.execute(allowed["permit"])
        record("stale_policy_revision", [response], stale_lab.effect_count() - before, 0, "stale_policy")
    finally:
        stale_lab.close()
    return results


def measure_allowed_latency(mode: str, runs: int = 40) -> dict:
    lab = Lab(mode)
    durations = []
    try:
        for _ in range(runs):
            started = time.perf_counter_ns()
            status, allowed = lab.authorize()
            if status != 200:
                raise RuntimeError("allowed request was denied")
            effect_status, _ = lab.execute(allowed["permit"])
            if effect_status != 200:
                raise RuntimeError("allowed effect was rejected")
            durations.append((time.perf_counter_ns() - started) / 1_000_000)
    finally:
        lab.close()
    ordered = sorted(durations)
    return {
        "runs": runs,
        "median_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[max(0, int(runs * 0.95) - 1)], 3),
    }


def run_matrix() -> dict:
    rows = {mode: run_cases(mode) for mode in ("trust-adapter", "permit")}
    return {
        "claim": "Moving authorization proof to the effect service blocks mutated, replayed, expired, forged, and stale actions that an effect service trusting a faulty or compromised host accepts.",
        "policy": "purchasing-agent may pay approved-vendor at most 1000 EUR",
        "modes": rows,
        "summary": {
            mode: {
                "cases_passed": sum(row["passed"] for row in mode_rows),
                "cases_total": len(mode_rows),
                "effects_committed": sum(row["effects_committed"] for row in mode_rows),
                "unauthorized_or_duplicate_effects": sum(max(0, row["effects_committed"] - row["allowed_commits"]) for row in mode_rows),
            }
            for mode, mode_rows in rows.items()
        },
        "allowed_path_latency": {mode: measure_allowed_latency(mode) for mode in ("trust-adapter", "permit")},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="results/canonical.json")
    args = parser.parse_args()
    result = run_matrix()
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], indent=2))
