# One approval, one exact effect

An AI agent gets approval to pay **€100**, then a faulty or compromised host changes the amount, reuses the approval, or sends it 16 times at once. The baseline tool service trusts the host that called it. This reference gate makes the tool service verify the approval itself before it changes state.

The approval is a signed, single-effect permit that binds a principal label, destination service, tool version, arguments, policy revision, and expiry time. Change any of them and the action is refused. Retry the identical action and the service returns the original effect reference without paying twice. The principal label is a signed claim, not proof of a human or workload identity.

## Result

The same ten control and attack cases ran against both designs:

| Design | Attack classes reaching a bad effect | 16 concurrent attempts |
|---|---:|---:|
| Effect service trusts a faulty/compromised adapter | 9/9 | 16 effects |
| Effect service verifies the permit | 0/9 | 1 effect |

The raw matrix records 23 unauthorized or duplicate effects in the trust-adapter baseline and zero behind the gate. That total is not the headline and is not a prevalence estimate: 15 come from the deliberately chosen 16-way retry. The invariant result is that all nine attack classes reached a bad effect in the baseline and none did behind the gate.

The three legitimate effects still complete: the original approved action, one sequential retry, and one winner from the 16-way concurrent retry. Identical retries receive the same `effect_id`; the transport metadata differs, but no second effect is created.

The canonical JSON also records median and p95 latency for 40 allowed actions in each design. These single-host timings expose the cost; they are not a universal overhead claim.

## What runs

Three request-level boundaries participate:

1. `policy_service.py` decides whether the proposed payment is allowed and signs a permit. Its private key never enters the agent process.
2. `agent_adapter.py` runs the real OpenAI Agents SDK with its deterministic `ScriptedModel`, obtains the opaque permit, and forwards the action.
3. `effect_service.py` recalculates the request fingerprint, verifies the signature and policy lineage, and atomically stores both the used nonce and the effect in SQLite.

`attack_matrix.py` acts as a faulty or hostile adapter with request access but no ability to reconfigure the policy or effect services. The approved control, changed-amount attack, and 16-way concurrent retry traverse the real OpenAI Agents SDK. The remaining cases call the protocol boundaries directly. This is a conformance experiment, not an SDK vulnerability test.

## Run

```bash
python -m pip install -r requirements.txt
python attack_matrix.py --output results/canonical.json
python -m unittest -v
```

No model API or API key is used.

## Why this is relevant to agent security

Dynamo AgentWarden documents that the host application owns the agent loop and enforces returned policy decisions. Its public SDK shape passes a structured tool request separately from the function that performs the action. This experiment tests a stricter adapter contract: the remote system that creates the effect accepts only the exact action that policy approved.

This is not a test of AgentWarden and does not report a Dynamo vulnerability. Signed capabilities, request binding, and idempotency are established security patterns. The contribution is the small executable contract and its adversarial regression matrix for an agent tool boundary.

## Claim ceiling

This repository demonstrates that, inside the included process and SQLite model, effect-side verification prevents the tested substitution, bypass, stale-policy, forgery, expiry, and duplicate-effect cases while preserving identical retries.

It does not provide exactly-once guarantees for arbitrary external systems. A production integration must either commit the business effect and idempotency record in one transaction or pass the same idempotency key to a system that can. Key rotation and cryptographic workload identity are outside this prototype.

## Sources

- Dynamo AgentWarden SDK: https://docs.dynamo.ai/docs/AgentWarden/SDK/
- Dynamo AgentWarden runtime model: https://docs.dynamo.ai/docs/AgentWarden/How-AgentWarden-Works/
- OAuth DPoP replay and request binding: https://www.rfc-editor.org/rfc/rfc9449.html
- OAuth Rich Authorization Requests: https://www.rfc-editor.org/rfc/rfc9396.html
- Macaroons: https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/
- Idempotent API design: https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/
