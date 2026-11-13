# Threat model and coverage

This maps the threat register in the research report (chapter 11) to what AgentShield does today. It is a statement of design intent backed by tests, not a certification. Nothing here has been penetration-tested or independently reviewed.

## Assumptions

Every guarantee below depends on these. Where one fails, the guarantee does not hold.

1. **Complete mediation.** The agent has no credential for, and no network path to, a protected tool except through the gateway. See [Closing the bypass](integration.md#closing-the-bypass).
2. **The gateway host is trusted.** Whoever can read the key directory can sign permits and events. A host administrator is outside the protection.
3. **Administration is honest and competent.** Grants are as narrow as the task; manifests describe tools truthfully; resources are labelled; two administrators do not collude.
4. **The policy signing key is held away from the gateway** and by someone other than whoever activates policy.
5. **Checkpoints leave the host.** Truncation of the audit chain is detectable only against a checkpoint the attacker could not also rewrite.

## What is claimed

Under those assumptions:

- An action outside the agent's grant does not execute, whatever the model was persuaded of.
- An approval applies to exactly one action, once.
- Spending under a grant, including by delegated agents, does not exceed its budget.
- A delegated agent holds no authority its parent lacked.
- Credentials matching a supported format do not leave in action arguments and do not reach the agent in tool results.
- Every decision and execution leaves a signed event, and alteration of recorded events is detectable.

## What is not claimed

- That prompt injection is detected. The heuristics are advisory and will be evaded.
- That all sensitive data is recognised. Detection is format, checksum and context rules; names, free-text addresses and proprietary content are not found.
- That an action *inside* a grant is benign. A broad grant permits misuse within it.
- That a pinned tool behaves well, or that a tool's result is true.
- Anything about covert channels, availability under load, or what a model says in text.
- Safety of physical systems. Schema bounds on a setpoint are a guard, not a safety system.

## Coverage by threat

Status: **Implemented** — enforced in code and tested. **Partial** — some of the report's controls are present; the gap is stated. **Deployment** — the control exists outside this software. **Not implemented**.

| # | Threat | Status | What AgentShield does | What remains |
|---|---|---|---|---|
| 1 | Impersonation | Partial | Tenant and principal come only from the credential; credentials are stored hashed; a permit is bound to the principal it was issued to and refused for anyone else | Credentials are long-lived bearer tokens. No mTLS, audience binding, short-lived tokens or workload identity. A stolen agent credential is that agent until suspended |
| 2 | Credential compromise | Partial | Downstream credentials are resolved inside the gateway at call time, never returned, never placed in model context; credentials in arguments and results are detected and removed | No vault integration or automatic rotation. Host compromise exposes everything |
| 3 | Prompt injection | Implemented, with limits | Results from MCP and external destinations are tagged untrusted; injection signals taint the task; writes in a tainted task need a person; the grant bounds what any hijacked agent can do | Detection is heuristic. An attack that stays inside the grant and below the taint threshold is not stopped |
| 4 | Data exfiltration | Partial | Destinations must be catalogued and approved; the envelope's destination is bound to the arguments; resource and task labels are checked against the destination's ceiling; secrets and personal data are redacted or blocked | No network egress isolation (deployment). Unlabelled data flows freely. Covert channels, and encodings other than one level of base64, are not addressed |
| 5 | Unauthorized transactions | Implemented | Exact-action permits; integer amounts; per-action limit; atomic shared budget; one-use nonce; idempotency key forwarded downstream; unknown outcomes held, never retried | Reconciliation with the payment provider is manual. No AgentPay integration. A settled payment cannot be undone |
| 6 | Privilege escalation | Implemented for grants | Delegation can only narrow; revoking a parent cuts off descendants | Resource-side ACLs are the resource's job. A misconfigured parent grant is inherited faithfully |
| 7 | Malicious tool execution | Partial | Tools are usable only at a reviewed, pinned revision; arguments are validated against the reviewed schema; unreviewed operations cannot be called | No sandbox. A stdio MCP server runs as the gateway's OS user, with a minimal environment but full filesystem access |
| 8 | Memory poisoning | Not implemented | — | No memory broker. Content written to an agent's memory outside the gateway is invisible to it |
| 9 | Retrieval poisoning | Partial | Retrieved content that passes through the gateway is scanned, tagged and counted against the task | No ingest-time provenance or index access control |
| 10 | Cross-agent collusion | Partial | Budgets are shared across a delegation tree, so splitting requests between agents does not raise the limit; labels are tracked per task | No correlation across unrelated agents or tasks. Agents that share a covert channel can pool what they know |
| 11 | Supply-chain compromise | Not implemented | The gateway itself has no runtime dependencies, which removes that surface for it | No signature or SBOM checks on tools, MCP servers or models |
| 12 | Compromised MCP server | Implemented, with limits | Server definitions are pinned and re-checked; drift quarantines; the agent's token is never forwarded; upstream uses a separate credential; results are size-limited, schema-checked, scanned and tagged untrusted | A server that returns valid but malicious content at an unchanged definition |
| 13 | Browser-based attack | Not implemented | A browser exposed as a registered tool gets destination binding like any other | No browser broker, origin isolation or upload control |
| 14 | Insecure code execution | Not implemented | — | No command runner or sandbox. Do not register a tool that executes arbitrary code |
| 15 | Sandbox escape | Not applicable | — | There is no sandbox |
| 16 | Unauthorized child agent | Implemented | A child grant must be a subset of its parent in scope, limits, expiry and depth; refusals are recorded | — |
| 17 | Gateway bypass | Deployment | Receipts make bypass detectable: a downstream action with no matching `execution.*` event did not come through the gateway | The comparison with downstream logs is not automated. Prevention is credential and network isolation |
| 18 | Policy tampering | Implemented | Bundles must be signed by a trusted key; a second administrator activates; versions are immutable; the stored bundle is re-verified on load; revoked versions cannot be reactivated | Collusion between the signer and an activating administrator |
| 19 | Audit manipulation | Implemented, with limits | Agents have no route to modify events; events are hash-chained and signed; checkpoints detect truncation and rewriting | Whoever controls both the database and the checkpoint sink. No write-once storage |
| 20 | Denial of service | Partial | Request and result size limits, per-principal rate limit, tool timeouts, bounded scanning; controls fail closed | Single process, single node. A flood denies service to everyone; that is the trade for failing closed |

## Adversarial tests

The report lists tests a release should pass (chapter 11, "Validation and recovery"). Where they stand:

| Test | Covered | Where |
|---|---|---|
| Expired, forged and borrowed permits | Yes | `invariants`: *expired, forged and borrowed permits are refused* |
| Wrong-audience tokens | No | Credentials are not audience-bound |
| Replayed permits, nonces, action ids, idempotency keys | Yes | `invariants`: *a permit executes one action, once*; *a nonce, an action id and an idempotency key each work once* |
| Action altered between authorization and execution | Yes | `invariants`: *the action presented at execution must be byte-for-byte…* |
| Parallel budget races | Yes, within one process | `invariants`: *concurrent payments cannot exceed the budget* |
| Mutated tool schema after approval | Yes | `invariants`: *re-registering a tool after approval invalidates the approval* |
| Revoked grant, suspended agent, quarantined tool, revoked policy during execution | Yes | `invariants`: the four *…kills a permit…* / *kill switch* tests |
| Child scope expansion, excess depth, later expiry | Yes | `workflows` 13.9; `invariants`: *children share the parent budget* |
| Unknown outcome on a payment | Yes | `invariants`: *a write with an unknown outcome is never retried…* |
| Audit edits, gaps, reordering, truncation | Yes | `invariants`: the two audit-chain tests |
| MCP definition drift (rug pull) | Yes | `http`: *MCP proxy: … quarantine on drift* |
| Encoded payloads | One level of base64, fullwidth and zero-width obfuscation | `detect`: *obfuscation…* |
| Destination spoofing in the envelope | Yes | `invariants`: *the envelope cannot name one destination…* |
| Cross-tenant access | Yes | `invariants`: *tenants are isolated* |
| Duplicate JSON keys, oversized and malformed bodies | Yes | `http`: *transport…*; `core`: *strict JSON…* |
| DNS rebinding | No | The REST adapter pins the host name from the manifest, not the resolved address |
| Symlink traversal | Not applicable | There is no file broker |
| Secrets split across streamed chunks | No | Streaming is not implemented |
| Model calls through an alternate network path | No | Deployment control |
| Poisoned memory | No | No memory broker |
| Crash during reservation or execution | Not exercised | By design an interrupted action stays `executing` and is listed as unresolved; no test kills the process mid-call |
| Concurrent writers in separate processes | Not exercised | Reservations use `BEGIN IMMEDIATE`, which serialises across processes, but only single-process concurrency is tested |

## Evaluation targets not yet measured

The report proposes acceptance gates (chapter 21). None has been measured for this build:

- Detection precision and recall on a held-out corpus, per class and per language.
- Attack success rate on AgentDojo or InjecAgent.
- False-positive blocking rate on benign workflows.
- Inline latency (the report's target is p95 ≤ 75 ms for a 4 KiB action) and throughput.
- Recovery time after a crash.

The detector tests are small, hand-written sets of positives and hard negatives. They show the detectors do what they were written to do, not how they perform on real data.

## Before production

1. An independent security review and penetration test.
2. Transport security and stronger authentication than static bearer tokens for anything beyond loopback.
3. Process and network isolation of the agent runtime, and a bypass test.
4. The policy signing key off the gateway host; checkpoints shipped to storage the gateway cannot rewrite.
5. Detection evaluated on your own data, with thresholds set from the results.
6. A data-protection assessment: the database holds action arguments so approvers can see what they approve.
