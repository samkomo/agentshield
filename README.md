# AgentShield

A runtime action-security gateway for autonomous AI agents. The agent proposes an action; AgentShield decides whether it happens, carries it out with credentials the agent never sees, and keeps signed evidence of both.

It implements the MVP proposed in the *AgentSecurity* research report (13 November 2026): a mandatory MCP/REST action gateway with local secret and PII detection, redact/block, deterministic policy, task grants and delegation, exact-action approval, a tamper-evident event log, and Python and TypeScript SDKs — deployable on one machine with no external services.

```
agent ──► authorize ──► identity · grant · tool pin · data labels · scan ──► policy ──► permit
                                   (redact → re-scan → re-decide)   (approval, budget reservation)
agent ──► execute(permit) ──► exact-action check · one use · re-check revocations
                          ──► tool call with brokered credential ──► scan result ──► signed receipt
```

## Quick start

Requires Node.js 24 or later. There are no runtime dependencies; `npm install` only fetches TypeScript for type-checking.

```bash
npm install
```

```bash
npm run demo
```

```bash
npm test
```

`npm run demo` runs the report's twelve security workflows in memory against mock tools and prints what was decided and whether anything reached the tool. `npm test` runs 84 tests, including the adversarial invariant suite.

To run a gateway:

```bash
node src/cli.ts init --dir .agentshield --tenant default
```

```bash
node src/cli.ts serve --dir .agentshield
```

`init` creates keys, the database, the signed default policy and three credentials (`admin`, `security`, `auditor`) in `.agentshield/bootstrap-credentials.json`, readable only by you. The gateway listens on `127.0.0.1:8787`; use `--socket PATH` for an owner-only Unix socket instead.

## What it enforces

| Property | How |
|---|---|
| Deny by default | No policy, no grant, unknown tool, unknown destination or a failed control all end in `block`. |
| Identity comes from the transport | Tenant and principal are read from the credential. Nothing in the request body is trusted for identity, findings, risk or approval status. |
| One exact action per permit | A permit binds the SHA-256 of the canonical (RFC 8785) action, the policy version, grant revision, tool revision and the agent's revocation epoch. The executor recomputes the digest from the action presented and uses the permit once. |
| Approval covers one digest | A human approves a specific action digest. Change a byte, or re-register the tool, and the approval no longer applies. Approval cannot override a grant, budget or policy denial. |
| Destinations are bound to arguments | The envelope's `destination_id` must equal what the recipient/beneficiary/URL argument resolves to, so a call cannot be labelled with one destination and sent to another. |
| Delegation only narrows | A child grant must be a subset of its parent in every dimension. Spending by a child counts against every ancestor's budget. |
| Atomic budgets | Reservation happens in the same write transaction as permit issue. Unused permits hold their reservation until they expire; unknown outcomes hold it until reconciled. |
| Secrets do not cross | Credentials in arguments are replaced with placeholders (or the action is blocked where rewriting would change its meaning). Credentials in tool results are removed before the agent sees them. |
| Untrusted content stays data | Results from MCP servers and external destinations are tagged untrusted. Injection signals taint the task, after which writes need a person. |
| Tools are pinned | A tool is usable only at the manifest hash someone reviewed. A live MCP server whose definitions drift from the pin is quarantined, and agents are only ever shown the pinned descriptions. |
| Revocation reaches issued permits | Suspending an agent, revoking a grant (or any ancestor), quarantining a tool or revoking a policy version stops permits that were already issued. |
| Evidence is tamper-evident | Every decision and outcome is a hash-chained, Ed25519-signed event written in the same transaction as the change. Signed checkpoints go to a separate file so truncation is detectable. Events hold digests and categories, never payloads. |

## Concepts

**Principals and roles.** `agent`, `approver`, `operator`, `admin`, `auditor`. Agents can scan, inspect, execute and delegate. They cannot reach the registry, policy, grants, suspension or audit.

**Grants.** What one agent may do for one task: tools, operations, resources, destinations (literals or `prefix*`), an optional per-action limit and budget in integer minor units, an expiry, and how many levels it may delegate.

**Tool registry.** A manifest per tool: kind (`http`, `mcp`, `function`), where it runs, a credential reference (`env:NAME` or `file:/path`), and per operation its class, effect, JSON Schemas and which arguments name the resource, destination and amount. Registering sets it `pending`; a second person verifies the exact revision.

**Catalog.** Destinations (internal/external, approved or not, the most sensitive label they may receive, whether they accept PII) and resource labels (`customer_*` → `RESTRICTED`).

**Policy.** A signed JSON bundle: label ordering, finding handling, per-class approval and redaction rules, risk weights and thresholds, limits. Only bundles signed by a key in `keys/trust/` are accepted; a second administrator activates a version. See [policies/default.policy.json](policies/default.policy.json).

**Decisions.** `allow`, `redact` (allowed after rewriting; the response includes the transformed action), `require_approval`, `block`. Risk is an interpretable weighted score that can add an approval or a block, never remove a denial.

## Setting up an agent

With the gateway running, and `ADMIN`, `SECURITY` set from the bootstrap credentials file:

```bash
curl -s -X POST localhost:8787/v1/principals -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' -d '{"principal_id":"oscar","role":"agent","sponsor":"alice"}'
```

```bash
curl -s -X POST localhost:8787/v1/destinations -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' -d '{"destination_id":"crm.internal","class":"internal","state":"approved","max_label":"RESTRICTED","accepts":["PII"]}'
```

```bash
curl -s -X POST localhost:8787/v1/tools -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' -d @examples/crm-tool.json
```

```bash
curl -s -X POST localhost:8787/v1/tools/crm.v1/verify -H "authorization: Bearer $SECURITY" -H 'content-type: application/json' -d '{"expected_revision":"sha256:…from the register response…"}'
```

```bash
curl -s -X POST localhost:8787/v1/grants -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' -d '{"agent_id":"oscar","task_id":"task_123","expires_at":"2026-12-31T00:00:00Z","scope":{"tools":["crm.v1"],"operations":["crm.read"],"resources":["customer_*"],"destinations":["crm.internal"]}}'
```

[examples/crm-tool.json](examples/crm-tool.json) is a sample HTTP tool manifest.

## Using it from an agent

Python (standard library only, 3.9+; `sdk/python`):

```python
from agentshield import Client

client = Client(endpoint="http://127.0.0.1:8787", credential=agent_token)
result = client.execute(
    tool_id="crm.v1", operation="crm.read", task_id="task_123",
    resource_id="customer_42", destination_id="crm.internal",
    arguments={"customer_id": "customer_42"}, idempotency_key="task_123-read_42",
)
if result.decision == "require_approval":
    ...                               # a person approves, then:
    result = client.resume(result)
elif result.decision == "block":
    raise RuntimeError(result.reason)  # do not call the provider some other way
```

TypeScript (`sdk/typescript/client.ts`):

```ts
const shield = new AgentShieldClient({ endpoint: 'http://127.0.0.1:8787', credential: agentToken });
const result = await shield.execute({
  toolId: 'crm.v1', operation: 'crm.read', taskId: 'task_123',
  resourceId: 'customer_42', destinationId: 'crm.internal', arguments: { customer_id: 'customer_42' },
});
if (result.decision !== 'allow' && result.decision !== 'redact') throw new Error(result.reason);
```

MCP. Every registered tool is also reachable as an MCP server at `POST /mcp/{tool_id}` (header `X-AgentShield-Task`). For clients that only speak stdio:

```json
{
  "mcpServers": {
    "files": {
      "command": "node",
      "args": ["/path/to/AgentShield/src/cli.ts", "mcp-stdio", "--tool", "files", "--task", "task_123"],
      "env": { "AGENTSHIELD_TOKEN": "…agent credential…" }
    }
  }
}
```

In-process. For embedding or tests, construct `Shield` directly and register handlers with `shield.functions.register(toolId, handler)`; see [examples/world.ts](examples/world.ts).

## REST API

All routes need `Authorization: Bearer …`. Bodies are strict JSON: duplicate keys and unknown envelope fields are rejected.

| Operation | Route | Permission |
|---|---|---|
| Scan inbound content, record task exposure | `POST /v1/scan/input` | `agent:scan` |
| Pre-flight an outbound payload | `POST /v1/scan/output` | `agent:scan` |
| Detect sensitive spans / redact / detect injection | `POST /v1/detect/sensitive`, `/v1/redact`, `/v1/detect/injection` | `agent:scan` |
| Inspect an action without recording it; risk only | `POST /v1/tools/inspect`, `/v1/actions/risk` | `agent:inspect` |
| Authorize; execute with a permit; both | `POST /v1/actions/authorize`, `/execute`, `/run` | `agent:execute` |
| Stop a decided action; settle an unknown outcome | `POST /v1/actions/{id}/block`, `/reconcile` | `operator:block` |
| Look up, view, list, decide approvals | `POST /v1/approvals`, `GET /v1/approvals[/{id}]`, `POST …/{id}/decide` | `agent:request` / `operator:approve` |
| Register, verify, quarantine, list tools | `POST /v1/tools`, `…/{id}/verify`, `…/{id}/quarantine`, `GET /v1/tools[/{id}]` | `admin:tools` / `operator:tools` |
| Create, test, activate, revoke policy | `POST /v1/policies`, `…/{id}/test`, `/activate`, `/revoke` | `admin:policy` |
| Principals, grants, delegation | `POST /v1/principals`, `/v1/grants`, `/v1/grants/{id}/revoke`, `/v1/grants/delegate` | `admin:*` / `agent:delegate` |
| Destinations and resource labels | `POST`/`GET /v1/destinations`, `/v1/resource-labels` | `admin:catalog` |
| Suspend, resume, list agents; an agent's risk history | `POST /v1/agents/{id}/suspend`, `/resume`, `GET /v1/agents[/{id}/risks]` | `operator:suspend` / `auditor:read` |
| Events, chain verification, checkpoint, report | `GET /v1/events[/{id}]`, `POST /v1/audit/verify`, `/v1/audit/checkpoint`, `/v1/reports` | `auditor:*` |
| MCP endpoint | `POST /mcp/{tool_id}` | `agent:execute` |

Status codes: `200` allowed/succeeded, `202` approval required, `403` blocked or not permitted, `409` replay or conflict, `413`/`415`/`422` bad input, `429` rate limited, `502` execution failed, `504` outcome unknown (do not retry; reconcile), `503` a control could not run (treated as a denial).

## Layout

```
src/core/        strict JSON + RFC 8785 canonicalization, Ed25519 tokens, schema validator
src/actions/     envelope validation and binding, permits, intent state machine
src/detect/      secret/PII patterns, normalization, redaction, injection heuristics
src/policy/      signed bundles, deterministic evaluator, risk scoring
src/identity/    principals, agents, grants and delegation
src/registry/    tool registry and pins, destination/label catalog, task context
src/budget/      atomic reservations
src/approvals/   digest-bound approvals
src/audit/       hash-chained events, checkpoints, redaction vault
src/executor/    HTTP, MCP and in-process adapters; credential broker
src/mcp/         upstream MCP client, agent-facing MCP proxy
src/gateway/     the pipeline (shield.ts) and REST server
sdk/             Python and TypeScript clients
tests/           workflows, invariants, end-to-end, detectors, primitives
examples/        demo and the synthetic organisation it runs against
```

## Differences from the report, and what is not here

The report recommends Go, OPA/Rego and PostgreSQL. This build is TypeScript on Node 24 with a built-in policy evaluator and SQLite, so that it runs anywhere Node does with nothing to install. The contracts the report says to own — the action envelope, permit lifecycle, provenance and label propagation, approval and receipt lifecycle — are implemented as specified; the engine choices sit behind small interfaces (`Store`, `decide`, `Identity.authenticate`, `ToolAdapter`, `Detector`).

Not implemented:

- **NER.** Detection is format, checksum and context rules. It does not find names, free-text addresses or proprietary code. A local model plugs in through the `Detector` interface.
- **Streaming inspection.** Payloads are scanned whole; chunked egress is not handled.
- **mTLS, SSO, MFA.** Authentication is bearer credentials over loopback or a Unix socket. AgentIdentity and AgentPay are integration points, not integrations: identity is a local provider and the budget ledger is local.
- **Shell, browser, file and database brokers; sandboxing.** Only REST and MCP actions are mediated.
- **Webhooks, SIEM export, OpenTelemetry, dashboard, multi-node operation, billing.**

## Limits you should know about

- **It is only a boundary if it cannot be bypassed.** An agent that holds a provider credential, or can open its own network connection, is not constrained by anything here. Remove direct credentials and restrict egress; the SDKs are a convenience, not a control.
- **A grant that is too broad permits misuse inside it.** Injection detection is heuristic and will be evaded. The guarantee is narrower: an action outside the grant does not execute.
- **A tool pin proves what was reviewed,** not that an unchanged server behaves well.
- **A host administrator is outside the protection.** Whoever can read `keys/` can sign permits and events. Move `keys/policy-signing.key` off the gateway host, and send `checkpoints.jsonl` somewhere the gateway's own user cannot rewrite.
- **Covert channels are out of scope,** as are availability under flood and the correctness of what a model says.
- **This has not had a penetration test or independent review.** The thresholds in the default policy are starting values, not calibrated ones.
