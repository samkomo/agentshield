# Integrating an agent

There are four ways to put an agent behind AgentShield. They can be mixed.

| Route | Use it when |
|---|---|
| [SDK](#sdks) (Python or TypeScript) | You control the agent's tool dispatcher and can replace direct tool calls |
| [MCP](#mcp) | The agent already speaks MCP; point it at the gateway instead of the real server |
| [REST](#rest) | Any other language; the API is small |
| [In-process](#in-process) | The gateway and the tools live in one Node application, or in tests |

Whichever you choose, read [Closing the bypass](#closing-the-bypass) first. Integration is not protection until the agent has no other way to reach the tool.

## What the agent must supply

Each action names:

- **`task_id`** — the unit of work the grant was issued for. Keep it stable for the life of the task: exposure (what the task has read, what injected content it has seen) is tracked per task.
- **`tool_id`** and **`operation`** — as registered.
- **`resource_id`** — the record, file or object being touched. If the operation declares a `resource_arg`, this must equal that argument.
- **`destination_id`** — where data is going. If the operation declares a `destination_arg`, this must equal what that argument resolves to (the recipient's domain, the URL's host, the beneficiary id). Otherwise it is the tool's own registered destination.
- **`arguments`** — what the tool receives.

The SDKs generate `action_id`, `nonce` and `expires_at`. Supply an `idempotency_key` for anything with a side effect.

## SDKs

### Python

Standard library only, Python 3.9+. Install from the repository:

```bash
pip install ./sdk/python
```

```python
from agentshield import Client, AgentShieldError

client = Client(endpoint="http://127.0.0.1:8787", credential=agent_token)

result = client.execute(
    tool_id="mail.v1", operation="email.send", task_id="task_abc",
    resource_id="report.pdf", destination_id="partner.example",
    arguments={"recipient": "reviewer@partner.example", "body": "Please review.", "attachment": "report.pdf"},
    idempotency_key="task_abc-send-1",
    ttl_seconds=600,
)

if result.decision == "block":
    # Final. Tell the user why; do not call the provider some other way.
    raise RuntimeError(result.reason)

if result.decision == "require_approval":
    # Keep `result`. When a person has approved (see below), resubmit the same action.
    notify_human(result.approval_id, result.reason)
    ...
    result = client.resume(result)

if result.state == "unknown":
    # A write may or may not have landed. Do not retry. An operator reconciles it.
    escalate(result.receipt_id)
elif result.state == "succeeded":
    data = result.result
    if result.untrusted_content:
        # Present this to the model as quoted data, never as instructions.
        data = wrap_as_untrusted(data)
```

`Result` fields: `decision`, `reason`, `reason_codes`, `risk_level`, `approval_id`, `state`, `result`, `untrusted_content`, `receipt_id`, `action` (the submitted envelope), `raw`, and the property `allowed`.

`AgentShieldError` is raised when the gateway refuses the *request* — a replayed nonce, a malformed field, a credential without the permission. A `block` is not an exception; it is a result.

Other methods: `resume`, `inspect`, `scan_input`, `scan_output`, `detect_sensitive`, `redact`, `detect_injection`, `delegate`, and `request` for any other route.

### TypeScript

One file, no dependencies: [sdk/typescript/client.ts](../sdk/typescript/client.ts).

```ts
import { AgentShieldClient } from './sdk/typescript/client.ts';

const shield = new AgentShieldClient({ endpoint: 'http://127.0.0.1:8787', credential: agentToken });

let result = await shield.execute({
  toolId: 'crm.v1', operation: 'crm.read', taskId: 'task_123',
  resourceId: 'customer_42', destinationId: 'crm.internal',
  arguments: { customer_id: 'customer_42' }, idempotencyKey: 'task_123-read_42',
});

if (result.decision === 'require_approval') {
  await waitForApproval(result.approvalId);
  result = await shield.resume(result);
}
if (result.state !== 'succeeded') throw new Error(result.reason);
```

### Wrapping a tool dispatcher

Most frameworks have one place where a model's tool call becomes a function call. That is where the SDK goes:

```python
def dispatch(tool_call, task_id):
    spec = ROUTES[tool_call.name]                 # your mapping: tool name -> tool_id, operation, how to derive ids
    result = client.execute(
        tool_id=spec.tool_id, operation=spec.operation, task_id=task_id,
        resource_id=spec.resource_of(tool_call.arguments),
        destination_id=spec.destination_of(tool_call.arguments),
        arguments=tool_call.arguments,
        idempotency_key=f"{task_id}-{tool_call.id}",
    )
    if result.decision in ("block", "require_approval"):
        return {"error": result.reason}           # the model sees the refusal, not a way around it
    return result.result
```

The adapter must not fall back to calling the provider directly on a denial, and must not hold the provider's credential.

No framework adapters are shipped or tested. Check, for your framework, that retries, checkpoint resume and child agents all pass through the same dispatcher.

## Telling the gateway what the agent has read

Content that reaches the model through a gateway-executed tool call is scanned and recorded automatically. Content that reaches it some other way — a file the runtime loaded, a web page fetched by a component outside the gateway — is invisible unless reported:

```python
scan = client.scan_input(page_text, task_id="task_abc", source_id=url)
if scan["provenance"]["tainted"]:
    ...  # the task is now tainted; later writes will need approval
```

This matters because the injection response (approval for writes in a tainted task) and label propagation (a task that read restricted data cannot send to a lesser destination) both key off what the gateway knows the task has seen. The stronger arrangement is to route every read through the gateway so nothing needs reporting.

## Approvals

When a decision is `require_approval`:

1. The agent receives `approval_id` and keeps the action.
2. A person with `operator:approve` opens `GET /v1/approvals/{id}`, which shows the exact action, its risk and why approval is needed.
3. They `POST /v1/approvals/{id}/decide` with `verdict` and the `action_digest` they were shown.
4. The agent resubmits the **same** action (`resume`). It executes once.

The approval lapses with the action's `expires_at`, so set `ttl_seconds` long enough for a human (up to the policy maximum, 15 minutes by default). If it lapses, submit a new action.

There is no notification channel built in. Poll `GET /v1/approvals?status=pending` from whatever your approvers use.

## Delegation

A parent agent can hand part of its grant to another agent:

```python
client.delegate("task_abc", {
    "agent_id": "summariser", "task_id": "task_abc",
    "expires_at": "2026-11-13T12:00:00Z",
    "scope": {"tools": ["docs"], "operations": ["docs.read"], "resources": ["handbook.md"], "destinations": ["docs.internal"]},
})
```

The child agent must already exist as a principal. The child's scope must be a subset of the parent's in every dimension, expire no later, and the parent's grant must allow delegation (`max_delegation_depth`). A refusal is `delegation_denied` with the list of violations. Spending by the child counts against the parent's budget.

## MCP

Every registered tool is reachable as an MCP server at `POST /mcp/{tool_id}`, with the agent's bearer credential and an `X-AgentShield-Task` header.

For clients that only launch stdio servers, use the bridge:

```json
{
  "mcpServers": {
    "files": {
      "command": "node",
      "args": ["/path/to/AgentShield/src/cli.ts", "mcp-stdio", "--tool", "files", "--task", "task_123", "--url", "http://127.0.0.1:8787"],
      "env": { "AGENTSHIELD_TOKEN": "<agent credential>" }
    }
  }
}
```

What the agent sees:

- `tools/list` returns only the reviewed operations its grant covers, with the pinned descriptions.
- A successful call returns the tool's result, with `_meta["agentshield/untrusted"]` and a receipt id.
- A blocked call returns `isError: true` and the reason. It is final.
- A call that needs approval returns `isError: true` with the approval id. After approval, the agent repeats the call with identical arguments and it executes.

The bridge is bound to one task id for its lifetime. Start one per task, or per session if a session is one task.

Remove the real MCP server from the agent's own configuration. If both are configured, the agent can simply use the unprotected one.

## REST

See [api.md](api.md). The minimal loop is one call:

```bash
curl -s -X POST localhost:8787/v1/actions/run -H "authorization: Bearer $AGENT" -H 'content-type: application/json' -d '{"action":{"action_id":"act_001","task_id":"task_123","tool_id":"crm.v1","operation":"crm.read","resource_id":"customer_42","destination_id":"crm.internal","arguments":{"customer_id":"customer_42"},"nonce":"3f9c2b1a7d5e4c60","expires_at":"2026-11-13T12:00:00Z"}}'
```

Use `/v1/actions/authorize` and `/v1/actions/execute` separately when a different component holds the permit and performs the execution step.

## In-process

```ts
import { DEFAULT_POLICY, Shield, ephemeralKeys, signBundle } from '../src/index.ts';

const keys = ephemeralKeys();
const shield = new Shield({ keys, twoPersonReview: false });
const TENANT = 'acme';

const admin = shield.authenticate(shield.identity.createPrincipal(TENANT, 'admin', 'admin'))!;
const operator = shield.authenticate(shield.identity.createPrincipal(TENANT, 'security', 'operator'))!;
const agent = shield.authenticate(shield.createPrincipal(admin, 'oscar', 'agent', { sponsor: 'alice' }))!;

shield.createPolicy(admin, signBundle(keys.policySigner!, DEFAULT_POLICY));
shield.activatePolicy(admin, DEFAULT_POLICY.policy_id, DEFAULT_POLICY.version);

shield.catalog.setDestination(TENANT, { destination_id: 'notes.internal', class: 'internal', state: 'approved', max_label: 'CONFIDENTIAL', accepts: [] });
const { tool } = shield.registerTool(admin, {
  tool_id: 'notes', kind: 'function', owner: 'me', destination_id: 'notes.internal',
  operations: { 'notes.get': { class: 'data_read', effect: 'read', resource_arg: 'id', input_schema: { type: 'object', required: ['id'], additionalProperties: false, properties: { id: { type: 'string' } } } } },
});
await shield.verifyTool(operator, 'notes', tool.schema_hash);
shield.functions.register('notes', (_operation, args) => ({ id: args.id, text: 'Quarterly notes.' }));

shield.createGrant(admin, {
  agent_id: 'oscar', task_id: 'task_1', expires_at: Date.now() + 3_600_000,
  scope: { tools: ['notes'], operations: ['notes.get'], resources: ['note-*'], destinations: ['notes.internal'] },
});

const { decision, execution } = await shield.run(agent, {
  action_id: 'act_1', task_id: 'task_1', tool_id: 'notes', operation: 'notes.get',
  resource_id: 'note-7', destination_id: 'notes.internal', arguments: { id: 'note-7' },
  nonce: crypto.randomUUID(), expires_at: new Date(Date.now() + 60_000).toISOString(),
});
console.log(decision.decision, execution?.state, execution?.result);
// allow succeeded { id: 'note-7', text: 'Quarterly notes.' }
```

`ephemeralKeys()` and the default in-memory store are for tests. For a persistent embedded gateway use `loadKeyDir(dir)` and `new Store(path)`, and leave `twoPersonReview` on. `startServer(shield, { port })` adds the REST interface to an embedded instance.

Embedding puts the gateway in the agent's process. That is convenient and it is not isolation: code in that process can read the keys. For a real boundary run the gateway as a separate, least-privileged process.

## Closing the bypass

Work through this before relying on the gateway.

1. **List every path to every protected tool**: provider SDKs, raw HTTP, shell commands, a browser, scheduled jobs, child agents, other MCP servers.
2. **Remove the credentials.** The agent runtime's environment, config files and secret store must not contain a credential for any protected tool. Only the gateway's `credential_ref` targets should.
3. **Restrict the network.** The agent runtime should be able to reach the gateway and its model provider, and nothing else that matters. If the model provider is itself a protected destination, route model calls through the gateway too.
4. **Separate the processes.** Run the gateway under a different OS user from the agent. The agent's user must not be able to read the gateway's data directory.
5. **Start in shadow.** Use `inspect` (which records nothing) alongside the existing direct calls to measure how many benign actions would be blocked. Fix grants, manifests and labels until that number is acceptable.
6. **Enforce one tool at a time.** Switch its calls to `execute`, remove its direct credential, and confirm the direct path now fails.
7. **Test the bypass.** From the agent's runtime, try to call each protected tool directly. Every attempt should fail for lack of a credential or a route.
8. **Reconcile.** Periodically compare the gateway's `execution.*` events with the downstream system's own logs. A downstream action with no matching receipt is a bypass.

### Notes for an OSCAR-style deployment

The report's reference deployment runs the gateway as a separate daemon on the same Mac as the agent. That maps to:

- `agentshield serve` on loopback TCP, which is what the SDKs and the MCP bridge speak. (`--socket` gives an owner-only Unix socket, but only for HTTP clients that support one; the SDKs do not yet.)
- The agent wraps its tool dispatcher and model client with the SDK. Policy logic does not go in a prompt.
- Provider tokens live only where the gateway's `credential_ref` entries point.
- The agent never receives redaction mappings (they stay in the vault) or audit administration.

This integration has not been built or tested. A host administrator on that Mac is outside the protection.
