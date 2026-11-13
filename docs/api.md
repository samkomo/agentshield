# REST API reference

Base URL: wherever `agentshield serve` is listening (default `http://127.0.0.1:8787`). All routes are under `/v1` except the MCP endpoint and the health check.

## Conventions

**Authentication.** `Authorization: Bearer <credential>` on every route except `GET /healthz`. The tenant and principal are taken from the credential. There is no tenant field in any request.

**Bodies.** `Content-Type: application/json`. Parsing is strict: duplicate keys, lone surrogates, a `__proto__` key or invalid UTF-8 give `400`. The body limit is 2 MiB (`413`).

**Errors.** Anything that is not a decision or an execution result looks like this:

```json
{ "error": { "code": "nonce_replay", "message": "This nonce has already been used.", "details": {} } }
```

A `block` decision is not an error. It is a `403` whose body is a normal decision.

**Timestamps.** Decisions, executions, events and reports use ISO 8601 strings. Stored records returned as-is (approvals, grants, agents, tools) use epoch milliseconds for `created_at`, `expires_at`, `decided_at` and `checked_at`.

**Roles and permissions.**

| Role | Permissions |
|---|---|
| `agent` | `agent:scan`, `agent:inspect`, `agent:execute`, `agent:request`, `agent:delegate` |
| `approver` | `operator:approve` |
| `operator` | `operator:approve`, `operator:block`, `operator:tools`, `operator:suspend` |
| `admin` | `admin:tools`, `admin:policy`, `admin:grants`, `admin:principals`, `admin:catalog` |
| `auditor` | `auditor:read`, `auditor:report` |

`vault:reveal` belongs to no built-in role.

**Rate limit.** 600 requests a minute per principal on agent-facing routes, with a burst of 100 (`429`).

## Status codes

| Code | Meaning | What to do |
|---|---|---|
| `200` | Allowed, or executed successfully | — |
| `201` | Created | — |
| `202` | Approval required; or an MCP notification was accepted | Wait for a person, then resubmit the same action |
| `400` | Malformed JSON or body | Fix the request |
| `401` | Missing or invalid credential | Re-authenticate |
| `403` | Blocked by policy; or this credential may not ask; or execution was denied after revocation | Do not retry; do not route around it |
| `404` / `405` | No such route or record / wrong method | — |
| `409` | Replay or conflict: nonce, idempotency key, action id, permit already used, revision mismatch | Reconcile; do not blindly retry |
| `413` / `415` / `422` | Too large / wrong media type / invalid field | Fix the request |
| `429` | Rate limited | Back off |
| `502` | The tool call definitely failed | The action did not happen |
| `503` | A required control could not run | Treat as a denial |
| `504` | Outcome unknown | **Do not retry.** An operator must reconcile |

## Actions

### `POST /v1/actions/authorize` — `agent:execute`

Body: `{ "action": <envelope>, "approval_id"?: string }`, or the bare envelope.

Envelope fields:

| Field | Required | Notes |
|---|---|---|
| `action_id` | yes | Unique per action. Reusing it with different content is `409 action_conflict` |
| `task_id` | yes | The task whose grant applies |
| `tool_id`, `operation` | yes | Must be in the registry and the grant |
| `resource_id` | yes | Must equal the argument the manifest names as `resource_arg`, if any |
| `destination_id` | yes | Must equal what `destination_arg` resolves to; otherwise the tool's own destination |
| `arguments` | yes | Object. At most 256 KiB canonical |
| `nonce` | yes | 8–128 characters. One use |
| `expires_at` | yes | ISO 8601, in the future, at most 15 minutes out (policy limit) |
| `idempotency_key` | no | One use. Forwarded to REST tools as `Idempotency-Key` |
| `tool_revision` | no | If given, must be the pinned revision |

Any other field is `422 unknown_field`.

Response (`200` for `allow` and `redact`, `202` for `require_approval`, `403` for `block`):

```json
{
  "decision": "allow",
  "decision_id": "dec_368d9b4bdacf8172883c4e29",
  "action_id": "act_1",
  "risk_level": "low",
  "risk_score": 17.8,
  "reason": "Within grant and policy.",
  "reasons": [{ "code": "within_grant", "message": "Within grant and policy." }],
  "policy_id": "agentshield-default",
  "policy_version": 1,
  "grant_revision": 1,
  "tool_revision": "sha256:188365f2…8fa7d1",
  "classification": "RESTRICTED",
  "finding_categories": [],
  "action_digest": "sha256:a53cb812…f77618",
  "expires_at": "2026-11-13T09:01:00.000Z",
  "permit": "eyJhbGciOiJFZERTQSIs…",
  "approval_id": null,
  "obligations": ["log_result", "validate_response"]
}
```

- `permit` is set only for `allow` and `redact`. `expires_at` is then the permit's expiry (60 seconds by default).
- For a tool of kind `external` the response has `"execution": "host"` and no permit: the caller runs the tool itself and reports back through the [host hooks](#host-hooks).
- For `require_approval`, `approval_id` is set and `expires_at` is when the approval request lapses.
- For `redact`, `transformed_action` holds the rewritten envelope. **That** is what the permit covers and what must be presented to `execute`.
- `reasons` lists every rule that applied. Codes are stable; see [Decision reason codes](#decision-reason-codes).

Resubmitting the same action:

| State of the action | Result |
|---|---|
| Awaiting approval | Same `require_approval`, same `approval_id` |
| Approved | A permit is issued (`allow`) |
| Permit already issued, not yet used | The same response, same permit |
| Blocked, executed, expired | `409 action_already_decided` |

### `POST /v1/actions/execute` — `agent:execute`

Body: `{ "action": <envelope>, "permit": string }`. The action must be byte-for-byte what was authorized (for `redact`, the `transformed_action`).

Response (`200` succeeded, `403` denied, `502` failed, `504` unknown):

```json
{
  "action_id": "act_1",
  "state": "succeeded",
  "result": { "ok": true },
  "untrusted_content": false,
  "injection": null,
  "finding_categories": [],
  "result_redacted": false,
  "error": null,
  "receipt": {
    "event_id": "evt_b819a12a6ea38d5887511a69",
    "sequence": 16,
    "action_digest": "sha256:a53cb812…f77618",
    "result_digest": "sha256:4062edaf…150f93",
    "provider_ref": null,
    "timestamp": "2026-11-13T09:00:00.000Z"
  }
}
```

- `state`: `succeeded`, `failed` (the tool did not act), `unknown` (a write may or may not have landed), `denied` (something was revoked after the permit was issued).
- `untrusted_content`: the result came from an MCP server or an external destination, or carries injection signals. Treat it as data.
- `injection`: `{ score, signals[] }` when any signal fired.
- `result_redacted`: credentials in the result were replaced with placeholders.
- `error`: `{ code, message }` for a failed, unknown or denied execution, or when the result was withheld (`invalid_response`, `result_too_large`).
- `receipt.event_id` is the signed audit event for this execution.

Errors before execution starts: `403 permit_invalid`, `403 permit_expired`, `409 action_mismatch`, `409 permit_replayed`.

`error.code` values in an execution response:

| Code | State | Meaning |
|---|---|---|
| `agent_revoked` | denied | The agent was suspended, or its revocation epoch changed, after the permit was issued |
| `grant_revoked` | denied | The grant or an ancestor was revoked, changed or expired |
| `tool_changed` | denied | The tool was re-registered, quarantined or revoked, or its MCP server drifted from the pin |
| `policy_revoked` | denied | The policy version the permit was decided under has been revoked |
| `credential_unavailable`, `no_handler`, `missing_path_argument`, `destination_changed` | failed | The call could not be made: no brokered credential, no in-process handler, a path argument missing, or a URL that left the registered host |
| `upstream_unavailable` | failed | The MCP server could not be started or connected to |
| `downstream_unreachable` | failed or unknown | A REST tool could not be reached. `failed` only when the request certainly never left |
| `downstream_rejected` | failed | A REST tool answered `4xx` |
| `downstream_error`, `upstream_error`, `tool_reported_error` | unknown for a write, failed for a read | The tool received the call and answered with an error, or did not answer |
| `execution_error` | unknown for a write, failed for a read | Any other failure during the call |
| `not_executed` | failed or denied | A host-executed tool was reported as never having run |
| `invalid_response`, `result_too_large` | unchanged | The result was withheld; the action's state stands |

### `POST /v1/actions/run` — `agent:execute`

Authorize and, if permitted, execute. Body as for `authorize`. Response: `{ "decision": <decision>, "execution": <execution> | null }`. The status is the execution's if there was one, otherwise the decision's. This is what the SDKs call.

### `POST /v1/tools/inspect` — `agent:inspect`

Evaluate without recording anything or consuming the nonce. Body as for `authorize`.

```json
{
  "decision": "allow",
  "risk": { "score": 17.8, "class": "low", "factors": [
    { "feature": "sensitivity", "weight": 25, "value": 0.71, "contribution": 17.9, "note": "data labelled RESTRICTED" },
    { "feature": "impact", "weight": 25, "value": 0, "contribution": 0, "note": "read only" },
    { "feature": "destination", "weight": 20, "value": 0, "contribution": 0, "note": "internal destination" },
    { "feature": "behavior", "weight": 15, "value": 0, "contribution": 0, "note": "no anomaly" },
    { "feature": "credential", "weight": 15, "value": 0, "contribution": 0, "note": "grant in good standing" }
  ]},
  "reasons": [{ "code": "within_grant", "message": "Within grant and policy." }],
  "findings": [],
  "tool_revision": "sha256:188365f2…8fa7d1",
  "classification": "RESTRICTED",
  "action_digest": "sha256:a53cb812…f77618"
}
```

`POST /v1/actions/risk` takes the same body and returns only `{ score, class, factors }`.

### `POST /v1/actions/{id}/block` — `operator:block`

Stop an action that is awaiting approval, approved, or permitted but not yet executed. Body: `{ "reason": string }`. Returns `{ "state": "denied", "event_id": … }`. Releases any reservation. `409 not_blockable` once execution has started.

### `POST /v1/actions/{id}/reconcile` — `operator:block`

Settle an action whose outcome is unknown, after checking the downstream system. Body: `{ "outcome": "succeeded" | "failed", "evidence": string }`. Commits or releases the reservation and returns the `execution.reconciled` event.

## Approvals

### `GET /v1/approvals/{id}` — `operator:approve`, or the requesting agent

```json
{
  "approval": {
    "approval_id": "apr_f161788949116a03e81c471b",
    "action_id": "act_2",
    "decision_id": "dec_2cc27748f0b4cd8bd641f7af",
    "action_digest": "sha256:577add43…6c6bc6",
    "requested_by": "oscar",
    "status": "pending",
    "decided_by": null,
    "expires_at": 1794560700000
  },
  "action": {
    "tool_id": "email", "operation": "email.send",
    "resource_id": "report.pdf", "destination_id": "partner.example",
    "arguments": { "recipient": "reviewer@partner.example", "body": "Please review.", "attachment": "report.pdf" },
    "actor_chain": ["alice", "oscar"]
  },
  "risk_level": "high",
  "reasons": [{ "code": "sensitive_external_send", "message": "Sending CONFIDENTIAL data outside the organisation is permitted only with approval." }]
}
```

An approver sees the full action. The requesting agent sees the approval's status with `action: null`.

Status values: `pending`, `approved`, `rejected`, `expired`, `consumed` (used to issue a permit), `superseded` (the action changed or was blocked).

### `POST /v1/approvals/{id}/decide` — `operator:approve`

Body: `{ "verdict": "approve" | "reject", "action_digest": string, "reason"?: string }`. `action_digest` must be the digest shown by `GET`; a mismatch is `409 digest_mismatch`. The requester cannot decide their own approval (`403 self_approval`).

### `GET /v1/approvals?status=pending` — `operator:approve`

Up to 200 most recent approvals, optionally filtered by status.

### `POST /v1/approvals` — `agent:request`

Look up the approval opened for a decision. Body: `{ "decision_id": string, "action_digest": string }`. Returns `{ approval_id, status, expiry }`. `authorize` already opens the request and returns its id; this route exists for callers that kept only the decision.

## Scanning

All take `{ "payload": string | JSON }` and need `agent:scan`. The payload limit is 1 MiB.

### `POST /v1/scan/input`

Scan content the agent pulled in from outside. Optional `task_id` and `source_id`. With `task_id`, the task's context records that it has seen untrusted content, the labels found and the injection score; the caller must hold a grant for that task (`403 no_active_grant`).

```json
{
  "scan_id": "scn_063e88d43450dd4d060df4e1",
  "findings": [{ "category": "PII", "type": "EMAIL", "start": 42, "end": 58, "byte_start": 42, "byte_end": 58, "confidence": 0.95, "detector": "patterns-1" }],
  "injection": { "score": 0.8, "signals": [{ "id": "instruction_override", "weight": 0.8 }] },
  "provenance": { "source_id": "https://forum.example/t/1", "trusted": false, "tainted": true },
  "model_version": "patterns-1"
}
```

`start`/`end` are UTF-16 offsets; `byte_start`/`byte_end` are offsets into the UTF-8 encoding. For a JSON payload each finding also has `path`, a JSON pointer. Findings never include the matched text.

### `POST /v1/scan/output`

Pre-flight check. Requires `destination_id`. Returns `{ scan_id, findings, verdict, model_version }` with `verdict` one of `allow`, `redact`, `block`. Advisory: the binding decision is still `authorize`.

### `POST /v1/detect/sensitive`

Optional `entity_types`: a list of finding types (`EMAIL`) or categories (`PII`) to keep. Returns `{ spans, model_version }`.

### `POST /v1/redact`

```json
{
  "scan_id": "scn_17f169cd28e4a90abcec05c6",
  "transformed_payload": "Contact [EMAIL_1] or [PHONE_1]",
  "digest": "sha256:b6fd56d0…ea81de",
  "findings": [ … ],
  "unresolved": 0,
  "model_version": "patterns-1"
}
```

`unresolved` counts findings that remain (those in object keys cannot be rewritten). With `task_id`, originals are sealed in the vault under the returned `scan_id`.

### `POST /v1/detect/injection`

Returns `{ score, signals, model_version }`. `score` is 0–1. Advisory only.

## Tool registry

### `POST /v1/tools` — `admin:tools`

Body: a [tool manifest](tools.md), or `{ "manifest": … }`. Returns `201`:

```json
{ "tool_id": "crm.v1", "revision": "sha256:…", "state": "pending", "warnings": [] }
```

`warnings` lists schema keywords the validator does not enforce and operations with no input schema. Registering an existing `tool_id` replaces the manifest and resets the tool to `pending`.

### `POST /v1/tools/{id}/verify` — `operator:tools`

Body: `{ "expected_revision": "sha256:…" }`. Approves that exact revision. The verifier must not be the registrant (`403 two_person_required`). For an MCP tool the live server is compared first: `409 upstream_drift` with the differences, or `503 upstream_unavailable`.

Returns `{ verified, schema_hash, state, checked_at }`.

### `POST /v1/tools/{id}/quarantine` — `operator:tools`

Body: `{ "reason": string }`. The tool stops being usable at once, including for permits already issued.

### `GET /v1/tools`, `GET /v1/tools/{id}` — `admin:tools`, `operator:tools` or `auditor:read`

States: `pending`, `approved`, `quarantined`, `revoked`.

## Policy

See [policy.md](policy.md) for the bundle format and lifecycle.

| Route | Permission | Body | Returns |
|---|---|---|---|
| `POST /v1/policies` | `admin:policy` | `{ bundle, signature, key_id }` as produced by `agentshield policy sign` | `201 { policy_id, revision, state: "draft", bundle_digest }` |
| `POST /v1/policies/{id}/test` | `admin:policy` | `{ revision, synthetic_cases: [{ name, agent_id, action, expect? }] }` | `{ results, total, passed, failed }` |
| `POST /v1/policies/{id}/activate` | `admin:policy` | `{ version }` | `{ policy_id, revision, state }` |
| `POST /v1/policies/{id}/revoke` | `admin:policy` | `{ version }` | `{ policy_id, revision, state: "revoked" }` |
| `GET /v1/policies` | `admin:policy` or `auditor:read` | — | `{ items }` (without bundle bodies) |

Activation must be by someone other than the version's author. `test` evaluates each case as the named agent against current grants, tools and catalog, and records nothing.

## Identity and grants

### `POST /v1/principals` — `admin:principals`

Body: `{ "principal_id", "role", "sponsor"?, "display_name"? }`. Returns `201 { principal_id, role, credential }`. The credential is shown once; only its hash is stored. Creating a principal with role `agent` also adds it to the agent inventory.

### `POST /v1/grants` — `admin:grants`

```json
{
  "agent_id": "oscar",
  "task_id": "task_123",
  "sponsor": "alice",
  "expires_at": "2026-12-31T00:00:00Z",
  "scope": {
    "tools": ["crm.v1"],
    "operations": ["crm.read"],
    "resources": ["customer_*"],
    "destinations": ["crm.internal"],
    "max_per_action_minor": 100000,
    "max_delegation_depth": 1
  },
  "budget_minor": 300000,
  "currency": "KES"
}
```

- Scope entries are a literal, `*`, or `prefix*`.
- `task_id` may be `*` to cover any task; a grant for the exact task takes precedence.
- `max_per_action_minor` and `budget_minor` are integers in minor units. Without them the grant authorizes no monetary action.
- `max_delegation_depth` defaults to 0: the agent may not delegate.

Returns `201` with the grant, including `grant_id` and `revision`.

### `POST /v1/grants/delegate` — `agent:delegate`

Body: `{ "parent_task_id": string, "grant": <as above> }`. The caller's live grant for `parent_task_id` is the parent. `403 delegation_denied` with `details.violations` listing each way the child exceeds it.

### `POST /v1/grants/{id}/revoke` — `admin:grants`

Revokes the grant and, in effect, everything delegated from it.

### `GET /v1/grants?agent_id=` — `admin:grants` or `auditor:read`

### Agents

| Route | Permission | Body | Returns |
|---|---|---|---|
| `GET /v1/agents` | `auditor:read`, `operator:suspend` or `admin:principals` | — | `{ items }` |
| `POST /v1/agents/{id}/suspend` | `operator:suspend` | `{ reason, expected_epoch? }` | `{ state, revocation_epoch }` |
| `POST /v1/agents/{id}/resume` | `operator:suspend` | `{}` | `{ state, revocation_epoch }` |
| `GET /v1/agents/{id}/risks?cursor=&limit=` | `auditor:read` | — | `{ items, next_cursor }` |

Suspension takes effect on new decisions and on permits already issued. Resuming does not revive those permits. `risks` lists decisions about the agent that were not a plain low-risk allow.

## Catalog

| Route | Permission | Body |
|---|---|---|
| `POST /v1/destinations` | `admin:catalog` | `{ destination_id, class: "internal" \| "external", state: "approved" \| "unreviewed" \| "blocked", max_label, accepts: [] }` |
| `GET /v1/destinations` | `admin:catalog` or `auditor:read` | — |
| `POST /v1/resource-labels` | `admin:catalog` | `{ pattern, labels: [] }` — an empty list removes the entry |
| `GET /v1/resource-labels` | `admin:catalog` or `auditor:read` | — |

`max_label` must be one of the policy's labels; an unrecognised value clears the destination for nothing. `accepts: ["PII"]` lets the destination receive personal data unredacted.

## Evidence

### `GET /v1/events?after=&limit=&agent_id=&action_id=&type=` — `auditor:read`

Returns `{ items, next_cursor }` in sequence order. Pass `next_cursor` as `after` for the next page. `agent_id` is matched through its pseudonym. `GET /v1/events/{id}` returns one event. The event format is in [architecture.md](architecture.md#audit).

Event types: `permit.issued`, `decision.allowed` (host-executed tools), `decision.blocked`, `decision.approval_required`, `approval.approved`, `approval.rejected`, `approval.host_approved`, `execution.succeeded`, `execution.failed`, `execution.unknown`, `execution.denied`, `execution.reconciled`, `action.blocked`, `scan.input_flagged`, `tool.registered`, `tool.verified`, `tool.quarantined`, `policy.created`, `policy.activated`, `policy.rolled_back`, `policy.revoked`, `grant.created`, `grant.delegated`, `grant.revoked`, `delegation.denied`, `agent.suspended`, `agent.resumed`, `principal.created`, `principal.credential_rotated`, `vault.reveal`.

### `POST /v1/audit/verify` — `auditor:read`

Body: `{ "checkpoints"?: [ … ] }`. Walks the chain and, if checkpoints are supplied, checks each is still present with the same digest.

```json
{
  "ok": true,
  "chain": { "ok": true, "events": 22, "head": { "sequence": 22, "event_digest": "sha256:e37e…1749" }, "error": null },
  "checkpoints": { "ok": true, "checked": 1, "problems": [] }
}
```

### `POST /v1/audit/checkpoint` — `auditor:report`

Signs the current head, appends it to the checkpoint sink, and returns it:

```json
{ "tenant_id": "acme", "sequence": 22, "event_digest": "sha256:e37e…1749", "timestamp": "2026-11-13T09:00:00.000Z", "key_id": "d0d4dc079ab1dd84", "signature": "XYMOyQpm…" }
```

### `POST /v1/reports` — `auditor:report`

Body: `{ "range": { "from": ISO, "to": ISO } }`. Returns a summary (`permits_issued`, `allowed_host_executed`, `blocked`, `approvals_required`, `approvals_granted`, `approvals_rejected`, `executions`, `executions_unknown`, `tools_quarantined`, `agents_suspended`), per-type event counts, chain integrity, `unresolved_actions`, and the active policy.

### `POST /v1/vault/reveal` — `vault:reveal`

Body: `{ task_id, scope_ref, placeholder }`, where `scope_ref` is the `action_id` (for a redacted action) or `scan_id` (for `/v1/redact`). Returns `{ value }` and appends a `vault.reveal` event.

## Host hooks

For agent runtimes that expose a hook before and after each tool call. The tool must be registered with kind `external`: the runtime executes it, the gateway decides and records. The [Hermes plugin](integration.md#hermes-plugin) is the client for these two routes.

### `POST /v1/hook/{tool_id}/before` — `agent:execute`

Body: `{ "tool_name": string, "args": object, "task_id"?: string, "dry_run"?: boolean }`. `task_id` is the runtime's session id; it is made safe to use as a task id, and defaults to `default`. The gateway builds the action itself, taking the resource and destination from the reviewed manifest.

```json
{
  "action": "modify",
  "action_id": "act_5f0c…",
  "decision": "redact",
  "decision_id": "dec_91ab…",
  "risk_level": "low",
  "reason": "Within grant and policy.",
  "reason_codes": ["within_grant"],
  "approval_id": null,
  "finding_categories": ["PII", "SECRET"],
  "args": { "query": "why is [GITHUB_TOKEN_1] rejected for [EMAIL_1]" }
}
```

| `action` | The runtime should |
|---|---|
| `allow` | Run the tool |
| `modify` | Run the tool with `args` in place of the original arguments |
| `approve` | Ask a person. `args` is present if the arguments were also rewritten |
| `block` | Not run the tool, and give the model `reason` |

With `dry_run: true` the answer is the same but nothing is recorded and there is no `action_id`.

### `POST /v1/hook/{tool_id}/after` — `agent:execute`

Body: `{ "action_id": string, "status": "ok" | "error" | "blocked", "result"?: any, "host_approved"?: boolean }`.

- `ok` and `error` mean the tool ran; `blocked` means it did not (a person refused, or something else in the runtime stopped it).
- `host_approved: true` is required to report a run for an action whose `before` answered `approve`. It is recorded as an approval given at the host.

Returns an [execution response](#post-v1actionsexecute--agentexecute) plus `tainted`: `result` is the copy that is safe to show the model, `result_redacted` says whether credentials were removed, and `tainted: true` means the content carries injection signals at or above the policy threshold.

Errors: `404 action_not_found` (not this agent's action, or not this tool), `409 not_host_executed` (the tool is not of kind `external`), `409 approval_required` (awaiting approval and `host_approved` was not set), `409 action_already_decided`.

## MCP endpoint

### `POST /mcp/{tool_id}` — `agent:execute`

JSON-RPC 2.0, one message or a batch. Header `X-AgentShield-Task: <task_id>` is required for `tools/list` and `tools/call`. Methods: `initialize`, `ping`, `tools/list`, `tools/call`; notifications get `202` with no body.

- `tools/list` returns the pinned definitions of operations the caller's grant covers.
- `tools/call` results carry `_meta` with `agentshield/action_id`, `agentshield/receipt`, `agentshield/untrusted`, and where relevant `agentshield/redacted` and `agentshield/injection_score`.
- A blocked call, a call needing approval, and a failed execution all return `isError: true` with a text explanation. Repeating a call that needs approval with identical arguments, after approval, executes it.

## Decision reason codes

| Code | Outcome | Meaning |
|---|---|---|
| `within_grant` | allow | Passed every check |
| `no_active_policy` | block | No signed policy is active |
| `agent_unknown`, `agent_suspended` | block | Agent not in the inventory, or suspended |
| `no_active_grant` | block | No live grant for this agent and task |
| `outside_grant` | block | Tool, operation, resource or destination not in the grant (the message says which) |
| `tool_unregistered`, `tool_not_approved`, `tool_expired` | block | Tool missing from the registry, not in state `approved`, or past its `expires_at` |
| `tool_revision_mismatch` | block | Caller named a revision other than the pin |
| `operation_unknown` | block | Operation not in the reviewed manifest |
| `binding_mismatch` | block | `resource_id` or `destination_id` disagrees with the arguments or the tool's registration |
| `operation_class_denied` | block | Policy denies this class to agents |
| `invalid_arguments` | block | Arguments fail the operation's input schema |
| `invalid_amount`, `amount_required` | block | Amount not an integer in minor units, bad currency, or missing where required |
| `no_spending_authority`, `currency_mismatch` | block | Grant chain has no budget or per-action limit, or a different currency |
| `exceeds_per_action_limit`, `budget_exceeded` | block | Over the per-action limit, or over the remaining shared budget |
| `destination_unknown`, `destination_not_approved` | block | Destination not in the catalog, or not approved |
| `label_exceeds_destination` | block | Resource or task labels are above the destination's ceiling |
| `secret_in_payload`, `pii_in_payload` | block | Prohibited content that cannot be redacted here |
| `redaction_unresolved` | block | Prohibited content remained after redaction |
| `risk_critical` | block | Risk score at or above the critical threshold |
| `approval_rejected` | block | An approver rejected the action |
| `tainted_task` | approval or block | The task ingested content with injection signals |
| `class_requires_approval`, `tool_requires_approval` | approval | Required by policy for the class, or by the tool's manifest |
| `risk_high` | approval | Risk score at or above the high threshold |
| `sensitive_external_send` | approval | Sensitive data to an external destination |
| `sensitive_write` | approval | Write to a record with a sensitive label |
