# Policy

A policy is a signed JSON bundle. It holds no code: it is thresholds, a label ordering and per-class rules, interpreted by a fixed evaluator ([src/policy/engine.ts](../src/policy/engine.ts)). The built-in default is [policies/default.policy.json](../policies/default.policy.json).

What the policy cannot do is as important as what it can. No setting makes an action outside its grant executable, lets approval override a budget, or allows a secret through unredacted. Those are in the evaluator, not the bundle.

## Lifecycle

```
author bundle.json ──► sign ──► create (draft) ──► test ──► activate (second admin) ──► active
                                                                 │
                                    rollback: activate an older, non-revoked version
                                    revoke: bar a version permanently
```

1. **Author.** Copy the default, bump `version`, edit. Keep it in version control.
2. **Sign** with the policy key:

   ```bash
   node src/cli.ts policy sign my-policy.json --dir .agentshield --out my-policy.signed.json
   ```

   In production the signing key should not be on the gateway host; pass `--key /path/to/policy-signing.key` wherever it lives. The gateway needs only the public half in `keys/trust/`.
3. **Create.** `POST /v1/policies` with the signed file. The gateway rejects an unknown signer, a bundle altered after signing, a structurally invalid bundle, and a `(policy_id, version)` that already exists. Versions are immutable.
4. **Test.** `POST /v1/policies/{id}/test` with synthetic cases. Each case is evaluated as a named agent against the real grants, registry and catalog, with the draft policy substituted. Nothing is recorded.

   ```json
   {
     "revision": 2,
     "synthetic_cases": [
       { "name": "CRM read still allowed", "agent_id": "oscar", "expect": "allow",
         "action": { "action_id": "t1", "task_id": "task_123", "tool_id": "crm.v1", "operation": "crm.read", "resource_id": "customer_42", "destination_id": "crm.internal", "arguments": { "customer_id": "customer_42" }, "nonce": "test-nonce-1", "expires_at": "2026-11-13T12:00:00Z" } }
     ]
   }
   ```

   The response gives each case's actual decision, risk level and reason codes, and whether it matched `expect`. Each case's `expires_at` must be a real future time within the action TTL, as for a live action.
5. **Activate.** `POST /v1/policies/{id}/activate` with `{ "version": 2 }`, by an administrator other than the one who created that version. One version is active per tenant; the previous one becomes `retired`.
6. **Roll back** by activating an older version. It is recorded as `policy.rolled_back`.
7. **Revoke** a version to bar it for good. A revoked version cannot be activated, and permits decided under it stop executing. Revoking the active version leaves no policy, which denies everything until another is activated.

The stored bundle's signature is re-verified when it is loaded. A row edited directly in the database is not trusted, and the tenant falls back to deny-all.

## Bundle reference

```json
{
  "policy_id": "agentshield-default",
  "version": 1,
  "description": "…"
}
```

### `label_order`

```json
["PUBLIC", "INTERNAL", "PERSONAL", "FINANCIAL", "CONFIDENTIAL", "RESTRICTED", "SECRET", "CRITICAL"]
```

Ascending sensitivity. Labels are yours to define; the evaluator only compares positions. A label on **data** that is not in this list is treated as the most sensitive. A destination `max_label` that is not in this list clears the destination for nothing.

### `detection`

| Field | Default | Meaning |
|---|---|---|
| `min_confidence` | `0.6` | Findings below this are ignored |
| `finding_labels` | `{ "SECRET": "SECRET", "PII": "PERSONAL" }` | The label a finding category implies for the payload it is in |

### `data_flow`

| Field | Default | Meaning |
|---|---|---|
| `secrets` | `"redact"` | `redact` or `block`. There is no `allow` |
| `pii` | `"redact"` | `redact`, `block` or `allow`. A destination with `accepts: ["PII"]` receives personal data regardless |
| `external_approval_label` | `"CONFIDENTIAL"` | Sending this label or above to an external destination needs approval |
| `write_approval_label` | `"PERSONAL"` | A `data_write` on a resource with this label or above needs approval |
| `propagate_task_labels_to` | `["egress", "model"]` | For these operation classes, labels the task has already seen count against the destination's ceiling |
| `destination_required_for` | `["egress", "model", "payment"]` | For these classes the destination must be in the catalog and approved |

Redaction applies only where the operation's class allows it (below). Where it does not, a finding that would have been redacted blocks the action instead.

### `operation_classes` and `default_class`

Each operation in a tool manifest declares a `class`. The policy says what each class needs:

```json
{
  "data_read":   { "approval": "risk",   "redaction": "allow" },
  "data_write":  { "approval": "risk",   "redaction": "forbid" },
  "egress":      { "approval": "risk",   "redaction": "allow" },
  "model":       { "approval": "risk",   "redaction": "allow" },
  "payment":     { "approval": "risk",   "redaction": "forbid", "requires_amount": true },
  "admin":       { "approval": "always", "redaction": "forbid" },
  "physical":    { "approval": "always", "redaction": "forbid" },
  "audit_admin": { "approval": "always", "redaction": "forbid", "deny": true }
}
```

| Field | Values | Meaning |
|---|---|---|
| `approval` | `never`, `risk`, `always` | `risk`: approval only when the risk score is high. `never` suppresses that, but not the other approval rules |
| `redaction` | `allow`, `forbid` | Whether arguments may be rewritten. Forbid it where a rewritten argument changes what the action means |
| `deny` | boolean | Operations of this class are unavailable to agents |
| `requires_amount` | boolean | The action must carry an integer amount and a currency |

`default_class` applies to any class not listed. The default is the strict one: `{ "approval": "always", "redaction": "forbid" }`.

Class names are free text. Add your own and reference them from manifests.

### `injection`

| Field | Default | Meaning |
|---|---|---|
| `taint_threshold` | `0.6` | A task is tainted once it has ingested content scoring at or above this |
| `tainted_write` | `"require_approval"` | What a write needs in a tainted task: `allow`, `require_approval` or `block` |

### `risk`

```json
{
  "weights": { "sensitivity": 25, "impact": 25, "destination": 20, "behavior": 15, "credential": 15 },
  "thresholds": { "moderate": 25, "high": 50, "critical": 75 },
  "rate_baseline_per_minute": 60
}
```

Weights must be non-negative and total 100. Thresholds must ascend.

### `limits`

| Field | Default | Meaning |
|---|---|---|
| `max_action_ttl_seconds` | `900` | Furthest an action's `expires_at` may be |
| `permit_ttl_seconds` | `60` | Lifetime of a permit |
| `approval_ttl_seconds` | `900` | Lifetime of an approval request (never beyond the action's expiry) |
| `max_arguments_bytes` | `262144` | Canonical size of `arguments` |
| `max_result_bytes` | `1048576` | Tool results and scan payloads |
| `max_delegation_depth` | `3` | Longest delegation chain |
| `execution_timeout_ms` | `30000` | Tool call timeout |

## How risk is scored

`R = Σ wᵢ · xᵢ`, each `xᵢ` in 0–1, giving 0–100 ([src/policy/risk.ts](../src/policy/risk.ts)).

| Feature | `x` |
|---|---|
| `sensitivity` | Position of the highest label, as a fraction of the scale; `1` for an operation the manifest marks `privileged` |
| `impact` | `0` for a read. For a write: `0.4` reversible, `0.7` irreversible, `0.8` for class `payment` or `physical`; raised toward `1` as the amount approaches the per-action limit. `1` when operation metadata is unknown |
| `destination` | `0` internal, `0.5` approved external, `1` unknown or unapproved |
| `behavior` | The largest of: actions in the last minute over the baseline; denials in the last ten minutes over five; the task's highest injection score |
| `credential` | `0.5` when there is no grant, or less than a tenth of its lifetime remains |

| Class | Score | Effect |
|---|---|---|
| low | below 25 | Allowed |
| moderate | 25–49 | Allowed, with a `scan_result` obligation |
| high | 50–74 | Approval required (unless the class says `approval: never`) |
| critical | 75 and above | Blocked |

The score ranks actions that are otherwise permitted. It adds approvals and blocks; it never removes a denial, and a low score never widens a grant. Every input comes from the registry, the catalog, the grant or measured behaviour.

The weights and thresholds are starting values. They have not been calibrated against labelled decisions.

## What requires approval

Any one of these is enough:

- The operation's class has `approval: "always"`.
- The tool manifest marks the operation `approval: "always"`. Policy cannot remove this.
- Risk is high and the class is not `approval: "never"`.
- The destination is external and the data's label is at or above `external_approval_label`.
- The operation is a `data_write` and the resource's label is at or above `write_approval_label`.
- The operation is a write, the task is tainted, and `tainted_write` is `require_approval`.

## Worked example: tightening model egress

To send nothing above `INTERNAL` to any model, and to block rather than redact personal data:

```json
{
  "policy_id": "agentshield-default",
  "version": 2,
  "data_flow": { "secrets": "block", "pii": "block", "…": "…" },
  "operation_classes": { "model": { "approval": "risk", "redaction": "forbid" }, "…": "…" }
}
```

with every other section of the bundle carried over unchanged (a bundle must be complete), and in the catalog set each model destination's `max_label` to `INTERNAL`. Then test with a case that sends a confidential resource to the model and `expect: "block"` before activating.
