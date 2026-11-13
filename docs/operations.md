# Operations runbook

How to install, run and look after a gateway, and what to do when something goes wrong.

## Install

Node.js 24 or later and Git. Nothing else.

```bash
curl -fsSL https://raw.githubusercontent.com/samkomo/agentshield/main/install.sh | bash
```

This puts a checkout in `~/.local/share/agentshield` and an `agentshield` command in `~/.local/bin`; see the [install guide](install.md). The gateway runs its `.ts` sources directly, so there is nothing to build. In a checkout you cloned yourself, `node src/cli.ts` is the same command.

## Initialise

```bash
node src/cli.ts init --dir /var/lib/agentshield --tenant default
```

Every command takes `--dir`. Without it the data directory is `$AGENTSHIELD_HOME`, or `~/.agentshield`. `agentshield up` runs `init` if the directory is new and then `serve`.

This creates, readable only by the user that ran it:

```
/var/lib/agentshield/
  agentshield.db                 state, intents, events
  config.json                    the tenant this directory was created for
  bootstrap-credentials.json     admin, security (operator) and auditor credentials
  agents/<id>.token              agent credentials written by `connect` (owner-only)
  keys/
    permit.key  permit.pub       signs / verifies execution permits
    event.key   event.pub        signs / verifies audit events and checkpoints
    vault.key                    seals redaction mappings
    telemetry.key                keys the pseudonyms in events
    policy-signing.key           signs policy bundles — move this off the host
    trust/policy-<id>.pub        public keys trusted to sign policy
  checkpoints.jsonl              appears once the first checkpoint is written
```

`init` signs and activates the default policy and records that as a bootstrap activation. It refuses to run on a directory that already has keys.

### Straight after `init`

1. **Take the credentials out of `bootstrap-credentials.json`** into your secret store, hand each to a different person, and delete the file. Credentials cannot be recovered; only their hashes are stored.
2. **Move `keys/policy-signing.key` off the gateway host.** The gateway needs only `keys/trust/*.pub`. Whoever holds this key decides what policy can say.
3. **Back up `keys/`** somewhere separate from the database backup. Losing `event.key` means earlier events can no longer be verified by this gateway; losing `vault.key` makes redaction mappings unreadable.
4. **Arrange for `checkpoints.jsonl` to leave the host** (below).

## Run

```bash
node src/cli.ts serve --dir /var/lib/agentshield --port 8787
```

| Flag | Default | Meaning |
|---|---|---|
| `--dir` | `.agentshield` | Data directory |
| `--host` | `127.0.0.1` | Listen address |
| `--port` | `8787` | Listen port |
| `--socket PATH` | — | Listen on a Unix socket instead, made owner-only |
| `--no-two-person` | off | Let one person both register and verify tools, and author and activate policy. For development only |

- **Run it as its own OS user.** The agent's user must not be able to read the data directory.
- **Keep it on loopback or a Unix socket.** There is no TLS. To serve other hosts, put a TLS-terminating proxy in front and treat that as part of the trusted base. The SDKs and the MCP bridge speak HTTP over TCP; the Unix socket is for clients that support one (`curl --unix-socket`).
- **Environment.** Any variable a tool's `credential_ref` names (`env:CRM_API_TOKEN`) must be set for the gateway process, and for nothing the agent runs as.
- **Supervision.** `agentshield service install` registers a per-user launchd agent (macOS) or systemd user unit (Linux) that starts at login and is restarted if the gateway exits with an error; `service status` and `service uninstall` are its counterparts. It writes to `gateway.log` in the data directory. Under any other supervisor, run `agentshield serve` and restart on exit. The gateway handles `SIGTERM` by closing connections, writing a checkpoint and exiting.
- **One process per data directory.** Running two against the same database is not tested.

Health: `GET /healthz` returns `200 {"status":"ok"}` without authentication.

Every 30 seconds the gateway expires unused permits and approvals (releasing their budget) and purges expired vault entries. Every 5 minutes, and at shutdown, it writes an audit checkpoint for each tenant whose chain has grown.

## Onboarding

In order, with the roles that can do each:

| Step | Who | How |
|---|---|---|
| Register destinations | admin | `POST /v1/destinations` |
| Label resources | admin | `POST /v1/resource-labels` |
| Register a tool | admin | `POST /v1/tools` — [tools.md](tools.md) |
| Verify the tool | operator | `POST /v1/tools/{id}/verify` |
| Create the agent | admin | `POST /v1/principals` with `role: "agent"`; give the credential to the agent's runtime only |
| Issue a grant | admin | `POST /v1/grants` — as narrow as the task |
| Create approvers | admin | `POST /v1/principals` with `role: "approver"` |

Then follow [Closing the bypass](integration.md#closing-the-bypass).

## Routine tasks

### Verify the audit chain

```bash
node src/cli.ts audit verify --dir /var/lib/agentshield --tenant default
```

Prints the event count and head digest, checks every checkpoint in `checkpoints.jsonl`, and exits non-zero if either check fails. Run it on a schedule. Run it against your **off-host** copy of the checkpoints as well, through `POST /v1/audit/verify`, since a local attacker could rewrite the local file.

### Ship checkpoints off the host

`checkpoints.jsonl` is append-only JSON lines. Copy or stream it to storage the gateway's OS user cannot modify — object storage with retention, a log collector, another machine. The CLI always writes to `<dir>/checkpoints.jsonl`; an embedded gateway can set `checkpointSink` to any path.

A checkpoint is useless for detecting truncation if the attacker can rewrite it too.

### Back up

- **Database:** `agentshield.db` uses write-ahead logging. Back up with `sqlite3 agentshield.db ".backup '/path/backup.db'"`, or stop the gateway and copy the file. Copying a live database file directly can produce a corrupt copy.
- **Keys:** separately, and encrypted.
- **Restore:** stop the gateway, put the files back, start it, run `audit verify`. Events after the backup are gone; your off-host checkpoints will say so.

### Review

- `GET /v1/approvals?status=pending` — is anyone waiting?
- `POST /v1/reports` for the last day — look at `blocked`, `executions_unknown`, `tools_quarantined` and `unresolved_actions`.
- `GET /v1/agents/{id}/risks` for agents with rising denial counts.
- `GET /v1/tools` — anything `pending` or `quarantined`?
- Grants close to expiry or broader than their task: `GET /v1/grants`.

### Connect or renew a Hermes agent

```bash
agentshield connect hermes
```

Finds Hermes, registers the Hermes tool preset and destinations, creates the agent with a standing grant (90 days; `--days` to change), installs the plugin through Hermes and tests it. Running it again changes only what is missing, so it is also how you renew an expired grant or pick up a newer preset or plugin. `--rotate` issues a new credential and invalidates the old one. When the agent runs in another account, `agentshield enroll hermes` does the gateway's half. See the [install guide](install.md).

When the grant expires every tool call is blocked with `no_active_grant` until it is renewed. `agentshield doctor` warns from 14 days before.

### Check an installation

```bash
agentshield doctor
```

Checks the gateway, the service, each connected agent's grant, and — where Hermes is installed in this account — the plugin, the credential and a test call. It exits non-zero if anything failed and names the command that fixes it. Run it after `hermes update`: Hermes disables a plugin that no longer fits a new release, and a disabled plugin checks nothing.

### Change policy

Author, sign, create, test, activate with a second administrator: [policy.md](policy.md#lifecycle).

### Add a policy signing key

```bash
openssl genpkey -algorithm ed25519 -out policy-signing-2027.key
```

```bash
openssl pkey -in policy-signing-2027.key -pubout -out /var/lib/agentshield/keys/trust/policy-2027.pub
```

Restart the gateway; trust roots are read at start. To retire a key, remove its `.pub` and restart. A policy that was active and signed by a removed key stops loading, which denies everything until a policy signed by a trusted key is activated — so activate the replacement first.

## Incidents

### An agent is misbehaving or its credential may be stolen

```bash
curl -s -X POST localhost:8787/v1/agents/oscar/suspend -H "authorization: Bearer $SECURITY" -H 'content-type: application/json' -d '{"reason":"credential may be exposed"}'
```

Takes effect immediately: new decisions are blocked, and permits already issued stop executing. Then:

1. `GET /v1/events?agent_id=oscar` — what it did and tried to do.
2. `POST /v1/reports` — any `unresolved_actions` for it; reconcile those.
3. Revoke its grants: `POST /v1/grants/{id}/revoke`.
4. Issue a new principal with a new credential rather than resuming, if the credential was exposed. (There is no credential-rotation route; `resume` re-enables the same credential.)

### A tool is returning suspicious results, or its server changed

```bash
curl -s -X POST localhost:8787/v1/tools/files/quarantine -H "authorization: Bearer $SECURITY" -H 'content-type: application/json' -d '{"reason":"unexpected instructions in results"}'
```

An MCP tool whose live definitions drift is quarantined automatically; look for `tool.quarantined` events, whose detail names what changed. To restore a tool: review it, register the manifest again (even unchanged), and have a second person verify it. Rotate the tool's downstream credential if the server may have been compromised.

### An action's outcome is unknown

A write was sent and no trustworthy answer came back (`504`, state `unknown`). The gateway will not retry it and keeps any budget reserved.

1. Find it: `POST /v1/reports` → `unresolved_actions`, or `GET /v1/events?type=execution.unknown`.
2. Check the downstream system. Use the action's `idempotency_key` and the receipt's `provider_ref` if the provider supports lookup by either.
3. Record what you found:

```bash
curl -s -X POST localhost:8787/v1/actions/act_h2/reconcile -H "authorization: Bearer $SECURITY" -H 'content-type: application/json' -d '{"outcome":"failed","evidence":"provider has no transaction for idempotency key task_9-pay-3"}'
```

`succeeded` commits the reservation; `failed` releases it. The agent may then submit a **new** action if the work still needs doing.

The same applies to an action left in `executing` because the gateway stopped mid-call.

### A decided action must not run

```bash
curl -s -X POST localhost:8787/v1/actions/act_42/block -H "authorization: Bearer $SECURITY" -H 'content-type: application/json' -d '{"reason":"recipient under investigation"}'
```

Works while the action is awaiting approval, approved, or permitted but not yet executed.

### A policy change went wrong

Activate the previous version (a second administrator, as always):

```bash
curl -s -X POST localhost:8787/v1/policies/agentshield-default/activate -H "authorization: Bearer $ADMIN2" -H 'content-type: application/json' -d '{"version":1}'
```

If the bad version must never be used again, revoke it. Revoking the *active* version denies everything until another is activated, so activate first, then revoke.

### `audit verify` fails

- **Chain broken at sequence N:** the event at N, or the link into it, was altered, removed or reordered. Everything before N is intact; treat everything from N on as untrusted.
- **Checkpoint missing or different:** history was truncated or rewritten after that checkpoint was taken.

In both cases: stop the gateway, preserve the database file and checkpoints as they are, restore from the last backup that verifies, and reconcile the gap against downstream systems' own logs. Assume whoever did it had write access to the database, which means the gateway's OS user or root.

### Everything is being blocked

| Reason code in the response | Likely cause |
|---|---|
| `no_active_policy` | No policy activated; the active one was revoked; its signing key is no longer in `keys/trust/`; or the stored bundle was modified |
| `no_active_grant` | Grant expired or revoked, or a parent grant was |
| `tool_not_approved` | Tool re-registered and not yet verified, or quarantined |
| `destination_unknown` | Destination not in the catalog |
| `binding_mismatch` | The agent's `destination_id` or `resource_id` does not match its arguments; usually an integration bug |
| `label_exceeds_destination` | The task has read something more sensitive than this destination may receive; start a new task for unrelated work |
| `503 control_unavailable` | An internal error. The gateway's standard error has the stack trace |

## What is not here yet

Known operational gaps, so they are not discovered during an incident:

- No credential rotation route (`connect hermes --rotate` or `enroll hermes --rotate` rotates a Hermes agent's), and no route to disable a non-agent principal.
- No way to create principals in a second tenant over REST; `init` creates the first tenant's.
- The checkpoint sink path is fixed when using the CLI.
- No built-in notification when an approval is waiting.
- No metrics endpoint or log export.
- No automatic reconciliation with downstream systems.
- No rotation procedure for the event key that keeps earlier events verifiable by the built-in verifier.
