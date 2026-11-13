# Registering tools

A tool is anything an agent can act through: a REST API, an MCP server, or an in-process function. Nothing is callable until it is in the registry, at a revision someone other than the registrant has verified.

## The manifest

```json
{
  "tool_id": "mail.v1",
  "kind": "http",
  "owner": "it-platform",
  "publisher": "Example Mail Ltd",
  "description": "Outbound mail through the company relay.",
  "destination_id": "mail.internal",
  "endpoint": { "base_url": "https://mail.internal.example/api" },
  "credential_ref": "env:MAIL_API_TOKEN",
  "expires_at": "2027-06-30T00:00:00Z",
  "operations": {
    "email.send": {
      "description": "Send one message with at most one attachment.",
      "class": "egress",
      "effect": "write",
      "reversible": false,
      "resource_arg": "attachment",
      "destination_arg": "recipient",
      "destination_from": "email_domain",
      "http": { "method": "POST", "path": "/messages" },
      "input_schema": {
        "type": "object",
        "required": ["recipient", "body", "attachment"],
        "additionalProperties": false,
        "properties": {
          "recipient": { "type": "string", "maxLength": 254 },
          "subject": { "type": "string", "maxLength": 200 },
          "body": { "type": "string", "maxLength": 20000 },
          "attachment": { "type": "string" }
        }
      }
    }
  }
}
```

### Tool fields

| Field | Required | Meaning |
|---|---|---|
| `tool_id` | yes | Letters, digits and `. _ : / -`, up to 128 characters |
| `kind` | yes | `http`, `mcp` or `function` |
| `owner` | yes | Who answers for this tool |
| `publisher`, `description` | no | For the reviewer |
| `destination_id` | yes | Where calls to this tool land, as an entry in the destination catalog |
| `endpoint` | by kind | See below |
| `credential_ref` | no | `env:NAME` or `file:/absolute/path`. Resolved inside the gateway at call time. Never a literal secret |
| `credential_header` | no | For `http`: send the credential in this header as-is, instead of `Authorization: Bearer …` |
| `expires_at` | no | The approval lapses at this time |
| `operations` | yes | At least one |

### Operation fields

| Field | Required | Meaning |
|---|---|---|
| `class` | yes | Which policy rule applies: `data_read`, `data_write`, `egress`, `model`, `payment`, `admin`, `physical`, or your own |
| `effect` | yes | `read` or `write`. Drives risk and how failures are classified |
| `reversible` | no | For writes; lowers impact when true |
| `privileged` | no | Scores sensitivity at maximum |
| `approval` | no | `"always"`: the tool owner requires a person for every call. Policy cannot remove it |
| `input_schema` | no, but give one | JSON Schema for `arguments`. This is how an operating envelope is enforced (a setpoint range, an allowed enum) |
| `output_schema` | no | JSON Schema for the result. A result that does not match is withheld from the agent |
| `resource_arg` | no | The argument that names the resource. The envelope's `resource_id` must equal it |
| `destination_arg` | no | The argument that says where data goes. The envelope's `destination_id` must equal what it resolves to |
| `destination_from` | no | How to read `destination_arg`: `value` (default), `email_domain`, `url_host` |
| `amount_arg`, `currency_arg` | no | Arguments holding the amount (integer minor units) and currency. Default `amount_minor` and `currency` for class `payment` |
| `http` | for `http` | `{ "method": "GET" \| "POST" \| "PUT" \| "PATCH" \| "DELETE", "path": "/…" }` |
| `description` | no | For MCP tools this is part of the pin |

### Why the binding arguments matter

Every destination rule — the grant, the catalog, the label ceiling, approval — judges the envelope's `destination_id`. Without `destination_arg`, nothing ties that field to where the call will actually send data: an agent could write `partner.example` in the envelope and an attacker's address in `recipient`.

- Set `destination_arg` on every operation where an argument chooses the recipient, beneficiary, channel or URL.
- When an operation has no `destination_arg`, the only valid `destination_id` is the tool's own `destination_id`.
- Set `resource_arg` wherever an argument chooses the record or file, so that resource labels apply to the thing actually touched.
- If `destination_arg` is a list, every entry must resolve to the same destination. Send one action per destination.

Personal data in these two arguments is not redacted (a recipient address is personal data by construction). Credentials found there still block.

### Supported JSON Schema

`type`, `properties`, `required`, `additionalProperties`, `items`, `enum`, `const`, `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `multipleOf`, `minLength`, `maxLength`, `pattern`, `minItems`, `maxItems`, `uniqueItems`, `allOf`, `anyOf`, `oneOf`, `not`.

Anything else (`$ref`, `if`/`then`, `patternProperties`, `format` as a constraint) is **not enforced**. Registration returns a `warnings` list naming each unenforced keyword and each operation with no input schema, so a reviewer knows what is and is not being checked.

## Kinds

### `http`

`endpoint.base_url` is required and may not embed credentials. Each operation needs `http.method` and `http.path`.

- `{name}` in the path is filled from the argument of that name, percent-encoded, and removed from the body. An argument cannot change the host.
- `GET` and `DELETE` send the remaining scalar arguments as query parameters; other methods send them as a JSON body.
- The credential goes in `Authorization: Bearer …` (or `credential_header`). The envelope's `idempotency_key` goes in `Idempotency-Key`.
- Redirects are errors.
- `2xx` is success. `4xx` is a definite failure. `5xx`, a timeout or a dropped connection on a **write** is an unknown outcome; on a read it is a failure. A response `X-Request-Id` is recorded in the receipt as `provider_ref`.

### `mcp`

```json
{
  "tool_id": "files",
  "kind": "mcp",
  "owner": "it",
  "destination_id": "files.local",
  "endpoint": { "transport": "stdio", "command": "/usr/local/bin/files-mcp", "args": ["--root", "/srv/docs"], "env": ["FILES_LICENSE"] },
  "operations": {
    "read_file": {
      "description": "Read a file from the shared docs folder.",
      "class": "data_read",
      "effect": "read",
      "resource_arg": "path",
      "input_schema": { "type": "object", "required": ["path"], "additionalProperties": false, "properties": { "path": { "type": "string" } } }
    }
  }
}
```

- `transport: "stdio"` needs `command`; `args` and `env` are optional. The process is started with `PATH` and only the gateway environment variables named in `env`. It does not inherit the rest.
- `transport: "http"` needs `url` (streamable HTTP; JSON and event-stream replies are both handled). `credential_ref` is sent as a bearer token. The agent's own credential is never forwarded upstream.
- Each operation key is an upstream tool name. Its `description` and `input_schema` must be **exactly** what the server reports, because together with the name they are the pin. Copy them from the server's `tools/list`.
- Tools the server offers that are not in the manifest are never exposed and cannot be called.

Verification fetches the live definitions and refuses on any difference. After approval the comparison repeats, at most once a minute, whenever the tool is listed or called. A difference quarantines the tool: agents see an empty tool list, calls are blocked, and permits already issued stop executing.

### `function`

In-process handlers, for embedding the gateway in an application and for tests:

```ts
shield.functions.register('notes', async (operation, args, action) => {
  return { ok: true };
});
```

The manifest needs no `endpoint`. Not available when running `agentshield serve`.

## Registering and verifying

```bash
curl -s -X POST localhost:8787/v1/tools -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' -d @examples/crm-tool.json
```

The response gives `revision` (the manifest hash) and `warnings`. A second person, with `operator:tools`, reviews the manifest and approves that revision:

```bash
curl -s -X POST localhost:8787/v1/tools/crm.v1/verify -H "authorization: Bearer $SECURITY" -H 'content-type: application/json' -d '{"expected_revision":"sha256:…"}'
```

If the manifest was replaced between review and approval, `expected_revision` no longer matches and the approval fails with `409 revision_conflict`.

Changing anything in a manifest means registering it again, which puts the tool back to `pending` until re-verified. Approvals granted to agents for actions on the old revision no longer apply, because the tool revision is part of the action digest.

## What to check when reviewing a manifest

- Does every operation that sends data somewhere have `destination_arg`?
- Does every operation that touches a specific record have `resource_arg`?
- Is `effect` right? Marking a write as a read hides it from approval rules and makes failures look harmless.
- Is the `class` the strictest one that fits?
- Does `input_schema` set `additionalProperties: false` and bound every string and number that matters?
- Are there any `warnings`?
- Is the credential scoped to what these operations need, and stored only where `credential_ref` points?
- For MCP: does the description contain instructions addressed to a model? Descriptions are shown to agents.

## Destinations and labels

Tools reference destinations; register those too.

```bash
curl -s -X POST localhost:8787/v1/destinations -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' -d '{"destination_id":"partner.example","class":"external","state":"approved","max_label":"CONFIDENTIAL","accepts":[]}'
```

```bash
curl -s -X POST localhost:8787/v1/resource-labels -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' -d '{"pattern":"customer_*","labels":["RESTRICTED"]}'
```

For `email_domain` the destination id is the domain (`partner.example`); for `url_host` it is the host name. A resource's labels are the union of every pattern that matches it.

## What a pin does and does not prove

A pin proves that the tool is the artifact and configuration someone reviewed. It does not prove the tool behaves well. A server that changes what it *does* without changing its metadata is not detected here. The controls for that are the scoped credential, `output_schema`, result scanning, the size limit, and treating results as untrusted data.
