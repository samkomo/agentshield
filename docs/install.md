# Install

This guide takes a machine with an agent runtime on it to one where every tool call the agent makes is checked by AgentShield first. It assumes nothing about the machine beyond the requirements below: every location is either under your home directory or reported by the runtime itself.

**Requirements**

- macOS or Linux
- Node.js 24 or later, and Git
- An agent runtime. [Hermes](https://github.com/NousResearch/hermes-agent) 0.22 or later is supported today; see [Other runtimes](#other-runtimes)

Nothing here uses `sudo`, and nothing is written outside your home directory.

## 1. Install the command

```bash
curl -fsSL https://raw.githubusercontent.com/samkomo/agentshield/main/install.sh | bash
```

This clones the repository to `~/.local/share/agentshield`, writes an `agentshield` command to `~/.local/bin`, and runs it once to confirm it works. It does not edit your shell files. If `~/.local/bin` is not on your `PATH` it prints the line to add.

AgentShield has no runtime dependencies, so there is no build and no package install.

To install a specific release instead of the latest:

```bash
curl -fsSL https://raw.githubusercontent.com/samkomo/agentshield/main/install.sh | bash -s -- --ref v0.1.0
```

## 2. Start the gateway

```bash
agentshield service install
```

The first run creates `~/.agentshield` (keys, database, the signed default policy, and three administrator credentials in `bootstrap-credentials.json`, readable only by you). It then registers the gateway as a background service for your account — a launchd agent on macOS, a systemd user unit on Linux — and waits until it answers on `127.0.0.1:8787`. The service starts again at each login.

On a Linux machine with no one logged in, a user service stops at logout unless lingering is on (`loginctl enable-linger`).

To run the gateway in a terminal instead, for a trial: `agentshield up`.

## 3. Connect your agent

### Hermes

```bash
agentshield connect hermes
```

Run this in the account that runs Hermes. It does four things, in this order, and stops before changing anything if the first fails:

1. **Looks.** Asks Hermes for its version, its home directory (which depends on `HERMES_HOME` and on profiles) and whether the plugin is already there, and checks the gateway is answering. It prints what it found and what it is about to do.
2. **Sets up the gateway side.** Registers the Hermes tool preset, creates an agent identity with a 90-day grant, and saves its credential to `~/.config/agentshield/token`, readable only by you. The credential is never displayed.
3. **Installs the plugin through Hermes.** It runs `hermes plugins install`, pinned to the exact commit of your AgentShield checkout, so Hermes's own source scan, version check and install record apply. Hermes prints two warnings at this point — that the source is not from its catalog and that it is a local path. Both are expected: the plugin is coming from the checkout you installed in step 1.
4. **Proves it.** Confirms Hermes reports the plugin as enabled and sends one test call through the gateway with the agent's credential.

A Hermes that is already running picks the plugin up for new tool calls. If it does not, `hermes gateway restart`.

Useful options:

| Option | Effect |
|---|---|
| `--dry-run` | Show what was found and what would be done; change nothing |
| `--profile NAME` | Connect a named Hermes profile rather than the active one |
| `--mode monitor` | Install, but block nothing: Hermes's log records what would have been blocked or sent for approval. `--mode enforce` switches back |
| `--rotate` | Issue a new credential and invalidate the old one |

Running `connect` again is safe. It changes only what is missing or out of date, which makes it the command for renewing the grant and for picking up a newer plugin after an update.

### Other runtimes

| Runtime | Status |
|---|---|
| Hermes 0.22+ | Supported: `agentshield connect hermes` |
| Claude Code, Grok Build, Codex, Cursor, Gemini CLI, OpenClaw | No `connect` adapter yet. Individual MCP servers can be put behind the gateway today; see [MCP](integration.md#mcp) |
| Your own agent | The [Python and TypeScript SDKs](integration.md#sdks), or [REST](integration.md#rest) |

## 4. Check it

```bash
agentshield doctor
```

```
ok    AgentShield     agentshield 0.1.0 (b099a6d) on Node 24.22.0
note  Gateway data    /home/you/.agentshield
ok    Gateway         answering at http://127.0.0.1:8787
ok    Service         systemd user unit agentshield.service is running
ok    Agent "hermes"  grant runs for another 90 days
ok    Hermes          0.22.7 at /home/you/.hermes
ok    Hermes plugin   enabled, git pinned@b099a6d2
ok    Credential      /home/you/.config/agentshield/token (owner-only)
ok    Test call       a test read was checked and allowed
ok    Mode            enforce

No problems found.
```

Every failed line comes with the command that fixes it, and the exit code is non-zero if anything failed. `--json` gives the same checks for scripts.

Run it after `hermes update` in particular. Hermes disables a plugin that no longer fits a new release rather than failing the update, and a disabled plugin checks nothing.

## Gateway and agent in different accounts

Running the agent under its own account, separate from the one that holds the gateway's keys, is the stronger arrangement: the agent cannot read the keys, the database or the audit log. Install the command (step 1) in both accounts, then:

In the gateway's account:

```bash
agentshield service install
```

```bash
agentshield enroll hermes
```

`enroll` does the gateway's half only and saves the agent's credential to `~/.agentshield/agents/hermes.token`. It prints the next line with the right path.

In the agent's account, with that credential on standard input:

```bash
agentshield connect hermes --token-stdin < /path/to/hermes.token
```

The agent's account cannot read the gateway account's files, so the credential has to be handed across. From the gateway's account, with `sudo`, that is one line and the credential is never displayed:

```bash
sudo -u AGENT_ACCOUNT -H -i agentshield connect hermes --token-stdin < ~/.agentshield/agents/hermes.token
```

Both accounts must be on the same machine, since the gateway listens on loopback only.

## Keeping it working

| When | Run |
|---|---|
| A new AgentShield release | The install line from step 1 again, then `agentshield service install` and `agentshield connect hermes` |
| After `hermes update` | `agentshield doctor` |
| The grant is close to expiry (`doctor` warns at 14 days) | `agentshield connect hermes`, or `agentshield enroll hermes` in the gateway's account |
| The credential may have leaked | `agentshield connect hermes --rotate` |

## Remove

```bash
agentshield disconnect hermes
```

```bash
agentshield service uninstall
```

```bash
curl -fsSL https://raw.githubusercontent.com/samkomo/agentshield/main/install.sh | bash -s -- --uninstall
```

`disconnect` removes the plugin through Hermes, deletes the saved credential and removes AgentShield's own lines from Hermes's env file. The last line removes the command and the checkout. Your gateway data in `~/.agentshield`, including the audit log, is left alone; delete it yourself once you no longer need the record.

## What is written where

| Path | What | Written by |
|---|---|---|
| `~/.local/share/agentshield` | The checkout | `install.sh` |
| `~/.local/bin/agentshield` | The command | `install.sh` |
| `~/.agentshield` | Keys, database, audit checkpoints, agent credentials, `gateway.log` | `service install`, `up`, `enroll`, `connect` |
| `~/Library/LaunchAgents/com.agentshield.gateway.plist` (macOS) or `~/.config/systemd/user/agentshield.service` (Linux) | The service definition | `service install` |
| `~/.config/agentshield/token` | The agent's credential, in the agent's account | `connect` |
| `plugins/agentshield` in the Hermes home | The plugin | Hermes, asked by `connect` |
| `.env` in the Hermes home | `AGENTSHIELD_MODE` and `AGENTSHIELD_URL` lines only, and only when not the default | `connect` |

Change the first three with `AGENTSHIELD_INSTALL_DIR`, `AGENTSHIELD_BIN_DIR` and `AGENTSHIELD_HOME`.

## If something goes wrong

| What you see | What it means |
|---|---|
| `Hermes was not found` | `hermes` is not on `PATH` in this account. Run `connect` in the account that runs Hermes, or pass `--hermes /path/to/hermes` |
| `The gateway is not running … Nothing was changed.` | Start it with `agentshield service install`. `connect` will not install a plugin with no gateway behind it, because in enforce mode that plugin would block every tool call |
| `There is no gateway data in …` | This account has no gateway. Start one here, or follow [Gateway and agent in different accounts](#gateway-and-agent-in-different-accounts) |
| `This plugin needs Hermes 0.22.0 or later` | `hermes update` |
| Hermes refuses to install the plugin | Its own message is shown above the error. Hermes's source scan and removed-plugin list run before anything is installed |
| Every tool call is blocked after connecting | `agentshield doctor`. The usual causes are a stopped gateway, a missing credential file, or an expired grant |
| Tool calls are not being checked | `agentshield doctor`. The plugin is disabled, or Hermes was started with `--safe-mode`, which skips all plugins |

## What this does and does not give you

The plugin is a checkpoint inside Hermes. While it is loaded, a call the policy denies does not run, a risky one goes to Hermes's approval prompt, credentials and personal data bound for the internet are replaced, and every decision is in a signed log. If the gateway cannot be reached, calls are blocked rather than waved through.

It is not a wall around Hermes. Hermes still holds its tools' credentials, and anything that can change Hermes's configuration in the agent's account can switch the plugin off. Model calls are not covered. For the tools that matter most, route them [through the gateway](integration.md#closing-the-bypass) so the agent never holds their credentials. See [Hermes plugin](integration.md#hermes-plugin) and the [threat model](threat-model.md).
