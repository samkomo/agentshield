# AgentShield plugin installed

Every tool call is now checked with an AgentShield gateway before it runs.

The plugin needs two things outside Hermes, and **blocks every tool call until it has both**:

1. A gateway answering at `http://127.0.0.1:8787` (or the address in `AGENTSHIELD_URL`).
2. The agent's credential in `~/.config/agentshield/token`.

`agentshield connect hermes` sets up both and tests them. If you installed this plugin directly
with `hermes plugins install`, run that command now, or `agentshield doctor` to see what is missing.

To watch without blocking anything: `agentshield connect hermes --mode monitor`.
