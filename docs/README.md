# AgentShield documentation

| Document | Read it to |
|---|---|
| [Architecture](architecture.md) | Understand how a decision is made and carried out: the pipeline, the state machine, grants, budgets, data handling, audit, keys |
| [REST API reference](api.md) | Call the gateway: every route, its permission, request and response, status codes and reason codes |
| [Integrating an agent](integration.md) | Put an agent behind the gateway with the SDKs, MCP, REST or in-process, and close the ways around it |
| [Registering tools](tools.md) | Write and review a tool manifest for a REST API or an MCP server; destinations and labels |
| [Policy](policy.md) | Author, sign, test, activate, roll back and revoke policy; the bundle reference; how risk is scored |
| [Operations runbook](operations.md) | Install, run, back up, verify the audit chain, and handle incidents |
| [Threat model and coverage](threat-model.md) | See which threats are addressed, which are not, what the tests cover, and what to do before production |
| [Research report](research/AgentSecurity_Illustrated_Research_Report.html) | Read the design and commercial assessment this was built from |

Start with the [project README](../README.md) for a quick start and the demo.

## About the research report

The report (13 November 2026) calls the product *AgentSecurity*; AgentShield is its name as built. It is a design proposal and commercial assessment, written before any implementation. Where it and these documents disagree about what exists, these documents describe the code. The differences are listed in the [README](../README.md#differences-from-the-report-and-what-is-not-here), and coverage of the report's threat register is in [threat-model.md](threat-model.md).

The report also contains market, pricing and commercial analysis. If this repository is ever shared or made public, decide first whether that file should go with it.
