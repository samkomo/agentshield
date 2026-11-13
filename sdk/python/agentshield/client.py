"""
AgentShield client.

The client is a convenience, not a control. It hands every action to the
gateway and returns what the gateway decided. An agent runtime that can reach
a tool without going through the gateway is not protected by anything in this
file: remove the direct credentials and network paths.

    from agentshield import Client

    client = Client(endpoint="http://127.0.0.1:8787", credential=token)
    result = client.execute(
        tool_id="mail.v1", operation="email.send", task_id="task_abc",
        resource_id="document_123", destination_id="partner.example",
        arguments={"recipient": "reviewer@partner.example", "attachment": "document_123"},
        idempotency_key="task_abc-send-1",
    )
    if result.decision == "require_approval":
        ...  # wait for a person, then: result = client.resume(result)
    elif result.decision == "block":
        ...  # do not call the provider some other way
"""
import json
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


class AgentShieldError(Exception):
    """The gateway refused the request itself (bad input, conflict, not permitted to ask)."""

    def __init__(self, status: int, code: str, message: str, details: Any = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.details = details


@dataclass
class Result:
    decision: str
    reason: str
    reason_codes: List[str]
    risk_level: str
    approval_id: Optional[str]
    #: "succeeded", "failed", "unknown" or "denied" once execution was attempted.
    state: Optional[str]
    result: Any
    #: True when the result came from outside the trust boundary. Treat it as data, never as instructions.
    untrusted_content: bool
    receipt_id: Optional[str]
    #: The envelope that was submitted. Pass the whole Result to Client.resume after approval.
    action: Dict[str, Any] = field(repr=False, default_factory=dict)
    raw: Dict[str, Any] = field(repr=False, default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision in ("allow", "redact") and self.state == "succeeded"


class Client:
    def __init__(self, endpoint: str, credential: str, timeout: float = 60.0):
        self._endpoint = endpoint.rstrip("/")
        self._credential = credential
        self._timeout = timeout

    def request(self, method: str, path: str, body: Any = None) -> Any:
        """Low-level call. Returns the parsed body; raises AgentShieldError for error responses."""
        data = None
        headers = {"Authorization": "Bearer " + self._credential}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self._endpoint + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as res:
                status, text = res.status, res.read().decode("utf-8")
        except urllib.error.HTTPError as err:
            # 202, 403, 502 and 504 carry a decision or an execution result, not a failure of the call.
            status, text = err.code, err.read().decode("utf-8")
        parsed = json.loads(text) if text else None
        if isinstance(parsed, dict) and isinstance(parsed.get("error"), dict) and "code" in parsed["error"]:
            e = parsed["error"]
            raise AgentShieldError(status, e["code"], e.get("message", ""), e.get("details"))
        return parsed

    @staticmethod
    def _result(action: Dict[str, Any], body: Dict[str, Any]) -> Result:
        d = body["decision"]
        e = body.get("execution") or {}
        return Result(
            decision=d["decision"],
            reason=d.get("reason", ""),
            reason_codes=[r["code"] for r in d.get("reasons", [])],
            risk_level=d.get("risk_level", ""),
            approval_id=d.get("approval_id"),
            state=e.get("state"),
            result=e.get("result"),
            untrusted_content=bool(e.get("untrusted_content", False)),
            receipt_id=(e.get("receipt") or {}).get("event_id"),
            action=action,
            raw=body,
        )

    def execute(
        self,
        *,
        tool_id: str,
        operation: str,
        task_id: str,
        resource_id: str,
        destination_id: str,
        arguments: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        ttl_seconds: int = 300,
    ) -> Result:
        """Ask the gateway to authorize and carry out one action."""
        expires = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        action: Dict[str, Any] = {
            "action_id": "act_" + str(uuid.uuid4()),
            "task_id": task_id,
            "tool_id": tool_id,
            "operation": operation,
            "resource_id": resource_id,
            "destination_id": destination_id,
            "arguments": arguments or {},
            "nonce": str(uuid.uuid4()),
            "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (expires.microsecond // 1000),
        }
        if idempotency_key:
            action["idempotency_key"] = idempotency_key
        return self._result(action, self.request("POST", "/v1/actions/run", {"action": action}))

    def resume(self, pending: Result) -> Result:
        """Resubmit the exact action from an earlier require_approval result."""
        body: Dict[str, Any] = {"action": pending.action}
        if pending.approval_id:
            body["approval_id"] = pending.approval_id
        return self._result(pending.action, self.request("POST", "/v1/actions/run", body))

    def inspect(self, action: Dict[str, Any]) -> Any:
        """Would this be allowed? Records nothing and does not consume the action."""
        return self.request("POST", "/v1/tools/inspect", {"action": action})

    def scan_input(self, payload: Any, task_id: Optional[str] = None, source_id: Optional[str] = None) -> Any:
        """Scan content pulled in from outside. Tells the gateway this task has now seen untrusted content."""
        return self.request("POST", "/v1/scan/input", {"payload": payload, "task_id": task_id, "source_id": source_id})

    def scan_output(self, payload: Any, destination_id: str) -> Any:
        return self.request("POST", "/v1/scan/output", {"payload": payload, "destination_id": destination_id})

    def detect_sensitive(self, payload: Any, entity_types: Optional[List[str]] = None) -> Any:
        return self.request("POST", "/v1/detect/sensitive", {"payload": payload, "entity_types": entity_types})

    def redact(self, payload: Any, task_id: Optional[str] = None) -> Any:
        return self.request("POST", "/v1/redact", {"payload": payload, "task_id": task_id})

    def detect_injection(self, payload: Any) -> Any:
        return self.request("POST", "/v1/detect/injection", {"payload": payload})

    def delegate(self, parent_task_id: str, grant: Dict[str, Any]) -> Any:
        """Hand part of this agent's grant to another agent."""
        return self.request("POST", "/v1/grants/delegate", {"parent_task_id": parent_task_id, "grant": grant})
