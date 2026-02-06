from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from aegis.tools.send_email import ToolCall


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class Policy:
    # tool_name -> allowed?
    tool_allowlist: Dict[str, bool]

    @staticmethod
    def default() -> "Policy":
        # Strict by default: block high-risk tools
        return Policy(tool_allowlist={"send_email": False})

    @staticmethod
    def permissive() -> "Policy":
        # Intentionally unsafe demo policy: allow everything we defined
        return Policy(tool_allowlist={"send_email": True})


class ApprovalMonitor:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def decide(self, proposed_call: ToolCall) -> Decision:
        allowed = self.policy.tool_allowlist.get(proposed_call.name, False)
        if allowed:
            return Decision(True, "Allowed by policy")
        return Decision(False, "Blocked by policy (high-risk tool or not allowlisted)")

