from __future__ import annotations

from dataclasses import dataclass

from aegis.defenses.approval_monitor import ApprovalMonitor, Decision, Policy
from aegis.defenses.keyword_guard import KeywordGuard, KeywordGuardConfig
from aegis.tools.send_email import ToolCall


@dataclass(frozen=True)
class EngineConfig:
    guard: str  # "none" | "keywords"


class DefenseEngine:
    """
    Combines:
      1) Policy-based approval (strict/permissive)
      2) Optional guardrails (keywords)
    """

    def __init__(self, policy: Policy, guard: str = "none") -> None:
        self.monitor = ApprovalMonitor(policy=policy)
        self.guard = guard
        self.keyword_guard = KeywordGuard(KeywordGuardConfig.default()) if guard == "keywords" else None

    def decide(self, proposed_call: ToolCall, context_text: str = "") -> Decision:
        base = self.monitor.decide(proposed_call)

        # If policy already blocks -> final block
        if not base.allowed:
            return base

        # Policy allows -> apply optional guard
        if self.guard == "keywords" and self.keyword_guard is not None:
            gd = self.keyword_guard.decide(proposed_call=proposed_call, context_text=context_text)
            if gd.blocked:
                return Decision(False, gd.reason)

        return base
