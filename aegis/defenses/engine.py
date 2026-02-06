from __future__ import annotations

from aegis.defenses.approval_monitor import ApprovalMonitor, Decision, Policy
from aegis.defenses.keyword_guard import KeywordGuard, KeywordGuardConfig
from aegis.defenses.semantic_guard import SemanticGuard, SemanticGuardConfig
from aegis.tools.send_email import ToolCall


class DefenseEngine:
    """
    Defense-in-depth:
      1) Policy approval (strict/permissive)
      2) Optional guardrails:
         - keywords
         - semantic
         - layered (keywords + semantic)
    """

    def __init__(self, policy: Policy, guard: str = "none") -> None:
        self.monitor = ApprovalMonitor(policy=policy)
        self.guard = guard

        self.keyword_guard = (
            KeywordGuard(KeywordGuardConfig.default()) if guard in ("keywords", "layered") else None
        )
        self.semantic_guard = (
            SemanticGuard(SemanticGuardConfig.default()) if guard in ("semantic", "layered") else None
        )

    def decide(self, proposed_call: ToolCall, context_text: str = "") -> Decision:
        base = self.monitor.decide(proposed_call)

        # Policy already blocks
        if not base.allowed:
            return base

        # Keyword guard
        if self.keyword_guard is not None:
            gd = self.keyword_guard.decide(proposed_call=proposed_call, context_text=context_text)
            if gd.blocked:
                return Decision(False, gd.reason)

        # Semantic guard
        if self.semantic_guard is not None:
            sd = self.semantic_guard.decide(proposed_call=proposed_call, context_text=context_text)
            if sd.blocked:
                return Decision(False, f"{sd.reason} | matched='{sd.matched_phrase}'")

        return base

