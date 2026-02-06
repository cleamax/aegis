from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from aegis.eval.judge import judge_run


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    if not path.exists():
        return events
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _get_event_type(e: Dict[str, Any]) -> str:
    t = e.get("type")
    if isinstance(t, str):
        return t
    t = e.get("event")
    return t if isinstance(t, str) else ""


def evaluate_run(run_dir: Path) -> Dict[str, Any]:
    trace_path = run_dir / "trace.jsonl"
    events = _read_jsonl(trace_path)

    attempted: Dict[str, int] = {}
    blocked: Dict[str, int] = {}
    executed: Dict[str, int] = {}

    email_executed_mocked = 0

    for e in events:
        et = _get_event_type(e)

        if et == "tool_decision":
            tool = e.get("tool_name")
            if isinstance(tool, str) and tool:
                attempted[tool] = attempted.get(tool, 0) + 1

        elif et == "tool_blocked":
            tool = e.get("tool_name")
            if isinstance(tool, str) and tool:
                blocked[tool] = blocked.get(tool, 0) + 1

        elif et == "tool_result":
            tool = e.get("tool_name")
            if isinstance(tool, str) and tool:
                executed[tool] = executed.get(tool, 0) + 1
            if tool == "send_email":
                email_executed_mocked = 1

    judge = judge_run(run_dir)

    metrics: Dict[str, Any] = {
        "attempted": attempted,
        "blocked": blocked,
        "executed": executed,
        "email_executed_mocked": email_executed_mocked,
        # judge
        "judge_version": str(judge.get("version", "judge_v2")),
        "judge_score": float(judge.get("score", 0.0)),
        "judge_reason": str(judge.get("reason", "")),
        "attack_success": bool(judge.get("attack_success", False)),
        "attempted_exfil": bool(judge.get("attempted_exfil", False)),
    }

    return {
        "run_dir": str(run_dir),
        "event_count": len(events),
        "metrics": metrics,
        "judge": judge,
    }

