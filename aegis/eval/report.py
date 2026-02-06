from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Tuple


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def _rate(numer: int, denom: int) -> str:
    if denom <= 0:
        return "—"
    return f"{(numer / denom) * 100:.1f}%"


def _avg(total: float, n: int) -> str:
    if n <= 0:
        return "—"
    return f"{(total / n):.2f}"


def bench_summary_to_markdown(payload: Dict[str, Any]) -> str:
    report_dir = str(payload.get("report_dir", ""))
    runs_dir = str(payload.get("runs_dir", ""))
    out_root = str(payload.get("out_root", "runs"))
    scenarios: List[str] = list(payload.get("scenarios", []))
    policies: List[str] = list(payload.get("policies", []))
    guard = str(payload.get("guard", "—"))
    results: List[Dict[str, Any]] = list(payload.get("results", []))

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines: List[str] = []
    lines.append("# AEGIS Bench Summary")
    lines.append("")
    lines.append(f"- Generated: **{now}**")
    if report_dir:
        lines.append(f"- Report dir: `{report_dir}`")
    if runs_dir:
        lines.append(f"- Runs dir: `{runs_dir}`")
    else:
        lines.append(f"- Runs folder: `{out_root}`")
    lines.append(f"- Guard: `{guard}`")
    lines.append(f"- Scenarios: {', '.join(f'`{s}`' for s in scenarios) if scenarios else '—'}")
    lines.append(f"- Policies: {', '.join(f'`{p}`' for p in policies) if policies else '—'}")
    lines.append("")

    lines.append("## Results")
    lines.append("")
    lines.append("| Scenario | Policy | Guard | Exfil Attempt | Blocked | Email Executed | Judge Score | Judge Reason | Run ID |")
    lines.append("|---|---|---|---:|---:|---:|---:|---|---|")

    results_sorted = sorted(results, key=lambda r: (r.get("scenario", ""), r.get("policy", "")))

    for r in results_sorted:
        scenario = _md_escape(str(r.get("scenario", "")))
        policy = _md_escape(str(r.get("policy", "")))
        rg = _md_escape(str(r.get("guard", guard)))

        attempted_exfil = "✅" if r.get("attempted_exfil") else "❌"

        blocked_map = r.get("blocked") or {}
        blocked_any = False
        if isinstance(blocked_map, dict):
            blocked_any = (blocked_map.get("send_email", 0) or 0) > 0
        blocked_icon = "✅" if blocked_any else "❌"

        email_exec = "✅" if r.get("email_executed_mocked") else "❌"
        judge_score = f"{float(r.get('judge_score', 0.0)):.2f}"
        reason = _md_escape(str(r.get("judge_reason", "")))[:80]
        run_id = _md_escape(str(r.get("run_id", "")))

        lines.append(
            f"| `{scenario}` | `{policy}` | `{rg}` | {attempted_exfil} | {blocked_icon} | {email_exec} | {judge_score} | {reason} | `{run_id}` |"
        )

    lines.append("")
    lines.append("## Aggregate")
    lines.append("")

    # per (policy, guard)
    agg: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for r in results:
        pol = str(r.get("policy", ""))
        g = str(r.get("guard", guard))
        key = (pol, g)
        if key not in agg:
            agg[key] = {"total": 0, "success": 0, "attempted": 0, "score_sum": 0.0}
        agg[key]["total"] += 1
        agg[key]["score_sum"] += float(r.get("judge_score", 0.0))
        if r.get("attack_success"):
            agg[key]["success"] += 1
        if r.get("attempted_exfil"):
            agg[key]["attempted"] += 1

    lines.append("| Policy | Guard | Runs | Exfil Attempts | Attack Success | Success Rate | Avg Judge Score |")
    lines.append("|---|---|---:|---:|---:|---:|---:|")
    for (pol, g), a in sorted(agg.items(), key=lambda x: (x[0][0], x[0][1])):
        total = int(a["total"])
        attempted = int(a["attempted"])
        success = int(a["success"])
        score_sum = float(a["score_sum"])
        lines.append(
            f"| `{_md_escape(pol)}` | `{_md_escape(g)}` | {total} | {attempted} | {success} | {_rate(success, total)} | {_avg(score_sum, total)} |"
        )

    lines.append("")
    lines.append("## Interpretation (quick)")
    lines.append("")
    lines.append("- `permissive` is intentionally unsafe (baseline).")
    lines.append("- `strict` blocks high-risk actions by policy.")
    lines.append("- `layered` should reduce success even under `permissive` via guardrails.")
    lines.append("- Judge v2 uses graded scoring (0.0 / 0.5 / 1.0) for quick comparison.")
    lines.append("")

    return "\n".join(lines)


