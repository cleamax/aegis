from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def bench_summary_to_markdown(payload: Dict[str, Any]) -> str:
    out_root = str(payload.get("out_root", "runs"))
    scenarios: List[str] = list(payload.get("scenarios", []))
    policies: List[str] = list(payload.get("policies", []))
    results: List[Dict[str, Any]] = list(payload.get("results", []))

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines: List[str] = []
    lines.append("# AEGIS Bench Summary")
    lines.append("")
    lines.append(f"- Generated: **{now}**")
    lines.append(f"- Runs folder: `{out_root}`")
    lines.append(f"- Scenarios: {', '.join(f'`{s}`' for s in scenarios) if scenarios else '—'}")
    lines.append(f"- Policies: {', '.join(f'`{p}`' for p in policies) if policies else '—'}")
    lines.append("")

    # Table header
    lines.append("## Results")
    lines.append("")
    lines.append("| Scenario | Policy | Email Executed (mocked) | Blocked | Executed | Run ID |")
    lines.append("|---|---|---:|---|---|---|")

    # Sort for readability
    results_sorted = sorted(results, key=lambda r: (r.get("scenario", ""), r.get("policy", "")))

    for r in results_sorted:
        scenario = _md_escape(str(r.get("scenario", "")))
        policy = _md_escape(str(r.get("policy", "")))
        email_exec = "✅" if r.get("email_executed_mocked") else "❌"
        blocked = _md_escape(str(r.get("blocked", {})))
        executed = _md_escape(str(r.get("executed", {})))
        run_id = _md_escape(str(r.get("run_id", "")))

        lines.append(f"| `{scenario}` | `{policy}` | {email_exec} | `{blocked}` | `{executed}` | `{run_id}` |")

    # Quick interpretation section
    lines.append("")
    lines.append("## Interpretation (quick)")
    lines.append("")
    lines.append("- **strict** should block high-risk tools (e.g., `send_email`).")
    lines.append("- **permissive** is intentionally unsafe for demonstration and should allow misuse.")
    lines.append("")

    return "\n".join(lines)
