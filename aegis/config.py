from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List


@dataclass(frozen=True)
class BenchConfig:
    out: str
    scenarios: List[str]
    policies: List[str]
    guard: str

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "BenchConfig":
        out = str(d.get("out", "runs"))
        scenarios = list(d.get("scenarios", [])) or ["indirect_injection_01", "context_fragmentation_01", "token_smuggling_01"]
        policies = list(d.get("policies", [])) or ["strict", "permissive"]
        guard = str(d.get("guard", "none"))
        return BenchConfig(out=out, scenarios=scenarios, policies=policies, guard=guard)


def load_bench_config(path: str) -> BenchConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    return BenchConfig.from_dict(data)
