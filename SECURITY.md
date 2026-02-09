# Security Policy

This document describes how to report security issues in **AEGIS**
and clarifies the scope for responsible disclosure.

AEGIS is a **security evaluation harness** maintained as an
individual research and portfolio project.
It is not a production system.

---

## Supported Versions

AEGIS is under active development.

Only the **latest released version** is considered relevant
for security reporting.

---

## Reporting a Vulnerability

If you identify a security-relevant issue in AEGIS
(for example, a logic flaw in policy enforcement or a guard bypass),
please report it responsibly.

### Please do **not** open a public GitHub issue.

Security reports should be sent via email:

📧 **max.richter.dev@proton.me**

---

## Reporting Guidelines

To support analysis and reproducibility, please include:

1. A clear description of the issue and the affected component.
2. A minimal reproduction scenario (configuration or script).
3. The expected behavior versus the observed behavior.
4. Any relevant traces, logs, or artifacts (for example `trace.jsonl`).

Reports that include a reproducible scenario are particularly helpful.

Reports will be reviewed on a **best-effort basis**.

---

## Scope

### In Scope

The following issues are considered **in scope**:

- Logic errors in the **Defense Engine**
- Incorrect behavior in **policy enforcement**
- Guardrail bypasses in:
  - `KeywordGuard`
  - `SemanticGuard`
  - layered or combined guard configurations
- Cases where **high-risk tool actions** are allowed
  despite being blocked by the active policy

### Out of Scope

The following are **out of scope**:

- Vulnerabilities in underlying LLMs or model providers
- Prompt injection behavior without a logic flaw in AEGIS
- Model alignment, training data, or model-side safety mechanisms
- General AI safety research unrelated to the evaluation harness

AEGIS evaluates agent behavior — it does not claim to secure models.

---

## Disclosure Expectations

AEGIS is an individual research and portfolio project.

There is no bug bounty program, service-level agreement,
or guaranteed remediation timeline.

Valid reports may result in documentation updates,
additional test coverage, or design adjustments.

