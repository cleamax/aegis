# AEGIS — Security Evaluation Harness for Tool-Using AI Agents

AEGIS is a security evaluation harness for tool-using AI agents.

It is built to answer a simple but uncomfortable question:

> When AI agents are exposed to untrusted input, how do they fail — and which defenses actually reduce risk?

Instead of optimizing prompts or building agent demos, AEGIS answers:

**How do AI agents fail under adversarial conditions — and which defenses actually work?**

---

## 🛡️ Security Engineering Portfolio

This repository is intentionally designed as a security engineering portfolio,
demonstrating how to reason about, test, and measure AI agent failure modes.

| Domain | Implementation |
| :--- | :--- |
| **Threat Modeling** | Formal [STRIDE analysis](THREAT_MODEL.md) of the agent harness boundaries. |
| **Fuzzing** | Property-based testing using **Hypothesis** to find edge cases in guards. |
| **Static Analysis** | Automated **Bandit** scanning in CI/CD to catch python vulnerabilities. |
| **CI/CD** | Full GitHub Actions pipeline (Linting, Type Checking, Testing). |
| **Policy** | Vulnerability disclosure policy defined in [SECURITY.md](SECURITY.md). |

---

## Why AEGIS exists

Modern AI agents combine:

- tool execution (email, file access, APIs)
- long context windows
- untrusted external data
- implicit decision-making

This creates a new attack surface (prompt injection, tool misuse, indirect injection). AEGIS is designed to:

- model **attacker behavior** (not toy examples)
- evaluate **defenses comparatively**
- produce **evidence-backed results** (trace + metrics + reports)

---

## What AEGIS is (and is not)

### What it is

- a deterministic **security evaluation harness**
- a framework for **attack and defense experiments**
- a way to compare **policies and guardrails**
- built for **traceability and reproducibility**

### What it is not

- not an agent framework
- not a prompt library
- not a chatbot demo
- not a production assistant

---

## Threat model (current)

AEGIS models attacks against **tool-using agents**, including:

- **Indirect prompt injection**  
  Malicious instructions embedded in untrusted content (for example, HTML)

- **Context fragmentation**  
  Instructions split across multiple turns to evade simple filters

- **Token smuggling / encoding**  
  Payloads hidden via encodings (for example, Base64) and reconstructed by the agent

All current scenarios attempt **high-risk tool misuse** (for example, email exfiltration). High-risk actions are **mocked by design**.

---

## Defense model

AEGIS evaluates defenses as **composable layers**.

### Policy layer

- `strict` — blocks high-risk tools by default
- `permissive` — intentionally unsafe baseline (for comparison)

### Guardrails

- `keywords` — simple keyword detection (also catches obfuscation like `S E N D  E M A I L`)
- `semantic` — dependency-free similarity detection (character n-grams + cosine similarity)
- `layered` — keywords + semantic (defense-in-depth)

Every decision is:

- deterministic
- explainable
- logged to the event trace

---

## Architecture

AEGIS is structured as a **security evaluation harness**, not as an agent framework.

The agent logic is intentionally minimal. The key property is that security-relevant behavior is explicit and testable.

### High-level flow

1. A scenario defines adversarial input or behavior
2. A simulated agent proposes a tool action
3. The defense engine evaluates the proposal
4. The action is blocked or executed (mocked)
5. Events are written to a trace (`trace.jsonl`)
6. Metrics and reports are derived from the trace

### Conceptual pipeline

- Scenario
- Simulated agent decision flow
- Tool proposal
- Defense engine
  - Policy layer
  - Keyword guard (optional)
  - Semantic guard (optional)
- Tool execution (mocked) or block
- Trace, metrics, reports

---

## Reproducible experiments


### Running Tests & Fuzzing

## Quick Start (60 seconds)

```bash
# Install AEGIS in editable mode
pip install -e .
```
# Run a reproducible security benchmark
aegis bench --config configs/experiments/basic.json

Ensure you have the dev dependencies installed:

```bash
pip install -e .[dev]
```

Run the full suite (Unit, Integration, Fuzzing):

```bash
# Run unit and integration tests
pytest

# Run fuzzing campaign
pytest fuzz/fuzz_guards.py
```

### 📊 Security Command Center (Dashboard)

Visualize run telemetry in the new **AEGIS Security Command Center**:

- **Real-time Event Stream**: Live monitoring of agent tool use.
- **Policy Analytics**: Charts showing Allowed vs Blocked actions.
- **Trace Analysis**: Deep dive into individual tool calls and defense logic.

The dashboard is intended for exploratory analysis of traces and policy behavior,
not for operational monitoring.


Launch locally:

```bash
streamlit run dashboard/app.py
```

Access at: **http://localhost:8501**


### Reproducible experiments

Example:

```bash
aegis bench --config configs/experiments/basic.json

