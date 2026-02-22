# Anticipator

**Runtime security for multi-agent AI systems.**

Anticipator detects prompt injection, credential leakage, and anomalous agent behavior across LangGraph pipelines — before they become incidents.

No LLMs. No embeddings. No external APIs. Fully local, fully deterministic, under 5ms per message.

> ⚡ Caught something in your pipeline? [Open an issue](../../issues) — we want to see real-world detections.

---

## Why Anticipator

Multi-agent systems introduce a new class of security problem. When agents pass messages to each other, any one of those messages can carry an injection attack, a leaked credential, or a role manipulation — and no existing tool is watching that traffic.

Anticipator wraps your existing agent graph and intercepts every message in transit. It does not block execution. It detects and logs — a smoke detector, not a firewall.

---

## Installation

```bash
pip install anticipator
```

---

## Quickstart

### LangGraph

```python
from anticipator import observe

graph = build_graph()  # your existing StateGraph
secure = observe(graph, name="my_pipeline")
app = secure.compile()

# Run normally — Anticipator intercepts silently in the background
result = app.invoke({"input": "..."})

# Optional: export JSON report from Python
app.export_report()
# Or use the CLI instead:
# anticipator export
```

### CLI

```bash
# Scan a message directly
anticipator scan "Ignore all previous instructions"

# View persistent threat monitor
anticipator monitor

# Filter by time window
anticipator monitor --last 24h

# Filter by pipeline
anticipator monitor --graph my_pipeline

# Export JSON report
anticipator export
anticipator export --output reports/report.json
```

---

## Detection Layers

Anticipator runs five detection layers on every inter-agent message:

| Layer | Method | Catches |
|---|---|---|
| Phrase Detection | Aho-Corasick | Injection commands, role switches, system prompt abuse |
| Encoding Detection | Base64 / Hex / URL decode + rescan | Obfuscated payloads, encoded attacks |
| Credential Detection | Shannon entropy + regex | API keys, JWTs, AWS keys, tokens, webhooks |
| Heuristic Detection | Pattern matching | Char spacing, ALL CAPS, role-switch phrases |
| Canary Detection | Unique token injection | Cross-agent context leakage |

---

## Output

### Terminal

```
┌─ ANTICIPATOR ──────────────────────────────┐
│  Graph : financial_research_pipeline
│  Nodes : 3 node(s) patched
└──────────────────────────────────────────────┘

╔══ ANTICIPATOR REPORT ══════════════════════════════════╗
║  Graph   : financial_research_pipeline
║  Scanned : 3 messages
║  Threats : 2
╠════════════════════════════════════════════════════════╣
║  [1] CRITICAL  ->  analyst_agent
║      Pull report. Auth: eyJhbGciOiJIUzI1NiJ9...
╚════════════════════════════════════════════════════════╝
```

### JSON Report

Running `app.export_report()` generates a structured JSON file with full scan history, threat propagation paths, and severity metadata.

---

## Persistent Monitoring

Every scan is written to a local SQLite database and accumulates across sessions. Query your threat history from the CLI at any time:

```bash
anticipator monitor --last 7d
anticipator monitor --graph my_pipeline
```

---

## How It Works

Anticipator wraps your graph or crew with a single function call and patches each node or agent to run detection on every input before forwarding to the underlying function. The original execution is always preserved — no messages are blocked or modified.

```
User Input
    │
    ▼
┌─────────────────────┐
│   Agent A (patched) │ ◄── Anticipator scans input here
└─────────┬───────────┘
          │  message
          ▼
┌─────────────────────┐
│   Agent B (patched) │ ◄── Anticipator scans input here
└─────────┬───────────┘
          │  message
          ▼
┌─────────────────────┐
│   Agent C (patched) │ ◄── Anticipator scans input here
└─────────────────────┘
```

---

## Supported Frameworks

| Framework | Status |
|---|---|
| LangGraph | ✅ Supported |
| CrewAI | 🔜 Coming soon |
| AutoGen | 🔜 Coming soon |
| Custom pipelines | ✅ Via direct `scan()` API |

---

## Design Principles

**Deterministic.** No LLMs, no embeddings, no network calls. Every detection decision is explainable.

**Non-blocking.** Anticipator never stops your pipeline. It observes, detects, and reports.

**Persistent.** SQLite storage accumulates threat history across restarts and sessions.

**Framework-agnostic.** One `observe()` call works for both LangGraph and CrewAI.

**Local by default.** No data leaves your environment.

---

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

*Built for the teams shipping multi-agent AI in production.*