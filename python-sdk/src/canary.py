import secrets
from typing import Optional

_canary_store: dict = {}

def generate_canary(agent_id: str) -> str:
    canary = f"__anticipator_{secrets.token_hex(8)}__"
    _canary_store[agent_id] = canary
    return canary


def get_canary(agent_id: str) -> Optional[str]:
    return _canary_store.get(agent_id)


def inject_canary(text: str, agent_id: str) -> str:
    canary = generate_canary(agent_id)
    return f"{text}\n<!-- {canary} -->"


def detect(text: str, source_agent_id: str, current_agent_id: str) -> dict:
    findings = []

    for agent_id, canary in _canary_store.items():
        if agent_id == current_agent_id:
            continue
        if canary in text:
            findings.append({
                "leaked_from_agent": agent_id,
                "found_in_agent": current_agent_id,
                "canary": canary
            })

    return {
        "detected": len(findings) > 0,
        "findings": findings,
        "severity": "critical" if findings else "none",
        "layer": "canary_trap"
    }


if __name__ == "__main__":
    # Agent A sends message with canary
    msg = inject_canary("Summarize this document", "agent_a")
    print(f"Agent A message: {msg}")

    # Agent B receives it — canary leak detected
    result = detect(msg, "agent_a", "agent_b")
    print(f"Detected: {result['detected']} | Severity: {result['severity']}")
    print(f"Findings: {result['findings']}")