"""
CrewAI Interceptor
Hooks into Agent.execute_task to scan every inter-agent message.
"""

import time
from anticipator.integrations.monitor import write_scan, write_delegation
from anticipator.detection.scanner import scan

_message_log = []
_last_agent = {}

def get_message_log():
    return _message_log

def clear_message_log():
    _message_log.clear()


# Terminal colors
RESET  = "\033[0m"
BOLD   = "\033[1m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
BG_RED = "\033[41m"


def _extract_text(task, context=None) -> str:
    """Pull readable text from a CrewAI task + context."""
    parts = []

    if hasattr(task, "description") and task.description:
        parts.append(str(task.description))

    if context:
        if isinstance(context, str):
            parts.append(context)
        elif isinstance(context, list):
            for c in context:
                if hasattr(c, "raw"):
                    parts.append(str(c.raw))
                elif isinstance(c, str):
                    parts.append(c)

    return " | ".join(parts) if parts else "empty"


def wrap_agent(agent, graph_name: str = "crewai") -> None:
    """
    Monkey-patch a single CrewAI Agent's execute_task method.
    Call this on each agent before kickoff().
    """

    # Prevent double wrapping
    if getattr(agent.execute_task, "__wrapped_anticipator__", False):
        return

    original_execute = agent.execute_task

    def patched_execute(task, context=None, tools=None):

        agent_name = getattr(agent, "role", str(agent))
        text = _extract_text(task, context)

        # Delegation tracking
        prev = _last_agent.get(graph_name)
        if prev and prev != agent_name:
            write_delegation("crewai", graph_name, prev, agent_name)

        _last_agent[graph_name] = agent_name

        # Scan message
        scan_result = scan(
            text=text,
            agent_id=agent_name,
            source_agent_id=graph_name,
        )

        # In-memory log
        _message_log.append({
            "timestamp": time.time(),
            "graph": graph_name,
            "node": agent_name,
            "input_preview": text[:120],
            "scan": scan_result,
        })

        # Persistent log
        write_scan("crewai", graph_name, agent_name, scan_result, text)
        

        # Alert
        if scan_result.get("detected"):
            sev = scan_result.get("severity", "low")
            col = f"{BG_RED}{WHITE}{BOLD}" if sev == "critical" else f"{YELLOW}{BOLD}"
            print(f"{CYAN}[ANTICIPATOR]{RESET} {col}⚠ {sev.upper()}{RESET} at agent {BOLD}{agent_name!r}{RESET}")
            print(f"  {text[:200]}\n")

        # Continue normal execution
        if tools is not None:
            return original_execute(task, context=context, tools=tools)
        return original_execute(task, context=context)

    patched_execute.__wrapped_anticipator__ = True
    object.__setattr__(agent, "execute_task", patched_execute)

    