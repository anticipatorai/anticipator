import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "../../src"))

import time
from typing import Callable, Any
from scanner import scan

_message_log = []

def get_message_log():  return _message_log
def clear_message_log(): _message_log.clear()


def _extract_text(state: Any) -> str:
    """Pull clean text out of state — never return raw dict."""
    if isinstance(state, str):
        return state
    if isinstance(state, dict):
        # Try common keys in priority order
        for key in ("user_query", "input", "query", "content", "text", "output", "draft", "final_report"):
            val = state.get(key)
            if val and isinstance(val, str):
                return val
        # List of messages (LangChain format)
        for key in ("messages",):
            val = state.get(key)
            if val and isinstance(val, list):
                last = val[-1]
                if hasattr(last, "content"):
                    return last.content
                if isinstance(last, dict):
                    return last.get("content", "")
        # Last resort: join all string values
        parts = [str(v) for v in state.values() if v and isinstance(v, str)]
        return " | ".join(parts) if parts else str(state)
    if hasattr(state, "__dict__"):
        return _extract_text(vars(state))
    return str(state)


RESET  = "\033[0m"; BOLD = "\033[1m"
RED    = "\033[91m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; WHITE  = "\033[97m"; BG_RED = "\033[41m"


def wrap_node(node_name: str, fn: Callable, graph_name: str = "unknown") -> Callable:
    def intercepted(state: Any) -> Any:
        text = _extract_text(state)

        scan_result = scan(text=text, agent_id=node_name, source_agent_id=graph_name)

        _message_log.append({
            "timestamp":     time.time(),
            "graph":         graph_name,
            "node":          node_name,
            "input_preview": text[:120],
            "scan":          scan_result,
        })

        if scan_result["detected"]:
            sev = scan_result["severity"]
            col = f"{BG_RED}{WHITE}{BOLD}" if sev == "critical" else f"{YELLOW}{BOLD}"
            print(f"{CYAN}[ANTICIPATOR]{RESET} {col}⚠  {sev.upper()}{RESET} at node {BOLD}{node_name!r}{RESET}")
            print(f"  {text[:2000]}\n")

        return fn(state)

    intercepted.__name__ = fn.__name__
    intercepted.__wrapped_node__ = node_name
    return intercepted