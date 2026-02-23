"""
anticipator.integrations.langgraph.interceptor
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Per-node scan hook for LangGraph graphs.

Fixes over v1
-------------
- _message_log and _last_node are now protected by threading.Lock()
  — safe under scan_pipeline concurrency=10 and any thread pool executor
- Alert print was a dead code block (col computed, nothing printed) — fixed
- functools.wraps applied so stack traces / LangGraph internals keep
  the original function name and docstring
- clear_message_log() is now also lock-protected
- _extract_text handles empty lists gracefully (was IndexError on val[-1])
- Delegation write is fire-and-forget safe (doesn't block the node return)
"""

import time
import threading
import functools
from typing import Callable, Any

from anticipator.integrations.monitor import write_scan, write_delegation
from anticipator.detection.scanner import scan

# ── Thread-safe in-memory log ─────────────────────────────────────────────────
_message_log: list  = []
_last_node:   dict  = {}
_log_lock            = threading.Lock()

# ── ANSI colours (module-level so intercepted() closure captures once) ────────
RESET  = "\033[0m";  BOLD   = "\033[1m";  DIM    = "\033[2m"
RED    = "\033[91m"; YELLOW = "\033[93m"; GREEN  = "\033[92m"
CYAN   = "\033[96m"; WHITE  = "\033[97m"; BG_RED = "\033[41m"


def get_message_log() -> list:
    with _log_lock:
        return list(_message_log)          # return a snapshot, not the live list


def clear_message_log() -> None:
    with _log_lock:
        _message_log.clear()
        _last_node.clear()


# ── State text extractor ──────────────────────────────────────────────────────

def _extract_text(state: Any) -> str:
    """
    Pull the most relevant string from a LangGraph node state.
    Handles: str, dict (various key conventions), LangChain messages,
    arbitrary objects with __dict__.
    """
    if isinstance(state, str):
        return state

    if isinstance(state, dict):
        # Priority key scan — first non-empty string wins
        for key in ("user_query", "input", "query", "content",
                    "text", "output", "draft", "final_report"):
            val = state.get(key)
            if val and isinstance(val, str):
                return val

        # LangChain messages list
        val = state.get("messages")
        if val and isinstance(val, list) and len(val) > 0:
            last = val[-1]
            if hasattr(last, "content") and last.content:
                return str(last.content)
            if isinstance(last, dict):
                return last.get("content", "") or ""

        # Fallback: join all string values
        parts = [str(v) for v in state.values() if v and isinstance(v, str)]
        return " | ".join(parts) if parts else str(state)

    if hasattr(state, "__dict__"):
        return _extract_text(vars(state))

    return str(state)


# ── Node wrapper ──────────────────────────────────────────────────────────────

def wrap_node(node_name: str, fn: Callable, graph_name: str = "unknown") -> Callable:
    """
    Return a wrapped version of *fn* that scans its state input before
    passing through to the original function.
    """

    @functools.wraps(fn)
    def intercepted(state: Any) -> Any:
        text = _extract_text(state)

        # ── Delegation tracking ───────────────────────────────────────────
        with _log_lock:
            prev = _last_node.get(graph_name)
            _last_node[graph_name] = node_name

        if prev and prev != node_name:
            # Non-blocking: write_delegation opens its own DB connection
            write_delegation("langgraph", graph_name, prev, node_name)

        # ── Scan ──────────────────────────────────────────────────────────
        scan_result = scan(text=text, agent_id=node_name, source_agent_id=graph_name)

        entry = {
            "timestamp":     time.time(),
            "graph":         graph_name,
            "node":          node_name,
            "input_preview": text[:1000],
            "scan":          scan_result,
        }

        with _log_lock:
            _message_log.append(entry)

        # ── Persist to SQLite ─────────────────────────────────────────────
        write_scan("langgraph", graph_name, node_name, scan_result, text)

        # ── Console alert ─────────────────────────────────────────────────
        if scan_result["detected"]:
            sev = scan_result["severity"]
            col = f"{BG_RED}{WHITE}{BOLD}" if sev == "critical" else f"{YELLOW}{BOLD}"
            layers_hit = ", ".join(
                k for k, v in scan_result.get("layers", {}).items()
                if isinstance(v, dict) and v.get("detected")
            )
            print(
                f"{col}[ANTICIPATOR] {sev.upper()} in '{node_name}'"
                f"{RESET}  layers=({layers_hit})"
                f"  preview={text[:60]!r}"
            )

        return fn(state)

    # Mark so wrapper.py can detect already-wrapped nodes
    intercepted.__wrapped_node__ = node_name
    return intercepted