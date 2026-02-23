"""
anticipator.integrations
~~~~~~~~~~~~~~~~~~~~~~~~~
Top-level integration package.

Provides a framework-aware observe() entry point.

Supported frameworks
--------------------
- LangGraph  (StateGraph / CompiledStateGraph)  ← active
- CrewAI     (Crew)                             ← add integrations/crewai/ to enable

Usage::

    from anticipator.integrations import observe

    secure_graph = observe(graph, name="my-pipeline")
    app = secure_graph.compile()

    # Or import the LangGraph integration directly:
    from anticipator.integrations.langgraph import observe
"""

from __future__ import annotations

from typing import Any


def observe(graph: Any, name: str = "anticipator") -> Any:
    """
    Route *graph* to the correct framework wrapper.

    Currently supports LangGraph (StateGraph / CompiledStateGraph).
    CrewAI support: add integrations/crewai/ and uncomment the block below.

    Raises
    ------
    ImportError
        If langgraph is not installed or the wrapper cannot be loaded.
    """
    # ── LangGraph ─────────────────────────────────────────────────────────────
    try:
        from langgraph.graph import StateGraph                      # type: ignore
        from langgraph.graph.state import CompiledStateGraph        # type: ignore
        if isinstance(graph, (StateGraph, CompiledStateGraph)):
            from anticipator.integrations.langgraph.wrapper import observe as lg_observe
            return lg_observe(graph, name)
    except ImportError:
        pass 
    
    try:
        from anticipator.integrations.langgraph.wrapper import observe as lg_observe
        return lg_observe(graph, name)
    except ImportError as exc:
        raise ImportError(
            f"No integration available for graph type {type(graph).__name__!r}. "
            f"Install langgraph or add the appropriate integrations/ sub-package. "
            f"Underlying error: {exc}"
        ) from exc


__all__ = ["observe"]