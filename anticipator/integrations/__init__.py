from __future__ import annotations

from typing import Any


def observe(graph: Any, name: str = "anticipator") -> Any:

    try:
        from langgraph.graph import StateGraph                      
        from langgraph.graph.state import CompiledStateGraph        
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