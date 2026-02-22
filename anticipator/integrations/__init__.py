def observe(graph, name="anticipator"):
    try:
        from anticipator.integrations.langgraph.wrapper import observe as lg_observe
        return lg_observe(graph, name)
    except ImportError as e:
        raise ImportError(f"LangGraph integration not available: {e}")