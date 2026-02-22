def observe(graph_or_crew, name="anticipator"):
    try:
        from anticipator.integrations.langgraph.wrapper import observe as lg_observe
        return lg_observe(graph_or_crew, name)
    except Exception:
        raise ValueError(
            "Unsupported object type. Expected LangGraph ."
        )