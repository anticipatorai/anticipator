def observe(graph_or_crew, name="anticipator"):
    try:
        from crewai import Crew
        if isinstance(graph_or_crew, Crew):
            from anticipator.integrations.crewai.wrapper import observe as crewai_observe
            return crewai_observe(graph_or_crew, name)
    except ImportError:
        pass

    try:
        from anticipator.integrations.langgraph.wrapper import observe as lg_observe
        return lg_observe(graph_or_crew, name)
    except Exception:
        raise ValueError(
            "Unsupported object type. Expected CrewAI Crew or LangGraph graph."
        )