from wrapper import ObservableGraph


def observe(graph, name: str = "langgraph") -> ObservableGraph:
    """
    Wrap any LangGraph StateGraph with Anticipator threat detection.

    Drop-in usage:
        from integrations.langgraph import observe

        graph = StateGraph(...)  # your existing graph
        graph = graph.compile()

        secure_graph = observe(graph)
        result = secure_graph.invoke({"input": "hello"})

    Detections run on every node's input automatically:
        - Prompt injection (Aho-Corasick + encoding + heuristics)
        - Credential leakage (regex + entropy)
        - Canary word tampering (if source agent is known)

    No messages are blocked — smoke detector mode only.
    Use secure_graph.report() to see a threat summary.
    """
    return ObservableGraph(graph, name=name)