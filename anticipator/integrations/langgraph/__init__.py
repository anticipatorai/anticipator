"""
anticipator.integrations.langgraph
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
LangGraph integration package.

Drop-in usage::

    from anticipator.integrations.langgraph import observe

    graph = StateGraph(MyState)
    # ... add_node / add_edge ...

    secure_graph = observe(graph, name="my-pipeline")
    app = secure_graph.compile()

    result = app.invoke({"input": "hello"})
    app.report()          # print threat summary to stdout
    app.monitor()         # print persistent DB summary
    app.export_report()   # write JSON to ./anticipator_report.json

What observe() does
-------------------
Wraps every non-system node in the StateGraph with a transparent
interceptor that:
  - Extracts the text payload from the node state (handles str, dict,
    LangChain BaseMessage, arbitrary objects)
  - Runs the full Anticipator detection pipeline (aho-corasick, encoding,
    entropy, heuristic, homoglyph, path traversal, tool alias, canary,
    threat categories)
  - Logs detections to an in-memory list AND a persistent SQLite store
  - Prints a coloured console alert for critical/high findings
  - Passes the state through unchanged — smoke-detector mode, never blocks
"""

from .wrapper import ObservableGraph, observe

__all__ = ["observe", "ObservableGraph"]