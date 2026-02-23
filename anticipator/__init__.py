"""
anticipator
~~~~~~~~~~~
Prompt injection and credential detection for LangGraph agents.

Usage::

    from anticipator import observe

    secure_graph = observe(graph, name="my-pipeline")
    app = secure_graph.compile()
"""

from anticipator.integrations import observe
from anticipator.detection.scanner import scan, scan_async, scan_pipeline

__all__ = ["observe", "scan", "scan_async", "scan_pipeline"]