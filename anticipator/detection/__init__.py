"""
anticipator.detection
~~~~~~~~~~~~~~~~~~~~~
Top-level detection package.
Import the scanner for all scanning needs.

    from anticipator.detection.scanner import scan, scan_async, scan_pipeline
"""
from .scanner import scan, scan_async, scan_pipeline

__all__ = ["scan", "scan_async", "scan_pipeline"]