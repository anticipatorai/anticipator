"""
anticipator.detection.extended
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Extended detection layers — enabled per agent type in scanner.py.

    from anticipator.detection.extended.homoglyph       import detect as homoglyph_detect
    from anticipator.detection.extended.path_traversal  import detect as path_traversal_detect
    from anticipator.detection.extended.tool_alias      import detect as tool_alias_detect
    from anticipator.detection.extended.config_drift    import detect as config_drift_detect
    from anticipator.detection.extended.threat_categories import detect as threat_categories_detect
"""
from .homoglyph        import detect as homoglyph_detect
from .path_traversal   import detect as path_traversal_detect
from .tool_alias       import detect as tool_alias_detect
from .config_drift     import detect as config_drift_detect
from .threat_categories import detect as threat_categories_detect

__all__ = [
    "homoglyph_detect",
    "path_traversal_detect",
    "tool_alias_detect",
    "config_drift_detect",
    "threat_categories_detect",
]