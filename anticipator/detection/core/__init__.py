"""
anticipator.detection.core
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Core detection layers — run on every agent type.

    from anticipator.detection.core.aho       import detect as aho_detect
    from anticipator.detection.core.encoding  import detect as encoding_detect
    from anticipator.detection.core.entropy   import detect as entropy_detect
    from anticipator.detection.core.heuristic import detect as heuristic_detect
    from anticipator.detection.core.canary    import detect as canary_detect
    from anticipator.detection.core.normalizer import normalize
"""
from .aho       import detect as aho_detect
from .encoding  import detect as encoding_detect
from .entropy   import detect as entropy_detect
from .heuristic import detect as heuristic_detect
from .canary    import detect as canary_detect
from .normalizer import normalize

__all__ = [
    "aho_detect",
    "encoding_detect",
    "entropy_detect",
    "heuristic_detect",
    "canary_detect",
    "normalize",
]