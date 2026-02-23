"""Main scanner — async concurrent scanning with full detection pipeline."""

import asyncio
import time

from anticipator.detection.core.aho import detect as aho_detect
from anticipator.detection.core.encoding import detect as encoding_detect
from anticipator.detection.core.entropy import detect as entropy_detect
from anticipator.detection.core.heuristic import detect as heuristic_detect
from anticipator.detection.core.canary import detect as canary_detect

from anticipator.detection.extended.homoglyph import detect as homoglyph_detect
from anticipator.detection.extended.path_traversal import detect as path_traversal_detect
from anticipator.detection.extended.tool_alias import detect as tool_alias_detect
from anticipator.detection.extended.config_drift import detect as config_drift_detect
from anticipator.detection.extended.threat_categories import detect as threat_categories_detect

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "warning": 1, "none": 0}

# Per-agent-type layer config
AGENT_TYPE_LAYERS = {
    "langgraph": ["aho", "encoding", "entropy", "heuristic", "canary",
                  "homoglyph", "path_traversal", "tool_alias", "threat_categories"],
    "openclaw":  ["aho", "encoding", "entropy", "heuristic", "canary",
                  "homoglyph", "path_traversal", "tool_alias", "threat_categories", "config_drift"],
    "crewai":    ["aho", "encoding", "entropy", "heuristic", "canary",
                  "homoglyph", "threat_categories"],
    "default":   ["aho", "encoding", "entropy", "heuristic", "canary",
                  "homoglyph", "path_traversal", "tool_alias", "threat_categories"],
}


def _highest_severity(severities: list) -> str:
    """Return the highest severity from a list."""
    return max(severities, key=lambda s: SEVERITY_RANK.get(s, 0), default="none")


def _to_dict(result) -> dict:
    """
    Convert a DetectionResult (or any non-dict return) to a plain dict.
    Handles dataclasses, namedtuples, and objects with __dict__.
    Does NOT recurse — use _sanitize() for deep conversion.
    """
    if isinstance(result, dict):
        return result
    if hasattr(result, "__dict__"):
        return vars(result)
    if hasattr(result, "_asdict"):
        return result._asdict()
    return dict(result)


def _sanitize(obj):
    """
    Recursively convert an arbitrary object tree into a structure that is
    fully JSON-serialisable (dicts, lists, str, int, float, bool, None).

    Handles:
      - dict             -> recurse into values
      - list / tuple     -> recurse into elements (tuples become lists)
      - str/int/float/
        bool/None        -> returned as-is
      - dataclass /
        object w/ vars   -> converted via vars(), then recursed
      - namedtuple       -> converted via _asdict(), then recursed
      - anything else    -> str() fallback so serialisation never fails
    """
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj

    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple)):
        return [_sanitize(item) for item in obj]

    # namedtuple — check before __dict__ because namedtuples have both
    if hasattr(obj, "_asdict"):
        return _sanitize(obj._asdict())

    # dataclass / regular class instance
    if hasattr(obj, "__dict__"):
        return _sanitize(vars(obj))

    # Last resort — stringify so json.dumps never raises
    return str(obj)


def _run_layer(layer_name: str, text: str, agent_id: str,
               source_agent_id: str, pipeline_position: int,
               requested_tool: str = None) -> dict:
    """Run a single detection layer and attach location metadata."""
    start = time.perf_counter()

    if layer_name == "aho":
        result = aho_detect(text)
    elif layer_name == "encoding":
        result = encoding_detect(text)
    elif layer_name == "entropy":
        result = entropy_detect(text)
    elif layer_name == "heuristic":
        result = heuristic_detect(text)
    elif layer_name == "canary":
        result = canary_detect(text, source_agent_id or "unknown", agent_id) if source_agent_id else {"detected": False, "severity": "none", "layer": "canary"}
    elif layer_name == "homoglyph":
        result = homoglyph_detect(text)
    elif layer_name == "path_traversal":
        result = path_traversal_detect(text)
    elif layer_name == "tool_alias":
        result = tool_alias_detect(text, requested_tool)
    elif layer_name == "threat_categories":
        result = threat_categories_detect(text)
    elif layer_name == "config_drift":
        result = {}  # config_drift called separately with config dict
    else:
        result = {"detected": False, "severity": "none", "layer": layer_name}

    elapsed_ms = (time.perf_counter() - start) * 1000

    # Convert top-level DetectionResult to dict, then deep-sanitize the
    # entire tree so nested Finding / Match / etc. objects don't survive
    # to json.dumps() in monitor.py
    result = _sanitize(_to_dict(result))

    # Attach line-level evidence
    result["location"] = {
        "agent_id": agent_id,
        "source_agent_id": source_agent_id,
        "pipeline_position": pipeline_position,
        "scan_ms": round(elapsed_ms, 3)
    }

    return result


def scan(
    text: str,
    agent_id: str = "unknown",
    source_agent_id: str = None,
    pipeline_position: int = 0,
    agent_type: str = "default",
    requested_tool: str = None,
    current_config: dict = None,
) -> dict:
    """
    Synchronous scan — runs all detection layers for the given agent type.
    Returns structured result with severity, findings, location evidence, summary.
    """
    start_total = time.perf_counter()

    layers_to_run = AGENT_TYPE_LAYERS.get(agent_type, AGENT_TYPE_LAYERS["default"])

    layer_results = {}
    for layer_name in layers_to_run:
        layer_results[layer_name] = _run_layer(
            layer_name, text, agent_id,
            source_agent_id, pipeline_position, requested_tool
        )

    # Config drift needs a config dict
    if current_config and agent_type == "openclaw":
        config_result = _sanitize(_to_dict(config_drift_detect(current_config)))
        config_result["location"] = {
            "agent_id": agent_id,
            "pipeline_position": pipeline_position
        }
        layer_results["config_drift"] = config_result

    # Aggregate severity
    all_severities = [r.get("severity", "none") for r in layer_results.values()]
    final_severity = _highest_severity(all_severities)
    detected = any(r.get("detected", False) for r in layer_results.values())

    # Summary by severity
    summary = {"critical": 0, "high": 0, "medium": 0, "warning": 0, "total": 0}
    for r in layer_results.values():
        if r.get("detected"):
            sev = r.get("severity", "none")
            if sev in summary:
                summary[sev] += 1
            summary["total"] += 1

    total_ms = (time.perf_counter() - start_total) * 1000

    return {
        "detected": detected,
        "severity": final_severity,
        "agent_id": agent_id,
        "source_agent_id": source_agent_id,
        "pipeline_position": pipeline_position,
        "agent_type": agent_type,
        "input_preview": text[:100],
        "layers": layer_results,
        "summary": summary,
        "total_scan_ms": round(total_ms, 3)
    }


async def scan_async(
    text: str,
    agent_id: str = "unknown",
    source_agent_id: str = None,
    pipeline_position: int = 0,
    agent_type: str = "default",
    requested_tool: str = None,
    timeout: float = 0.005,  # 5ms timeout per scan
) -> dict:
    """Async version — use for concurrent multi-message scanning."""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: scan(text, agent_id, source_agent_id,
                             pipeline_position, agent_type, requested_tool)
            ),
            timeout=timeout
        )
        return result
    except asyncio.TimeoutError:
        return {
            "detected": False,
            "severity": "none",
            "error": "scan_timeout",
            "agent_id": agent_id,
            "pipeline_position": pipeline_position,
            "total_scan_ms": timeout * 1000
        }


async def scan_pipeline(
    messages: list,
    agent_type: str = "default",
    concurrency: int = 10,
) -> list:
    """
    Scan multiple inter-agent messages concurrently with semaphore control.

    messages: list of dicts with keys:
        text, agent_id, source_agent_id, pipeline_position, requested_tool (optional)
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded_scan(msg: dict) -> dict:
        async with semaphore:
            return await scan_async(
                text=msg.get("text", ""),
                agent_id=msg.get("agent_id", "unknown"),
                source_agent_id=msg.get("source_agent_id"),
                pipeline_position=msg.get("pipeline_position", 0),
                agent_type=agent_type,
                requested_tool=msg.get("requested_tool"),
            )

    tasks = [_bounded_scan(msg) for msg in messages]
    return await asyncio.gather(*tasks)