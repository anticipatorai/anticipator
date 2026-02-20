from anticipator.detection.aho import detect as aho_detect
from anticipator.detection.encoding import detect as encoding_detect
from anticipator.detection.entropy import detect as entropy_detect
from anticipator.detection.heuristic import detect as heuristic_detect
from anticipator.detection.canary import detect as canary_detect, inject_canary

def scan(text: str, agent_id: str = "unknown", source_agent_id: str = None) -> dict:
    results = {
        "agent_id": agent_id,
        "input": text[:100],
        "layers": {},
        "detected": False,
        "severity": "none"
    }

    results["layers"]["aho"] = aho_detect(text)
    results["layers"]["encoding"] = encoding_detect(text)
    results["layers"]["entropy"] = entropy_detect(text)
    results["layers"]["heuristic"] = heuristic_detect(text)

    if source_agent_id:
        results["layers"]["canary"] = canary_detect(text, source_agent_id, agent_id)

    for layer, result in results["layers"].items():
        if result["detected"]:
            results["detected"] = True
            if result["severity"] == "critical":
                results["severity"] = "critical"
            elif results["severity"] == "none":
                results["severity"] = "warning"

    return results
