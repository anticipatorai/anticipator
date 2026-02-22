import os
import json
from datetime import datetime


def export_json(log: list = None, name: str = "graph", path: str = None):
    if path is None:
        path = os.path.join(os.getcwd(), "anticipator_report.json")

    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    if log is None:
        from anticipator.integrations.langgraph.interceptor import get_message_log
        log = get_message_log()

    threats = [r for r in log if r["scan"]["detected"]]

    grouped = {}
    for t in threats:
        key = t["input_preview"][:300]
        if key not in grouped:
            grouped[key] = {"nodes": [], "severity": t["scan"]["severity"], "preview": key}
        grouped[key]["nodes"].append(t["node"])

    report = {
        "meta": {
            "graph": name,
            "generated": datetime.now().isoformat(),
            "version": "0.1.0",
        },
        "summary": {
            "total_scanned": len(log),
            "total_threats": len(threats),
            "clean": len(log) - len(threats),
        },
        "threats": [
            {
                "severity": data["severity"],
                "propagation": list(set(data["nodes"])),
                "preview": data["preview"],
            }
            for data in grouped.values()
        ],
        "full_log": [
            {
                "node": r["node"],
                "timestamp": r["timestamp"],
                "detected": r["scan"]["detected"],
                "severity": r["scan"]["severity"],
                "input_preview": r["input_preview"],
            }
            for r in log
        ],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[ANTICIPATOR] Report exported → {path}")
    return path