"""
JSON Report Exporter
Structured export of all scans, threats, and node paths.
"""
import json
from datetime import datetime
from interceptor import get_message_log


def export_json(name: str = "graph", path: str = "anticipator_report.json"):
    log     = get_message_log()
    threats = [r for r in log if r["scan"]["detected"]]

    # Group threats by content
    grouped = {}
    for t in threats:
        key = t["input_preview"][:80]
        if key not in grouped:
            grouped[key] = {"nodes": [], "severity": t["scan"]["severity"], "preview": key}
        grouped[key]["nodes"].append(t["node"])

    report = {
        "meta": {
            "graph":      name,
            "generated":  datetime.now().isoformat(),
            "version":    "0.1.0",
        },
        "summary": {
            "total_scanned": len(log),
            "total_threats": len(threats),
            "clean":         len(log) - len(threats),
        },
        "threats": [
            {
                "severity":    data["severity"],
                "propagation": data["nodes"],
                "preview":     data["preview"],
            }
            for data in grouped.values()
        ],
        "full_log": [
            {
                "node":          r["node"],
                "timestamp":     r["timestamp"],
                "detected":      r["scan"]["detected"],
                "severity":      r["scan"]["severity"],
                "input_preview": r["input_preview"],
            }
            for r in log
        ]
    }

    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[ANTICIPATOR] Report exported → {path}")
    return path