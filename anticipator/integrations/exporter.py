"""
anticipator.integrations.exporter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
One-shot JSON report writer for scan logs.

Fixes over v1
-------------
- Threat grouping key uses SHA-256 of the full input_preview instead of
  the first 300 chars — two messages with a long shared preamble but
  different payloads no longer collapse into one report entry
- export_json accepts an explicit *log* list OR fetches from interceptor
  if none supplied (unchanged behaviour, just made the default explicit)
- Path handling uses pathlib for cross-platform safety
- Report version bumped to 0.2.0
- Added per-threat layer breakdown to the threats section so the report
  is self-contained (no need to cross-reference scan_json)
- full_log entries include severity breakdown from scan layers
"""

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional


def export_json(
    log: Optional[List[dict]] = None,
    name: str = "graph",
    path: Optional[str] = None,
) -> str:
    """
    Write a structured JSON threat report to *path*.

    Parameters
    ----------
    log:
        List of scan-log entries (from interceptor.get_message_log()).
        If None, fetched automatically from the LangGraph interceptor.
    name:
        Graph / pipeline name embedded in the report metadata.
    path:
        Destination file path. Defaults to ./anticipator_report.json.

    Returns
    -------
    str
        Absolute path of the written report file.
    """
    if log is None:
        from anticipator.integrations.langgraph.interceptor import get_message_log
        log = get_message_log()

    if path is None:
        path = os.path.join(os.getcwd(), "anticipator_report.json")

    # Ensure parent directory exists
    dest = Path(path).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)

    # ── Threat grouping ──────────────────────────────────────────────────────
    # Key: SHA-256 of the full input_preview — prevents preamble collisions
    threats_raw = [r for r in log if r["scan"]["detected"]]
    grouped: dict = {}

    for t in threats_raw:
        preview = t["input_preview"]
        key     = hashlib.sha256(preview.encode("utf-8", errors="replace")).hexdigest()

        if key not in grouped:
            # Extract which layers fired
            layers_hit = [
                layer
                for layer, result in t["scan"].get("layers", {}).items()
                if isinstance(result, dict) and result.get("detected")
            ]
            grouped[key] = {
                "nodes":      [],
                "severity":   t["scan"]["severity"],
                "preview":    preview[:300],
                "layers_hit": layers_hit,
            }
        grouped[key]["nodes"].append(t["node"])

    # ── Report structure ─────────────────────────────────────────────────────
    report = {
        "meta": {
            "graph":     name,
            "generated": datetime.utcnow().isoformat() + "Z",
            "version":   "0.2.0",
        },
        "summary": {
            "total_scanned": len(log),
            "total_threats": len(threats_raw),
            "clean":         len(log) - len(threats_raw),
        },
        "threats": [
            {
                "severity":    data["severity"],
                "propagation": sorted(set(data["nodes"])),
                "layers_hit":  data["layers_hit"],
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
                "input_preview": r["input_preview"][:200],
                # Which layers fired (empty list when clean)
                "layers_hit": [
                    layer
                    for layer, result in r["scan"].get("layers", {}).items()
                    if isinstance(result, dict) and result.get("detected")
                ],
            }
            for r in log
        ],
    }

    with open(dest, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"[ANTICIPATOR] Report exported → {dest}")
    return str(dest)