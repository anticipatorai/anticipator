"""
anticipator.detection.extended.config_drift
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Config drift monitor — detects unauthorized changes to agent configuration
mid-run, including new key injection attacks.

Fixes over v1
-------------
- NEW: flags keys that appear in current config but not in baseline
  (injection of tools.allow, elevated, etc.)
- NEW: flags keys that disappear from baseline (removal of tools.deny
  is as dangerous as adding tools.allow)
- _flatten: now handles list values (converts to frozenset for comparison)
- set_baseline: thread-safe copy, doesn't hold reference to caller's dict
"""

import copy
import threading
from typing import Any

IMMUTABLE_KEYS = [
    "agent_id",
    "workspace",
    "sandbox.mode",
    "tools.deny",
]

SENSITIVE_KEYS = [
    "model",
    "elevated",
    "send_policy",
    "thinking_level",
]

# Keys whose *addition* is high-risk (not just modification)
INJECTION_RISK_KEYS = [
    "tools.allow",
    "elevated",
    "permissions",
    "sandbox.bypass",
    "debug",
    "unsafe_mode",
]

_baseline_config: dict = {}
_lock = threading.Lock()


def set_baseline(config: dict) -> None:
    """Call once at pipeline start to register the expected config snapshot."""
    global _baseline_config
    with _lock:
        _baseline_config = _flatten(copy.deepcopy(config))


def _normalize_value(v: Any) -> Any:
    """Normalize value for stable comparison (lists → frozenset)."""
    if isinstance(v, list):
        return frozenset(str(i) for i in v)
    return v


def _flatten(d: dict, prefix: str = "") -> dict:
    """Flatten nested dict to dot-notation keys with normalized values."""
    result = {}
    for k, v in d.items():
        full_key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            result.update(_flatten(v, full_key))
        else:
            result[full_key] = _normalize_value(v)
    return result


def detect(current_config: dict) -> dict:
    findings = []

    with _lock:
        baseline = dict(_baseline_config)   # snapshot under lock

    if not baseline:
        return {
            "detected": False,
            "findings": [],
            "severity": "none",
            "layer": "config_drift",
            "note": "no baseline set — call set_baseline() at pipeline start",
        }

    current_flat = _flatten(current_config)

    # ── 1. Immutable keys changed ────────────────────────────────────────────
    for key in IMMUTABLE_KEYS:
        b_val = baseline.get(key)
        c_val = current_flat.get(key)
        if b_val is not None and c_val is not None and b_val != c_val:
            findings.append({
                "type": "immutable_key_changed",
                "key": key,
                "baseline": str(b_val),
                "current": str(c_val),
                "severity": "critical",
            })

    # ── 2. Sensitive keys changed ────────────────────────────────────────────
    for key in SENSITIVE_KEYS:
        b_val = baseline.get(key)
        c_val = current_flat.get(key)
        if b_val is not None and c_val is not None and b_val != c_val:
            findings.append({
                "type": "sensitive_key_changed",
                "key": key,
                "baseline": str(b_val),
                "current": str(c_val),
                "severity": "high",
            })

    # ── 3. New keys injected (not in baseline) ───────────────────────────────
    new_keys = set(current_flat) - set(baseline)
    for key in new_keys:
        severity = "critical" if key in INJECTION_RISK_KEYS else "high"
        findings.append({
            "type": "new_key_injected",
            "key": key,
            "value": str(current_flat[key]),
            "severity": severity,
        })

    # ── 4. Keys removed (not in current) ────────────────────────────────────
    removed_keys = set(baseline) - set(current_flat)
    for key in removed_keys:
        # Removal of deny-list or sandbox keys is critical
        severity = "critical" if key in IMMUTABLE_KEYS else "high"
        findings.append({
            "type": "key_removed",
            "key": key,
            "baseline_value": str(baseline[key]),
            "severity": severity,
        })

    worst = "none"
    if any(f["severity"] == "critical" for f in findings):
        worst = "critical"
    elif findings:
        worst = "high"

    return {
        "detected": bool(findings),
        "findings": findings,
        "severity": worst,
        "layer": "config_drift",
    }