"""
anticipator.detection.extended.tool_alias
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tool alias normalizer — catches tool policy bypass via alias confusion.
Agents may request dangerous capabilities under friendly names.

Fixes over v1
-------------
- `import re` moved to module level (was buried inside detect())
- Added script runner aliases: node, python, python3, ruby, perl, php
- Added eval — common alias confusion vector in agent tool definitions
- Added nc (netcat), nmap, curl variants
- Compiled bypass patterns at module load
- High-risk tool set expanded to include process and write_file variants
"""

import re

# ── Alias → canonical tool name ──────────────────────────────────────────────

TOOL_ALIASES: dict[str, str] = {
    # Shell execution
    "bash":         "exec",
    "sh":           "exec",
    "shell":        "exec",
    "terminal":     "exec",
    "cmd":          "exec",
    "powershell":   "exec",
    "pwsh":         "exec",
    "run_command":  "exec",
    "os_command":   "exec",
    "system_call":  "exec",
    "subprocess":   "exec",
    "eval":         "exec",   # eval == arbitrary execution
    # Script runners
    "python":       "exec",
    "python3":      "exec",
    "node":         "exec",
    "nodejs":       "exec",
    "ruby":         "exec",
    "perl":         "exec",
    "php":          "exec",
    "lua":          "exec",
    # File read
    "read":         "read_file",
    "file_read":    "read_file",
    "open_file":    "read_file",
    "get_contents": "read_file",
    "cat_file":     "read_file",
    "cat":          "read_file",
    "less":         "read_file",
    "more":         "read_file",
    "head":         "read_file",
    "tail":         "read_file",
    # File write
    "write":        "write_file",
    "save_file":    "write_file",
    "file_write":   "write_file",
    "put_file":     "write_file",
    "tee":          "write_file",
    # Network
    "http":         "http_request",
    "fetch":        "http_request",
    "curl":         "http_request",
    "wget":         "http_request",
    "request":      "http_request",
    "download":     "http_request",
    "post":         "http_request",
    "get":          "http_request",
    "nc":           "http_request",     # netcat
    "netcat":       "http_request",
    "nmap":         "http_request",     # network scan
}

TOOL_GROUPS: dict[str, list[str]] = {
    "group:fs":       ["read_file", "write_file", "edit", "apply_patch"],
    "group:runtime":  ["exec", "process"],
    "group:memory":   ["memory_search", "memory_get"],
    "group:web":      ["web_search", "http_request"],
    "group:sessions": ["sessions_list", "sessions_history",
                       "sessions_send", "sessions_spawn"],
}

HIGH_RISK_TOOLS: frozenset[str] = frozenset({
    "exec",
    "process",
    "write_file",
    "http_request",
    "sessions_spawn",
})

# ── Bypass patterns — compiled at module load ─────────────────────────────────

_BYPASS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'use\s+(?:the\s+)?["\']?(?:bash|shell|terminal|cmd|powershell)["\']?\s+to\s+run',
                re.IGNORECASE), 'shell_alias_request'),
    (re.compile(r'call\s+["\']?(?:exec|subprocess|system|eval)["\']?',
                re.IGNORECASE), 'exec_alias_request'),
    (re.compile(r'invoke\s+["\']?(?:terminal|shell|bash|powershell)["\']?',
                re.IGNORECASE), 'terminal_invoke'),
    (re.compile(r'run\s+(?:a\s+)?(?:python|node|ruby|perl|php|bash)\s+script',
                re.IGNORECASE), 'script_runner_request'),
    (re.compile(r'(?:execute|run)\s+(?:this\s+)?(?:code|script|command)',
                re.IGNORECASE), 'generic_code_execution'),
    (re.compile(r'(?:netcat|nc|nmap)\s+-',
                re.IGNORECASE), 'network_tool_with_flag'),
]


def normalize_tool_name(name: str) -> str:
    """Resolve alias to canonical tool name."""
    return TOOL_ALIASES.get(name.strip().lower(), name.strip().lower())


def expand_group(group: str) -> list[str]:
    """Expand a tool group to individual tool names."""
    return TOOL_GROUPS.get(group, [])


def detect(text: str, requested_tool: str | None = None) -> dict:
    findings: list[dict] = []

    # ── Requested tool alias check ───────────────────────────────────────────
    if requested_tool:
        normalized = normalize_tool_name(requested_tool)

        if normalized != requested_tool.strip().lower():
            findings.append({
                "type": "alias_detected",
                "original": requested_tool,
                "resolves_to": normalized,
                "severity": "high" if normalized in HIGH_RISK_TOOLS else "medium",
            })

        if normalized in HIGH_RISK_TOOLS:
            findings.append({
                "type": "high_risk_tool",
                "tool": normalized,
                "severity": "high",
            })

    # ── Text bypass pattern scan ─────────────────────────────────────────────
    for pattern, label in _BYPASS_PATTERNS:
        if pattern.search(text):
            findings.append({
                "type": "tool_bypass_attempt",
                "pattern": label,
                "severity": "high",
            })

    return {
        "detected": bool(findings),
        "findings": findings,
        "severity": "high" if findings else "none",
        "layer": "tool_alias",
    }