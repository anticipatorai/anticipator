"""
anticipator.detection.extended.path_traversal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Path traversal detector — catches directory escape and sensitive file
access attempts in agent messages.

Fixes over v1
-------------
- Added %252e%252e (double URL-encoded dot-dot)
- Added ....// (four-dot variant)
- Added Windows UNC paths \\server\share
- Added /dev/ and /tmp/ (relevant in agent sandbox contexts)
- Added ~/ and $HOME (home-dir relative access)
- Added /var/log/, /boot/, /lib/ (common LFI targets)
- Added Windows sensitive paths (SAM, NTDS, win.ini, hosts)
- Compile all patterns at module load (not per-call)
"""

import re
from typing import NamedTuple


class _Pattern(NamedTuple):
    regex: re.Pattern
    label: str
    severity: str


# ── Traversal mechanics ──────────────────────────────────────────────────────

_TRAVERSAL_PATTERNS: list[_Pattern] = [
    _Pattern(re.compile(r'\.\.[\\/]',        re.IGNORECASE), 'dot_dot_slash',              'high'),
    _Pattern(re.compile(r'\.\.%2[fF]',       re.IGNORECASE), 'encoded_dot_dot_slash',      'high'),
    _Pattern(re.compile(r'\.\.%5[cC]',       re.IGNORECASE), 'encoded_dot_dot_backslash',  'high'),
    _Pattern(re.compile(r'%2e%2e[\\/]',      re.IGNORECASE), 'double_encoded_traversal',   'high'),
    _Pattern(re.compile(r'%252e%252e',       re.IGNORECASE), 'double_url_encoded_dot_dot', 'high'),
    _Pattern(re.compile(r'\.\.\.\.//',),                      'four_dot_traversal',         'high'),
    _Pattern(re.compile(r'\.\./'),                            'unix_traversal',             'high'),
    _Pattern(re.compile(r'\.\.[\\]'),                         'windows_traversal',          'high'),
    # Windows UNC path  \\server\share or //server/share
    _Pattern(re.compile(r'(\\\\|//)[A-Za-z0-9_\-]+[/\\][A-Za-z0-9_\-$]+'),
             'unc_path', 'high'),
    # Home-relative
    _Pattern(re.compile(r'(~/|~\\|\$HOME/)'), 'home_relative_path', 'high'),
]

# ── Forbidden paths ───────────────────────────────────────────────────────────

_FORBIDDEN_PATTERNS: list[_Pattern] = [
    # Linux / Unix system files
    _Pattern(re.compile(r'/etc/passwd',   re.IGNORECASE), 'passwd_file',      'critical'),
    _Pattern(re.compile(r'/etc/shadow',   re.IGNORECASE), 'shadow_file',      'critical'),
    _Pattern(re.compile(r'/etc/sudoers',  re.IGNORECASE), 'sudoers_file',     'critical'),
    _Pattern(re.compile(r'/etc/ssh/',     re.IGNORECASE), 'ssh_config_dir',   'critical'),
    _Pattern(re.compile(r'/etc/hosts',    re.IGNORECASE), 'hosts_file',       'high'),
    _Pattern(re.compile(r'/root/',        re.IGNORECASE), 'root_directory',   'critical'),
    _Pattern(re.compile(r'/proc/',        re.IGNORECASE), 'proc_directory',   'critical'),
    _Pattern(re.compile(r'/sys/',         re.IGNORECASE), 'sys_directory',    'high'),
    _Pattern(re.compile(r'/dev/',         re.IGNORECASE), 'dev_directory',    'high'),
    _Pattern(re.compile(r'/tmp/',         re.IGNORECASE), 'tmp_directory',    'high'),
    _Pattern(re.compile(r'/var/log/',     re.IGNORECASE), 'var_log',          'high'),
    _Pattern(re.compile(r'/boot/',        re.IGNORECASE), 'boot_directory',   'critical'),
    _Pattern(re.compile(r'/lib/',         re.IGNORECASE), 'lib_directory',    'high'),
    # SSH & cloud credentials
    _Pattern(re.compile(r'\.ssh/id_rsa',          re.IGNORECASE), 'ssh_private_key',   'critical'),
    _Pattern(re.compile(r'\.ssh/authorized_keys',  re.IGNORECASE), 'ssh_auth_keys',    'critical'),
    _Pattern(re.compile(r'\.aws/credentials',      re.IGNORECASE), 'aws_credentials',  'critical'),
    _Pattern(re.compile(r'\.aws/config',           re.IGNORECASE), 'aws_config',       'high'),
    _Pattern(re.compile(r'\.kube/config',          re.IGNORECASE), 'kube_config',      'critical'),
    _Pattern(re.compile(r'gcloud/credentials',     re.IGNORECASE), 'gcloud_credentials','critical'),
    # Windows sensitive paths
    _Pattern(re.compile(r'C:[/\\]Windows[/\\]System32', re.IGNORECASE), 'system32',    'critical'),
    _Pattern(re.compile(r'C:[/\\]Windows[/\\]System32[/\\]config[/\\]SAM', re.IGNORECASE),
             'windows_sam', 'critical'),
    _Pattern(re.compile(r'NTDS\.dit',              re.IGNORECASE), 'ntds_dit',         'critical'),
    _Pattern(re.compile(r'win\.ini',               re.IGNORECASE), 'win_ini',          'high'),
    _Pattern(re.compile(r'C:[/\\]Windows[/\\]System32[/\\]drivers[/\\]etc[/\\]hosts', re.IGNORECASE),
             'windows_hosts', 'high'),
    # Docker / container
    _Pattern(re.compile(r'/var/run/docker\.sock',  re.IGNORECASE), 'docker_socket',    'critical'),
    _Pattern(re.compile(r'run/secrets/',           re.IGNORECASE), 'docker_secrets',   'critical'),
]


def detect(text: str) -> dict:
    findings = []

    for pat in _TRAVERSAL_PATTERNS:
        if pat.regex.search(text):
            findings.append({
                "type": "path_traversal",
                "pattern": pat.label,
                "severity": pat.severity,
            })

    for pat in _FORBIDDEN_PATTERNS:
        if pat.regex.search(text):
            findings.append({
                "type": "forbidden_path",
                "pattern": pat.label,
                "severity": pat.severity,
            })

    if any(f["severity"] == "critical" for f in findings):
        severity = "critical"
    elif findings:
        severity = "high"
    else:
        severity = "none"

    return {
        "detected": bool(findings),
        "findings": findings,
        "severity": severity,
        "layer": "path_traversal",
    }