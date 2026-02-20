import re
import math
from typing import List
from .signatures import CREDENTIAL_PATTERNS

ENTROPY_THRESHOLD = 4.2
LENGTH_THRESHOLD = 20

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        prob = count / len(text)
        entropy -= prob * math.log2(prob)
    return entropy

def find_high_entropy_strings(text: str) -> List[dict]:
    findings = []
    tokens = re.findall(r'[A-Za-z0-9+/=_\-\.]{20,}', text)
    for token in tokens:
        entropy = shannon_entropy(token)
        if entropy > ENTROPY_THRESHOLD and len(token) >= LENGTH_THRESHOLD:
            findings.append({
                "type": "high_entropy",
                "value": token[:10] + "...",
                "entropy": round(entropy, 3),
                "length": len(token)
            })
    return findings

def find_credential_patterns(text: str) -> List[dict]:
    findings = []
    for pattern, label in CREDENTIAL_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            findings.append({
                "type": label,
                "severity": "critical"
            })
    return findings

def detect(text: str) -> dict:
    entropy_findings = find_high_entropy_strings(text)
    regex_findings = find_credential_patterns(text)
    all_findings = entropy_findings + regex_findings

    return {
        "detected": len(all_findings) > 0,
        "findings": all_findings,
        "severity": "critical" if regex_findings else ("warning" if entropy_findings else "none"),
        "layer": "entropy_credential"
    }