import re
import string

def detect(text: str) -> dict:
    findings = []
    normalized = text.lower().translate(str.maketrans("", "", string.punctuation))

    if re.search(r'(\b\w\s){4,}', normalized):
        findings.append({"type": "char_spacing", "severity": "warning"})

    if re.search(r'(.)\1{4,}', text):
        findings.append({"type": "char_repetition", "severity": "warning"})

    if len(text) > 20 and text.upper() == text:
        findings.append({"type": "all_caps", "severity": "warning"})

    role_patterns = r'you are now|act as|pretend to be|roleplay as|simulate|from now on you'
    if re.search(role_patterns, normalized):
        findings.append({"type": "role_switch", "severity": "warning"})

    for word in text.split():
        if len(word) > 40:
            findings.append({"type": "long_token", "severity": "warning"})

    if re.match(r'^[A-Za-z0-9+/=]{40,}$', text.replace("\n", "")):
        findings.append({"type": "encoded_string", "severity": "warning"})

    return {
        "detected": len(findings) > 0,
        "findings": findings,
        "severity": "warning" if findings else "none",
        "layer": "heuristic"
    }

