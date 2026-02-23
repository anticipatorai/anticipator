import base64
import re
from urllib.parse import unquote
from typing import Optional, List, Dict, Set
from . import aho

MAX_DEPTH = 3

HEX_PATTERN = re.compile(r'\b(?:[0-9a-fA-F]{2}){20,}\b')
BASE64_PATTERN = re.compile(r'(?:[A-Za-z0-9+/]{4}){5,}(?:==|=)?')

def decode_base64(text: str) -> Optional[str]:
    try:
        padding = len(text) % 4
        if padding:
            text += "=" * (4 - padding)

        decoded_bytes = base64.b64decode(text)
        return decoded_bytes.decode("utf-8")
    except Exception:
        return None

def decode_hex(text: str) -> Optional[str]:
    try:
        return bytes.fromhex(text).decode("utf-8")
    except Exception:
        return None

def recursive_scan(text: str,
                   depth: int = 0,
                   seen_texts: Optional[Set[str]] = None) -> List[Dict]:

    if seen_texts is None:
        seen_texts = set()

    if depth > MAX_DEPTH or text in seen_texts:
        return []

    seen_texts.add(text)
    findings = []

    result = aho.detect(text)
    if result["detected"]:
        findings.append({
            "type": "direct",
            "decoded": text,
            "aho_matches": result["matches"]
        })

    for candidate in HEX_PATTERN.findall(text):
        decoded = decode_hex(candidate)
        if decoded and decoded not in seen_texts:
            findings.append({
                "type": "hex",
                "decoded": decoded
            })
            findings += recursive_scan(decoded, depth + 1, seen_texts)

    for candidate in BASE64_PATTERN.findall(text):
        decoded = decode_base64(candidate)
        if decoded and decoded not in seen_texts:
            findings.append({
                "type": "base64",
                "decoded": decoded
            })
            findings += recursive_scan(decoded, depth + 1, seen_texts)

    url_decoded = unquote(text)
    if url_decoded != text and url_decoded not in seen_texts:
        findings.append({
            "type": "url_encoded",
            "decoded": url_decoded
        })
        findings += recursive_scan(url_decoded, depth + 1, seen_texts)

    return findings

def detect(text: str) -> dict:
    findings = recursive_scan(text)

    return {
        "detected": len(findings) > 0,
        "findings": findings,
        "severity": "critical" if findings else "none",
        "layer": "encoding_decoder"
    }

