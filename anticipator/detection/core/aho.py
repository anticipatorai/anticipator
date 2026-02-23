import re
from typing import Any

import ahocorasick

from anticipator.detection.core.normalizer import normalize
from anticipator.detection.signatures import (
    ADJECTIVES,
    DIRECT_PHRASES,
    OBJECTS,
    PREPOSITIONS,
    VERBS,
)


_WINDOW = 80


def _build(words: list[str]) -> ahocorasick.Automaton:
    """Build an Aho-Corasick automaton from a flat word/phrase list."""
    A = ahocorasick.Automaton()
    seen: set[str] = set()
    for i, raw in enumerate(words):
        w = normalize(raw)
        if w and w not in seen:
            seen.add(w)
            A.add_word(w, (i, w))
    A.make_automaton()
    return A


print("[ANTICIPATOR] Loading detection engine...", flush=True)

_DIRECT_AC = _build(DIRECT_PHRASES)           # ~300 phrases  exact match
_VERB_AC   = _build(VERBS)                    # ~60  words    proximity trigger
_OBJECT_AC = _build(OBJECTS)                  # ~60  words    proximity target

print("[ANTICIPATOR] Detection engine ready.", flush=True)


_STRUCTURAL: list[tuple[re.Pattern, str]] = [

    (re.compile(r'you\s+are\s+now\s+\w',               re.I), 'role_switch'),
    (re.compile(r'act\s+as\s+(a|an|if)\s+\w',          re.I), 'act_as'),
    (re.compile(r'pretend\s+(you\s+are|to\s+be)\s+\w', re.I), 'pretend'),
    (re.compile(r'from\s+now\s+on\s+you',               re.I), 'from_now_on'),

    (re.compile(r'base64\s*(decode|encoded)',           re.I), 'base64_instruction'),
    (re.compile(r'(decode|translate)\s+and\s+(run|execute|follow)', re.I), 'decode_execute'),

    (re.compile(r'i\s+am\s+(the\s+)?(admin|developer|creator|operator)', re.I), 'authority_claim'),
    (re.compile(r'this\s+(has\s+been\s+)?(pre.?approved|authorized)',    re.I), 'preapproved_claim'),

    (re.compile(r'you\s+(must|have\s+to|are\s+required\s+to)\s+(comply|answer|respond)', re.I), 'forced_compliance'),
    (re.compile(r'do\s+not\s+(say\s+no|refuse|add\s+(warnings?|disclaimers?))', re.I), 'refuse_suppression'),

    (re.compile(r'(developer|god|unrestricted|maintenance)\s+mode\s+(enabled|activated|on)', re.I), 'mode_switch'),
    (re.compile(r'you\s+(are\s+)?(jail\s*broken|have\s+no\s+rules)', re.I), 'jailbreak_claim'),

    (re.compile(r'(print|dump|show|reveal|output)\s+(your\s+)?(system\s+prompt|env|config|keys?|tokens?)', re.I), 'credential_extraction'),
]


def detect(text: str) -> dict:
    normalized = normalize(text)
    matches: list[dict[str, Any]] = []

    for end, (_, pattern) in _DIRECT_AC.iter(normalized):
        start = end - len(pattern) + 1
        matches.append({
            "type":    "direct",
            "pattern": pattern,
            "span":    (start, end),
        })

    for verb_end, (_, verb) in _VERB_AC.iter(normalized):
        verb_start = verb_end - len(verb) + 1

        win_lo = max(0, verb_start - _WINDOW)
        win_hi = min(len(normalized), verb_end + _WINDOW)
        window = normalized[win_lo:win_hi]

        for _, (_, obj) in _OBJECT_AC.iter(window):
            matches.append({
                "type":   "proximity",
                "verb":   verb,
                "object": obj,
                "span":   (verb_start, verb_end),
            })
            break   

    for pattern, label in _STRUCTURAL:
        m = pattern.search(normalized)
        if m:
            matches.append({
                "type":    "structural",
                "pattern": label,
                "span":    m.span(),
            })

    return {
        "detected": bool(matches),
        "matches":  matches,
        "severity": "critical" if matches else "none",
        "layer":    "aho_corasick",
    }