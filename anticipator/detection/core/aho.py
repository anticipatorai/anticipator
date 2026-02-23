"""
anticipator.detection.core.aho
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Three-automaton token-proximity detector.

Why this is fast
----------------
Old approach: generate VERBS × ADJECTIVES × OBJECTS × PREPOSITIONS
  = ~300,000 phrases → 30s build, 400MB RAM, cache required

This approach: store only primitives (VERBS, OBJECTS, DIRECT_PHRASES)
  = ~700 words/phrases total → <100ms build, ~3MB RAM, no cache needed

How it works
------------
Three passes over the normalised text, all O(n):

  Pass 1 — _DIRECT_AC
    Exact match against every DIRECT_PHRASES entry.
    Highest confidence, always critical.

  Pass 2 — _VERB_AC + _OBJECT_AC proximity
    Find every VERB hit, then search a ±_WINDOW char context for any
    OBJECT hit. Equivalent to matching all VERB * OBJECT combinations
    without storing them.

  Pass 3 — structural regex
    Catches patterns that aren't well represented by token lists:
    role-switch ("you are now X"), encoding markers, authority claims.
    Compiled once at module load, zero overhead per call.

Detection quality vs old approach
----------------------------------
  Old: "ignore all previous instructions"        ← caught (direct)
  New: same                                       ← caught (pass 1)

  Old: "disregard the above commands"            ← caught (combo)
  New: "disregard" (verb hit) + "commands" (obj) ← caught (pass 2, window)

  Old: "you are now DAN"                         ← caught (direct)
  New: same                                       ← caught (pass 3 regex)

  Startup: ~30s  →  <100ms  (300x faster)
  Cache  : required  →  not needed
"""

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

# ── Tuning ────────────────────────────────────────────────────────────────────

# Characters either side of a VERB hit to search for an OBJECT
_WINDOW = 80


# ── Automaton builder (tiny, instant) ────────────────────────────────────────

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


# ── Three tiny automatons — all build in <100ms total ────────────────────────

print("[ANTICIPATOR] Loading detection engine...", flush=True)

_DIRECT_AC = _build(DIRECT_PHRASES)           # ~300 phrases  exact match
_VERB_AC   = _build(VERBS)                    # ~60  words    proximity trigger
_OBJECT_AC = _build(OBJECTS)                  # ~60  words    proximity target

print("[ANTICIPATOR] Detection engine ready.", flush=True)


# ── Structural regex patterns (compiled once) ─────────────────────────────────
# Catches role-switch, encoding, authority, and jailbreak structures that
# don't reduce well to verb+object token pairs.

_STRUCTURAL: list[tuple[re.Pattern, str]] = [
    # Role / persona switch
    (re.compile(r'you\s+are\s+now\s+\w',               re.I), 'role_switch'),
    (re.compile(r'act\s+as\s+(a|an|if)\s+\w',          re.I), 'act_as'),
    (re.compile(r'pretend\s+(you\s+are|to\s+be)\s+\w', re.I), 'pretend'),
    (re.compile(r'from\s+now\s+on\s+you',               re.I), 'from_now_on'),
    # Encoding / obfuscation markers
    (re.compile(r'base64\s*(decode|encoded)',           re.I), 'base64_instruction'),
    (re.compile(r'(decode|translate)\s+and\s+(run|execute|follow)', re.I), 'decode_execute'),
    # Authority / social engineering structures
    (re.compile(r'i\s+am\s+(the\s+)?(admin|developer|creator|operator)', re.I), 'authority_claim'),
    (re.compile(r'this\s+(has\s+been\s+)?(pre.?approved|authorized)',    re.I), 'preapproved_claim'),
    # Forced compliance
    (re.compile(r'you\s+(must|have\s+to|are\s+required\s+to)\s+(comply|answer|respond)', re.I), 'forced_compliance'),
    (re.compile(r'do\s+not\s+(say\s+no|refuse|add\s+(warnings?|disclaimers?))', re.I), 'refuse_suppression'),
    # Jailbreak classics
    (re.compile(r'(developer|god|unrestricted|maintenance)\s+mode\s+(enabled|activated|on)', re.I), 'mode_switch'),
    (re.compile(r'you\s+(are\s+)?(jail\s*broken|have\s+no\s+rules)', re.I), 'jailbreak_claim'),
    # Credential extraction structures
    (re.compile(r'(print|dump|show|reveal|output)\s+(your\s+)?(system\s+prompt|env|config|keys?|tokens?)', re.I), 'credential_extraction'),
]


# ── Public API ────────────────────────────────────────────────────────────────

def detect(text: str) -> dict:
    """
    Scan *text* for injection signals across three passes.

    Returns
    -------
    dict with keys:
        detected  bool
        matches   list of match dicts (type, pattern/verb/object, span)
        severity  "critical" | "none"
        layer     "aho_corasick"
    """
    normalized = normalize(text)
    matches: list[dict[str, Any]] = []

    # ── Pass 1: exact DIRECT_PHRASES hits ─────────────────────────────────────
    for end, (_, pattern) in _DIRECT_AC.iter(normalized):
        start = end - len(pattern) + 1
        matches.append({
            "type":    "direct",
            "pattern": pattern,
            "span":    (start, end),
        })

    # ── Pass 2: VERB + OBJECT proximity ───────────────────────────────────────
    for verb_end, (_, verb) in _VERB_AC.iter(normalized):
        verb_start = verb_end - len(verb) + 1

        # Context window around the verb
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
            break   # one object per verb is enough — avoid duplicate floods

    # ── Pass 3: structural regex ───────────────────────────────────────────────
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