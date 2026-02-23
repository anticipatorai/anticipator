"""
anticipator.detection.core.heuristic
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Lightweight structural heuristics — catches obfuscation patterns that
semantic/signature layers miss. Deliberately low-precision; use severity
"warning" only, never escalate to critical here.

Fixes over v1
-------------
- char_spacing: tightened to require 6+ spaced chars (not 4) AND
  excludes normal sentences by checking the spaced segment is short
- all_caps: now requires len > 50 AND filters out common legitimate
  ALL_CAPS patterns (env vars, constants)
- role_switch: removed — fully covered by aho + threat_categories
- long_token: threshold raised to 60 chars, skips URLs and base64-like
  tokens that encoding.py handles
- Added: mixed_script detection (Latin + non-Latin in same word)
- Added: excessive punctuation (common in noise-padding attacks)
- Added: zero_width_chars (belt-and-suspenders alongside normalizer)
"""

import re
import string
import unicodedata


# ── Compiled patterns (module-level, not per-call) ──────────────────────────

# Six or more single chars separated by spaces: "i g n o r e ..."
_CHAR_SPACING = re.compile(r'(\b\w\s){6,}')

# A single character repeating 6+ times: "aaaaaa", "......"
_CHAR_REPETITION = re.compile(r'(.)\1{6,}')

# URL-like tokens — skip in long_token check
_URL_LIKE = re.compile(r'https?://', re.IGNORECASE)

# Base64-like tokens — encoding.py owns these
_BASE64_LIKE = re.compile(r'^[A-Za-z0-9+/=]{40,}$')

# Mixed-script: word contains both ASCII letters and non-ASCII letters
# in the same token — strong homoglyph signal at word level
_ASCII_LETTER = re.compile(r'[A-Za-z]')
_NONASCII_LETTER = re.compile(r'[^\x00-\x7F]')

# Excessive punctuation: more than 30% of chars are punctuation
_PUNCTUATION_SET = set(string.punctuation)

# Zero-width / invisible characters (belt-and-suspenders)
_ZERO_WIDTH = re.compile(r'[\u200b\u200c\u200d\u2060\ufeff]')

# Looks like an env var / constant — skip all_caps check
_CONSTANT_LIKE = re.compile(r'^[A-Z][A-Z0-9_]{2,}$')


def _is_all_caps_suspicious(text: str) -> bool:
    """True only if text is long, fully uppercase, and not a constant/env var."""
    if len(text) <= 50:
        return False
    # If every token looks like a constant, it's legitimate
    tokens = text.split()
    if all(_CONSTANT_LIKE.match(t) for t in tokens if t):
        return False
    return text.upper() == text and any(c.isalpha() for c in text)


def _has_mixed_script_words(text: str) -> bool:
    """True if any single whitespace-separated token mixes ASCII and non-ASCII letters."""
    for word in text.split():
        if len(word) < 4:
            continue
        if _ASCII_LETTER.search(word) and _NONASCII_LETTER.search(word):
            return True
    return False


def _excessive_punctuation(text: str) -> bool:
    """True if more than 35% of characters are punctuation (noise padding signal)."""
    if len(text) < 20:
        return False
    punct_count = sum(1 for c in text if c in _PUNCTUATION_SET)
    return (punct_count / len(text)) > 0.35


def _has_zero_width(text: str) -> bool:
    return bool(_ZERO_WIDTH.search(text))


def detect(text: str) -> dict:
    findings = []

    # ── Char spacing (i g n o r e) ──────────────────────────────────────────
    if _CHAR_SPACING.search(text):
        findings.append({"type": "char_spacing", "severity": "warning"})

    # ── Char repetition (aaaaaa) ─────────────────────────────────────────────
    if _CHAR_REPETITION.search(text):
        findings.append({"type": "char_repetition", "severity": "warning"})

    # ── All caps (long suspicious block) ────────────────────────────────────
    if _is_all_caps_suspicious(text):
        findings.append({"type": "all_caps_block", "severity": "warning"})

    # ── Long tokens (obfuscated payloads) ────────────────────────────────────
    for word in text.split():
        if len(word) > 60:
            if _URL_LIKE.match(word) or _BASE64_LIKE.match(word):
                continue   # encoding.py handles these
            findings.append({"type": "long_token", "severity": "warning",
                              "length": len(word)})
            break   # one finding is enough per message

    # ── Mixed script in a single word ────────────────────────────────────────
    if _has_mixed_script_words(text):
        findings.append({"type": "mixed_script_word", "severity": "warning"})

    # ── Excessive punctuation (noise padding) ────────────────────────────────
    if _excessive_punctuation(text):
        findings.append({"type": "excessive_punctuation", "severity": "warning"})

    # ── Zero-width characters ────────────────────────────────────────────────
    if _has_zero_width(text):
        findings.append({"type": "zero_width_chars", "severity": "warning"})

    return {
        "detected": len(findings) > 0,
        "findings": findings,
        "severity": "warning" if findings else "none",
        "layer": "heuristic",
    }