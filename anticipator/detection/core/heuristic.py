import re
import string

_CHAR_SPACING = re.compile(r'(\b\w\s){6,}')

_CHAR_REPETITION = re.compile(r'(.)\1{6,}')

_URL_LIKE = re.compile(r'https?://', re.IGNORECASE)

_BASE64_LIKE = re.compile(r'^[A-Za-z0-9+/=]{40,}$')

_ASCII_LETTER = re.compile(r'[A-Za-z]')
_NONASCII_LETTER = re.compile(r'[^\x00-\x7F]')

_PUNCTUATION_SET = set(string.punctuation)

_ZERO_WIDTH = re.compile(r'[\u200b\u200c\u200d\u2060\ufeff]')

_CONSTANT_LIKE = re.compile(r'^[A-Z][A-Z0-9_]{2,}$')


def _is_all_caps_suspicious(text: str) -> bool:
    if len(text) <= 50:
        return False

    tokens = text.split()
    if all(_CONSTANT_LIKE.match(t) for t in tokens if t):
        return False
    return text.upper() == text and any(c.isalpha() for c in text)


def _has_mixed_script_words(text: str) -> bool:
    for word in text.split():
        if len(word) < 4:
            continue
        if _ASCII_LETTER.search(word) and _NONASCII_LETTER.search(word):
            return True
    return False


def _excessive_punctuation(text: str) -> bool:
    if len(text) < 20:
        return False
    punct_count = sum(1 for c in text if c in _PUNCTUATION_SET)
    return (punct_count / len(text)) > 0.35


def _has_zero_width(text: str) -> bool:
    return bool(_ZERO_WIDTH.search(text))


def detect(text: str) -> dict:
    findings = []

    if _CHAR_SPACING.search(text):
        findings.append({"type": "char_spacing", "severity": "warning"})

    if _CHAR_REPETITION.search(text):
        findings.append({"type": "char_repetition", "severity": "warning"})

    if _is_all_caps_suspicious(text):
        findings.append({"type": "all_caps_block", "severity": "warning"})

    for word in text.split():
        if len(word) > 60:
            if _URL_LIKE.match(word) or _BASE64_LIKE.match(word):
                continue   
            findings.append({"type": "long_token", "severity": "warning",
                              "length": len(word)})
            break   

    if _has_mixed_script_words(text):
        findings.append({"type": "mixed_script_word", "severity": "warning"})

    if _excessive_punctuation(text):
        findings.append({"type": "excessive_punctuation", "severity": "warning"})

    if _has_zero_width(text):
        findings.append({"type": "zero_width_chars", "severity": "warning"})

    return {
        "detected": len(findings) > 0,
        "findings": findings,
        "severity": "warning" if findings else "none",
        "layer": "heuristic",
    }