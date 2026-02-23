"""
anticipator.detection.extended.homoglyph
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Homoglyph detector — catches Cyrillic/Greek/fullwidth lookalike character
attacks used to smuggle injection keywords past normalizers.

Fixes over v1
-------------
- Added fullwidth Latin A-Z, a-z (U+FF21–U+FF5A) — NFKC should catch
  these but we defend in depth
- Added more Cyrillic confusables: ѕ→s, ԁ→d, ɡ→g, ᴄ→c, ʜ→h
- Added Greek: Α Β Ε Ζ Η Ι Κ Μ Ν Ο Ρ Τ Υ Χ (uppercase Greek that map to Latin)
- Added lookalike digits: ０-９ fullwidth, ℓ→l, ℐ→I
- SUSPICIOUS_KEYWORDS extended to cover more injection targets
- note: run AFTER normalizer.py in pipeline so NFKC catches fullwidth first;
  this layer is belt-and-suspenders for chars NFKC does NOT normalize
"""

from anticipator.detection.core.normalizer import normalize

# ── Homoglyph map ─────────────────────────────────────────────────────────────
# Key: lookalike codepoint   Value: Latin equivalent it impersonates

HOMOGLYPH_MAP: dict[str, str] = {
    # ── Cyrillic lowercase ──────────────────────────────────────────────────
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'і': 'i', 'х': 'x', 'у': 'y', 'ѕ': 's', 'ԁ': 'd',
    'ɡ': 'g',
    # ── Cyrillic uppercase ──────────────────────────────────────────────────
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M',
    'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
    # ── Greek lowercase ─────────────────────────────────────────────────────
    'α': 'a', 'β': 'b', 'ε': 'e', 'ο': 'o', 'ρ': 'p',
    'ν': 'v', 'χ': 'x', 'ι': 'i', 'κ': 'k',
    # ── Greek uppercase (maps to Latin visually) ────────────────────────────
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H',
    'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O',
    'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
    # ── Fullwidth Latin (U+FF21–U+FF5A) ─────────────────────────────────────
    # NFKC handles these; we map them anyway for belt-and-suspenders
    **{chr(0xFF21 + i): chr(ord('A') + i) for i in range(26)},   # Ａ-Ｚ
    **{chr(0xFF41 + i): chr(ord('a') + i) for i in range(26)},   # ａ-ｚ
    # ── Fullwidth digits ─────────────────────────────────────────────────────
    **{chr(0xFF10 + i): str(i) for i in range(10)},               # ０-９
    # ── Other lookalikes ─────────────────────────────────────────────────────
    'ⅼ': 'l', 'ⅰ': 'i', 'Ⅰ': 'I', 'ℓ': 'l', 'ℐ': 'I',
    'ᴄ': 'c', 'ʜ': 'h', 'ꓲ': 'l',
    # Digits that look like letters
    '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
    '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
}

SUSPICIOUS_KEYWORDS = [
    "ignore", "system", "bypass", "admin", "override",
    "execute", "password", "secret", "token", "forget",
    "disregard", "instructions", "prompt", "inject",
    "credentials", "access", "auth", "sudo", "root",
    "eval", "exec", "shell", "terminal", "command",
]


def normalize_homoglyphs(text: str) -> str:
    """Replace homoglyph characters with their Latin equivalents."""
    return ''.join(HOMOGLYPH_MAP.get(c, c) for c in text)


def detect(text: str) -> dict:
    findings = []

    # ── Phase 1: find homoglyph characters ───────────────────────────────────
    for i, char in enumerate(text):
        if char in HOMOGLYPH_MAP:
            findings.append({
                "type": "homoglyph",
                "char": char,
                "looks_like": HOMOGLYPH_MAP[char],
                "position": i,
                "severity": "high",
            })

    # ── Phase 2: if any found, check if normalizing reveals a keyword ────────
    triggered_keywords: list[str] = []
    if findings:
        # Run both our map AND full NFKC normalizer for maximum coverage
        homoglyph_normalized = normalize_homoglyphs(text).lower()
        # Also run through the pipeline normalizer (NFKC + zero-width strip)
        pipeline_normalized = normalize(text)
        combined = homoglyph_normalized + " " + pipeline_normalized

        triggered_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in combined]

        if triggered_keywords:
            for finding in findings:
                finding["severity"] = "critical"
            findings.append({
                "type": "homoglyph_keyword_match",
                "keywords": triggered_keywords,
                "severity": "critical",
            })

    # ── Severity rollup ──────────────────────────────────────────────────────
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
        "layer": "homoglyph",
    }