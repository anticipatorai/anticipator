"""
anticipator.detection.core.entropy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Entropy-based credential and secret detection layer.

Improvements over v1:
  - Per-charset entropy thresholds (hex, base64, alphanum, full)
  - Context-window scoring (key=, token=, secret= proximity)
  - False-positive suppression via curated allowlist + word-ratio heuristic
  - Token deduplication with span tracking
  - Severity grading: critical / high / warning / none
  - Structured Finding dataclass for downstream consumers
  - Credential regex findings include redacted preview + span
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import List, Optional

from ..signatures import CREDENTIAL_PATTERNS

# ─────────────────────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────────────────────

# Minimum token length to bother analysing
MIN_TOKEN_LENGTH = 16

# Characters we tokenise on (greedy – captures most secret formats)
_TOKEN_RE = re.compile(r'[A-Za-z0-9+/=_\-\.]{16,}')

# Context window (chars either side of a token) searched for sensitive labels
_CONTEXT_RADIUS = 60
_CONTEXT_LABELS_RE = re.compile(
    r'(?i)(key|token|secret|password|passwd|pwd|auth|cred(?:ential)?|'
    r'private|bearer|api[_-]?key|access|refresh|client_secret|'
    r'signing|webhook|pkce|verifier|challenge)',
)

# ── Per-charset entropy thresholds ──────────────────────────────────────────
# Lower threshold → more sensitive.
# Rationale: a 40-char hex string has lower max entropy (4.0 bits) than
# a base64 string (6.0 bits), so we use different cut-offs.

_CHARSET_HEX        = frozenset('0123456789abcdefABCDEF')
_CHARSET_BASE64     = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
_CHARSET_BASE64URL  = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_')
_CHARSET_ALPHANUM   = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')

@dataclass
class _CharsetProfile:
    name: str
    charset: frozenset
    entropy_threshold: float   # bits – flag above this
    length_threshold: int      # minimum token length for this charset

_CHARSET_PROFILES: list[_CharsetProfile] = [
    _CharsetProfile('hex',       _CHARSET_HEX,       3.6, 32),
    _CharsetProfile('base64url', _CHARSET_BASE64URL,  4.5, 24),
    _CharsetProfile('base64',    _CHARSET_BASE64,     4.5, 24),
    _CharsetProfile('alphanum',  _CHARSET_ALPHANUM,   4.0, 20),
    # Fallback – full printable (highest threshold to avoid noise)
    _CharsetProfile('mixed',     frozenset(), 4.8, 20),
]

# ── False-positive allowlist ─────────────────────────────────────────────────
# Exact lowercase tokens that look high-entropy but are benign.
_ALLOWLIST: frozenset[str] = frozenset({
    # common base64 padding artefacts / lorem ipsum style
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    # common test fixtures
    'testtoken', 'faketoken', 'placeholder', 'xxxxxxxxxxxxxxxxxxxx',
    'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'ffffffffffffffffffffffffffffffff',
    '0000000000000000000000000000000000000000',
    '1111111111111111111111111111111111111111',
    # well-known public keys / hashes in documentation
    'da39a3ee5e6b4b0d3255bfef95601890afd80709',  # SHA-1 of empty string
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  # SHA-256 empty
    'sha256', 'sha512', 'md5sum', 'checksum',
})

# Allowlist prefix patterns (lowercase) – skip tokens starting with these
_ALLOWLIST_PREFIXES: tuple[str, ...] = (
    'http',    # URLs will get caught by credential regex separately
    'https',
    'font-',
    'data:',
    'rgba(',
    'rgb(',
    'var(--',
    'linear-gradient',
    'application/',
    'text/',
    'image/',
)

# Heuristic: if a token's lowercase char ratio (a-z only) exceeds this
# it's likely a natural word / CamelCase identifier, not a secret.
_WORD_CHAR_RATIO_THRESHOLD = 0.80

# ── Severity grade boundaries ────────────────────────────────────────────────
# score = entropy × log2(length) + context_bonus
_SCORE_CRITICAL = 28.0
_SCORE_HIGH     = 22.0
_SCORE_WARNING  = 16.0

# Context match adds bonus to score
_CONTEXT_BONUS = 6.0


# ─────────────────────────────────────────────────────────────────────────────
#  Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    type: str                        # 'high_entropy' | credential label
    severity: str                    # 'critical' | 'high' | 'warning'
    layer: str = 'entropy_credential'
    # entropy findings
    charset: Optional[str] = None
    entropy: Optional[float] = None
    length: Optional[int] = None
    score: Optional[float] = None
    context_label: Optional[str] = None  # matched context keyword if any
    redacted: Optional[str] = None       # first 6 chars + '...'
    span: Optional[tuple[int, int]] = None
    # regex findings
    pattern_label: Optional[str] = None


@dataclass
class DetectionResult:
    detected: bool
    severity: str                 # overall worst severity
    layer: str = 'entropy_credential'
    findings: List[Finding] = field(default_factory=list)

    @property
    def critical(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == 'critical']

    @property
    def high(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == 'high']

    @property
    def warnings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == 'warning']


# ─────────────────────────────────────────────────────────────────────────────
#  Core maths
# ─────────────────────────────────────────────────────────────────────────────

def shannon_entropy(text: str) -> float:
    """Return Shannon entropy (bits per character) for *text*."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _classify_charset(token: str) -> _CharsetProfile:
    """Return the tightest charset profile that contains all chars of *token*."""
    chars = frozenset(token)
    for profile in _CHARSET_PROFILES[:-1]:  # skip fallback 'mixed'
        if chars <= profile.charset:
            return profile
    return _CHARSET_PROFILES[-1]   # mixed fallback


def _score(entropy: float, length: int, context_hit: bool) -> float:
    """Composite risk score used for severity grading."""
    return entropy * math.log2(max(length, 2)) + (_CONTEXT_BONUS if context_hit else 0.0)


def _severity_from_score(score: float) -> str:
    if score >= _SCORE_CRITICAL:
        return 'critical'
    if score >= _SCORE_HIGH:
        return 'high'
    if score >= _SCORE_WARNING:
        return 'warning'
    return 'none'


# ─────────────────────────────────────────────────────────────────────────────
#  False-positive filters
# ─────────────────────────────────────────────────────────────────────────────

def _is_allowlisted(token: str) -> bool:
    low = token.lower()
    if low in _ALLOWLIST:
        return True
    return any(low.startswith(p) for p in _ALLOWLIST_PREFIXES)


def _looks_like_natural_text(token: str) -> bool:
    """Return True if the token looks like a human-readable word/identifier."""
    lower_count = sum(1 for c in token if c.islower())
    ratio = lower_count / len(token)
    return ratio > _WORD_CHAR_RATIO_THRESHOLD


def _has_repetitive_structure(token: str, repeat_threshold: float = 0.35) -> bool:
    """Return True if a single character accounts for > threshold of the token."""
    if not token:
        return False
    freq = {}
    for c in token:
        freq[c] = freq.get(c, 0) + 1
    return max(freq.values()) / len(token) > repeat_threshold


# ─────────────────────────────────────────────────────────────────────────────
#  Context analysis
# ─────────────────────────────────────────────────────────────────────────────

def _extract_context(text: str, start: int, end: int) -> str:
    lo = max(0, start - _CONTEXT_RADIUS)
    hi = min(len(text), end + _CONTEXT_RADIUS)
    return text[lo:hi]


def _context_label(context: str) -> Optional[str]:
    """Return the first sensitive label found in *context*, or None."""
    m = _CONTEXT_LABELS_RE.search(context)
    return m.group(0).lower() if m else None


# ─────────────────────────────────────────────────────────────────────────────
#  Detection routines
# ─────────────────────────────────────────────────────────────────────────────

def find_high_entropy_strings(text: str) -> List[Finding]:
    """
    Scan *text* for high-entropy tokens that may be secrets.

    Changes from v1
    ---------------
    - Per-charset thresholds (not a single global cut-off)
    - Context-window scoring boosts tokens near key/token/secret labels
    - False-positive filters: allowlist, natural-text ratio, repetition check
    - Deduplication by span; overlapping matches kept only once
    - Structured Finding objects instead of raw dicts
    - Redacted preview (first 6 chars + '...') instead of first 10
    """
    findings: List[Finding] = []
    seen_spans: set[tuple[int, int]] = set()

    for m in _TOKEN_RE.finditer(text):
        token = m.group()
        span = m.span()

        if span in seen_spans:
            continue

        # ── length gate ──
        if len(token) < MIN_TOKEN_LENGTH:
            continue

        # ── false-positive filters ──
        if _is_allowlisted(token):
            continue
        if _looks_like_natural_text(token):
            continue
        if _has_repetitive_structure(token):
            continue

        # ── charset classification & threshold ──
        profile = _classify_charset(token)
        if len(token) < profile.length_threshold:
            continue

        entropy = shannon_entropy(token)
        if entropy <= profile.entropy_threshold:
            continue

        # ── context scoring ──
        context_text = _extract_context(text, span[0], span[1])
        label = _context_label(context_text)
        composite_score = _score(entropy, len(token), label is not None)

        severity = _severity_from_score(composite_score)
        if severity == 'none':
            continue

        seen_spans.add(span)
        findings.append(Finding(
            type='high_entropy',
            severity=severity,
            charset=profile.name,
            entropy=round(entropy, 3),
            length=len(token),
            score=round(composite_score, 3),
            context_label=label,
            redacted=token[:6] + '...',
            span=span,
        ))

    return findings


def find_credential_patterns(text: str) -> List[Finding]:
    """
    Match *text* against the compiled CREDENTIAL_PATTERNS signature list.

    Changes from v1
    ---------------
    - Includes span and redacted preview for each match
    - Deduplicates overlapping regex matches per label
    - All regex findings are severity=critical (known secret format)
    """
    findings: List[Finding] = []
    seen: set[tuple[str, int]] = set()   # (label, start)

    for pattern, label in CREDENTIAL_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            key = (label, m.start())
            if key in seen:
                continue
            seen.add(key)
            raw = m.group()
            findings.append(Finding(
                type='credential_pattern',
                severity='critical',
                pattern_label=label,
                redacted=raw[:6] + '...' if len(raw) > 6 else raw,
                span=m.span(),
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  Public API
# ─────────────────────────────────────────────────────────────────────────────

def detect(text: str) -> DetectionResult:
    """
    Run entropy + credential-pattern detection on *text*.

    Returns
    -------
    DetectionResult
        .detected   – bool
        .severity   – worst severity across all findings
        .findings   – list of Finding objects
    """
    entropy_findings   = find_high_entropy_strings(text)
    credential_findings = find_credential_patterns(text)
    all_findings = credential_findings + entropy_findings  # credentials first

    if not all_findings:
        return DetectionResult(detected=False, severity='none')

    # Overall severity = worst individual severity
    rank = {'critical': 3, 'high': 2, 'warning': 1, 'none': 0}
    worst = max(all_findings, key=lambda f: rank.get(f.severity, 0))

    return DetectionResult(
        detected=True,
        severity=worst.severity,
        findings=all_findings,
    )