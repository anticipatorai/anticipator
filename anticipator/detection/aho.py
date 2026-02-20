import ahocorasick
from anticipator.detection.normalizer import normalize
from anticipator.detection.signatures import VERBS, ADJECTIVES, PREPOSITIONS, OBJECTS, DIRECT_PHRASES

def generate_phrases():
    phrases = [normalize(p) for p in DIRECT_PHRASES]
    for verb in VERBS:
        for adj in ADJECTIVES:
            for obj in OBJECTS:
                for prep in PREPOSITIONS:
                    parts = [p for p in [verb, adj, obj, prep] if p]
                    phrase = normalize(" ".join(parts))
                    phrases.append(phrase)
    return list(set(phrases))

def build_automaton():
    A = ahocorasick.Automaton()
    for idx, phrase in enumerate(generate_phrases()):
        A.add_word(phrase, (idx, phrase))
    A.make_automaton()
    return A

_AUTOMATON = build_automaton()

def detect(text: str) -> dict:
    normalized = normalize(text)
    matches = []
    for end_index, (idx, pattern) in _AUTOMATON.iter(normalized):
        start_index = end_index - len(pattern) + 1
        matches.append((start_index, end_index, pattern))

    return {
        "detected": len(matches) > 0,
        "matches": matches,
        "severity": "critical" if matches else "none",
        "layer": "aho_corasick"
    }

