import re
import unicodedata


def normalize(text: str) -> str:
    """
    Normalize text before scanning.
    - NFKC unicode normalization (catches fullwidth tricks)
    - Strip zero-width and invisible characters
    - Lowercase
    - Collapse whitespace
    """
    # NFKC first — converts ｉgnore → ignore
    text = unicodedata.normalize("NFKC", text)

    # Strip zero-width and invisible characters
    text = re.sub(r'[\u200b\u200c\u200d\u2060\ufeff]', '', text)

    # Lowercase
    text = text.lower()

    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()

    return text

