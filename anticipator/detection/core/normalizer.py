import re
import unicodedata


def normalize(text: str) -> str:

    text = unicodedata.normalize("NFKC", text)

    text = re.sub(r'[\u200b\u200c\u200d\u2060\ufeff]', '', text)

    text = text.lower()

    text = re.sub(r'\s+', ' ', text).strip()

    return text

