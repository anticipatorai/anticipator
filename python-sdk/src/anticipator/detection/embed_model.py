# embed_model.py

from sentence_transformers import SentenceTransformer

def load_model():
    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    return model
