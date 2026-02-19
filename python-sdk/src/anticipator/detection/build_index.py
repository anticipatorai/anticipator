from datasets import load_dataset
from embed_model import load_model
import pickle

model = load_model()

dataset = load_dataset("qualifire/prompt-injections-benchmark")

prompts = []

for item in dataset["test"]:
    prompts.append(item["text"])

print(f"Loaded {len(prompts)} prompts")

embeddings = model.encode(prompts, show_progress_bar=True)

with open("jailbreak_embeddings.pkl", "wb") as f:
    pickle.dump(embeddings, f)

print("Embeddings saved!")
