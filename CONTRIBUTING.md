# Contributing to Anticipator

Thanks for your interest in contributing. Here's how to get started.

## Getting Started
```bash
git clone https://github.com/anticipatorai/anticipator
cd anticipator
pip install -e ".[dev]"
```

## Ways to Contribute

- **Bug reports** — open an issue with steps to reproduce
- **New detection phrases** — add to `anticipator/detection/signatures.py`
- **New detection algorithms** — implement new scoring or pattern-matching logic in `anticipator/detection/`
- **Framework support** — help add AutoGen or other pipeline support
- **Tests** — add test cases in `tests/`
- **Documentation** — improve examples and guides

## Pull Request Process

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `pytest`
5. Open a pull request with a clear description

## Adding Detection Phrases

The easiest contribution is adding new injection phrases to `DIRECT_PHRASES` in `anticipator/detection/signatures.py`. If you find a prompt injection pattern that Anticipator misses, open a PR with the phrase added.

## Adding Detection Algorithms

If you have an idea for a new detection method — such as semantic similarity scoring, entropy analysis, token pattern matching, or heuristic-based classifiers — you can contribute it to `anticipator/detection/`. Here's how:

1. Create a new file in `anticipator/detection/` (e.g., `my_detector.py`)
2. Implement a function that accepts a text string and returns a result dict:
```python
   def detect(text: str) -> dict:
       return {
           "detected": True or False,
           "severity": "critical" | "warning" | "none",
           "reason": "short explanation"
       }
```
3. Wire it into `anticipator/detection/scanner.py` so it runs as part of the scan pipeline
4. Add tests in `tests/` covering both positive and negative cases
5. Keep it local and deterministic — no external API calls

Good candidates for new algorithms include regex-based structural analysis, instruction boundary detection, role-switching pattern recognition, and payload obfuscation detection.

## Code Style

- Keep it simple and readable
- No external API calls in detection logic — everything must be local and deterministic
- All detection must be explainable — no black boxes

## Questions

Open an issue or start a discussion on GitHub.