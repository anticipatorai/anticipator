 # Contributing to Anticipator

Thanks for your interest in contributing. Here's how to get started.

## Getting Started

```bash
git clone https://github.com/yourusername/anticipator
cd anticipator
pip install -e ".[dev]"
```

## Ways to Contribute

- **Bug reports** — open an issue with steps to reproduce
- **New detection phrases** — add to `anticipator/detection/signatures.py`
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

## Code Style

- Keep it simple and readable
- No external API calls in detection logic — everything must be local and deterministic
- All detection must be explainable — no black boxes

## Questions

Open an issue or start a discussion on GitHub.