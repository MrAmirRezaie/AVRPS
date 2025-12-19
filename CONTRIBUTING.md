# Contributing to AVRPS

Thanks for your interest in contributing to AVRPS! We welcome bug reports, feature requests, documentation improvements, and code contributions.

## How to contribute

1. Fork the repository on GitHub.
2. Create a feature branch: git checkout -b feature/my-change.
3. Write tests for any non-trivial changes. Tests live under 	ests/ and use pytest.
4. Ensure style and linting pass (PEP8). Optionally run lack or uff.
5. Commit and push your changes to your fork.
6. Open a pull request describing the change and rationale.

## Coding guidelines

- Follow PEP8 and type hints where useful.
- Keep functions small and focused.
- Add unit tests for logic changes; mock external calls.
- Use existing patterns in AVRPS.py for new managers and modules.

## Testing

Use the included virtual environment to run tests:

\\\ash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
pytest -q
\\\

## Reporting bugs

Open an issue in the repository with a clear description, reproduction steps, and environment details.

## Security and responsible disclosure

If your contribution includes security-sensitive fixes, please follow the \SECURITY.md\ guidelines and avoid disclosing exploit details in public issues.
