# Contributing to supply-chain-scanner

Thanks for helping keep the Python ecosystem safer. The most valuable contributions are **new or improved detections** for supply-chain attack techniques.

## Project layout

- `supply_chain_scanner/test_supply_chain.py` — the detectors, written as pytest security tests, plus the watchlists/patterns (`KNOWN_COMPROMISED`, `TYPOSQUAT_WATCHLIST`, `SUSPICIOUS_PATTERNS`, `SENSITIVE_EXFIL_TARGETS`, `OBFUSCATION_PATTERNS`, …).
- `supply_chain_scanner/conftest.py` — pytest options (e.g. `--requirements`).
- `pyproject.toml` — packaging and pytest config.

## Run the scanner / tests

```bash
pip install .
python -m pytest --pyargs supply_chain_scanner -v
```

To scan a specific requirements file:

```bash
python -m pytest --pyargs supply_chain_scanner -v --requirements /path/to/requirements.txt
```

## Adding a detection

1. Add a focused `test_*` function (or extend the relevant watchlist/pattern set) in `test_supply_chain.py`, marked `@pytest.mark.security`.
2. Make the failure message actionable: name the package/file, the technique detected, and what to do.
3. Cite the attack technique or incident your detection is based on (link in a comment) so reviewers can verify it.
4. Avoid false positives: include a known-safe counter-example where practical (see the existing `KNOWN_SAFE_*` allowlists).
5. **Analyze, never execute.** Detections must inspect content (metadata, `.pth`, source) without importing or running scanned code.
6. Run the suite locally; it also runs in CI on every PR.

## Conduct

By participating you agree to our [Code of Conduct](CODE_OF_CONDUCT.md). To report a security issue in this tool, see [SECURITY.md](SECURITY.md).
