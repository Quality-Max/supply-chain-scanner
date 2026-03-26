# Supply Chain Security Scanner for Python

[![GitHub stars](https://img.shields.io/github/stars/Quality-Max/supply-chain-scanner)](https://github.com/Quality-Max/supply-chain-scanner)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A pytest-based security scanner that detects supply chain attack vectors in your Python dependencies. Inspired by the [litellm PyPI supply chain attack](https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/) (March 2026), where a poisoned release used a `.pth` file with base64-encoded instructions to exfiltrate SSH keys, cloud credentials, environment variables, and crypto wallets from every machine that installed it.

## What It Catches

17 security tests across 7 categories:

- **Known compromised packages** -- detects installed packages with versions involved in past supply chain attacks (litellm, ctx, ultralytics, etc.)
- **Typosquatted packages** -- flags installed packages that are known typosquats of legitimate packages (e.g., `colourama` for `colorama`)
- **Compromised versions in requirements.txt** -- catches pinned versions that match known-bad releases
- **Malicious .pth file injection** -- scans for the exact attack vector used in litellm 1.82.8 (base64 payloads, executable imports, suspicious patterns)
- **Executable .pth entries** -- flags .pth files containing `import` statements (the Python auto-execution mechanism)
- **Encoded exfiltration payloads** -- decodes base64, hex, zlib, and rot13 strings in package `__init__.py` files looking for hidden exec/eval/import calls
- **String concatenation obfuscation** -- detects `"su" + "bprocess"` style evasion techniques
- **Unpinned security-critical packages** -- advisory warnings for cryptography, pyjwt, bcrypt, certifi without exact version pins
- **Missing hash verification** -- advisory for requirements.txt files not using `--require-hashes`
- **Wildcard version specifiers** -- catches `*` versions vulnerable to version hijacking
- **Suspicious install hooks** -- scans egg-info scripts and setup.py files for code execution and network calls
- **Unexpected .pth files** -- detects .pth files that don't correspond to any installed package
- **Credential exfiltration in startup** -- checks for .pth files referencing `.ssh/`, `.aws/`, `wallet.dat`, and other sensitive paths
- **Direct URL dependencies** -- flags `git+`, `http://` requirements that bypass PyPI
- **Duplicate package entries** -- detects duplicate requirements that could mask a malicious override
- **Requirements file tampering** -- checks for shell injection syntax (`;`, `&&`, `$()`) in requirements.txt

## Quick Start

```bash
pip install supply-chain-scanner
python -m pytest --pyargs supply_chain_scanner -v
```

To scan a specific requirements.txt:

```bash
python -m pytest --pyargs supply_chain_scanner -v --requirements /path/to/requirements.txt
```

By default, the scanner auto-detects `requirements.txt` by searching upward from your current working directory.

## CI Integration

Add this to your GitHub Actions workflow (`.github/workflows/supply-chain-scan.yml`):

```yaml
name: Supply Chain Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install supply-chain-scanner
      - run: python -m pytest --pyargs supply_chain_scanner -v
```

## Built by QualityMax

This scanner is maintained by [QualityMax](https://qualitymax.io) -- the AI-native test automation platform.

## Want more?

For AI-powered test generation, self-healing tests, and full security scanning integrated into your CI/CD pipeline, check out [QualityMax](https://qualitymax.io) -- the full quality platform.
