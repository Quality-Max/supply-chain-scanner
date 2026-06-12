# Security Policy

`supply-chain-scanner` is a security tool: a pytest-based scanner that detects supply-chain attack vectors in Python dependencies (compromised packages, typosquatting, malicious `.pth` files, encoded payloads, and more). Because people rely on it to surface real attacks, its own integrity matters.

## Reporting a vulnerability

Please report security issues privately — do **not** open a public issue.

- Preferred: GitHub **Security Advisories** → "Report a vulnerability" on this repository.
- Or email **contact@qualitymax.io** with `SECURITY: supply-chain-scanner` in the subject.

Include affected version, impact, and steps to reproduce. We aim to acknowledge within **5 business days** and to agree on a disclosure timeline with you. Reporters who wish to be credited will be.

## What we consider a vulnerability

- A **false negative** in a detector that lets a real supply-chain attack pass undetected (e.g., an evasion that bypasses `.pth`, encoding, or obfuscation checks).
- A way to make the scanner itself execute attacker-controlled code while scanning untrusted packages or requirements.
- A false-positive class severe enough to be abused (e.g., to mask a real finding).

Detection gaps for **newly disclosed** attack techniques are very welcome as reports or PRs — keeping the detectors current is core to the project's value.

## Scope and safe handling

The scanner inspects dependency metadata, `requirements.txt`, `.pth` files, and package `__init__.py` contents. It is designed to **analyze, not execute** scanned code. If you find a path where scanning untrusted input could trigger execution, treat it as a high-severity vulnerability and report it privately.

## Supported versions

The latest release and the `main` branch are supported. Fixes ship to `main` and a new release.
