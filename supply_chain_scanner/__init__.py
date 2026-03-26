"""Supply Chain Security Scanner for Python.

Detects supply chain attack vectors in Python dependencies including
compromised packages, typosquatting, malicious .pth files, encoded payloads,
and obfuscated code.
"""

from supply_chain_scanner.test_supply_chain import (
    KNOWN_COMPROMISED,
    KNOWN_SAFE_BASE64_PACKAGES,
    OBFUSCATION_PATTERNS,
    SENSITIVE_EXFIL_TARGETS,
    SUSPICIOUS_PATTERNS,
    TYPOSQUAT_WATCHLIST,
)

__all__ = [
    "KNOWN_COMPROMISED",
    "TYPOSQUAT_WATCHLIST",
    "SUSPICIOUS_PATTERNS",
    "OBFUSCATION_PATTERNS",
    "SENSITIVE_EXFIL_TARGETS",
    "KNOWN_SAFE_BASE64_PACKAGES",
]
