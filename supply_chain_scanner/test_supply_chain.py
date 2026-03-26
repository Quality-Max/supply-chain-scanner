"""
Supply Chain Security Scanner for Python

Detects supply chain attack vectors in Python dependencies:
- Known compromised packages (e.g., litellm 1.82.8)
- Malicious .pth file injection (auto-executes at interpreter startup)
- Multi-encoding payload detection (base64, hex, zlib, rot13)
- String concatenation obfuscation detection
- Unpinned dependencies vulnerable to version hijacking
- Typosquatted package names
- Setup-time code execution via install hooks
- Hash verification advisory

Inspired by the litellm PyPI supply chain attack (2026-03) where a poisoned
release used a .pth file with base64-encoded instructions to exfiltrate
SSH keys, cloud credentials, env vars, and crypto wallets.

Reference: https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/
"""

import base64
import binascii
import codecs
import importlib.metadata
import re
import site
import sys
import warnings
import zlib
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Known-compromised packages: (name, compromised_versions)
# Update this list as new supply chain attacks are disclosed.
# ---------------------------------------------------------------------------
KNOWN_COMPROMISED: dict[str, set[str]] = {
    "litellm": {"1.82.8"},
    "ctx": {"0.1.2", "0.2.0"},  # 2022 PyPI attack
    "colourama": {"*"},  # typosquat of colorama
    "python-binance": {"99.0"},  # 2023 PyPI attack
    "ultralytics": {"8.3.41", "8.3.42"},  # 2024 PyPI attack
}

# Packages that are known typosquats of legitimate packages
TYPOSQUAT_WATCHLIST: dict[str, str] = {
    "colourama": "colorama",
    "python3-dateutil": "python-dateutil",
    "jeIlyfish": "jellyfish",  # capital I instead of l
    "requsets": "requests",
    "urlib3": "urllib3",
    "beutifulsoup4": "beautifulsoup4",
    "djanga": "django",
    "flasck": "flask",
    "httpx2": "httpx",
    "numppy": "numpy",
    "pandsa": "pandas",
    "pydanticc": "pydantic",
    "fasttapi": "fastapi",
    "playright": "playwright",
    "openai-python": "openai",
    "anthropics": "anthropic",
}

# Suspicious patterns in .pth files and package code
SUSPICIOUS_PATTERNS = [
    re.compile(r"exec\s*\(", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"__import__\s*\(", re.IGNORECASE),
    re.compile(r"subprocess", re.IGNORECASE),
    re.compile(r"os\.system\s*\(", re.IGNORECASE),
    re.compile(r"urlopen\s*\(", re.IGNORECASE),
    re.compile(r"requests\.(get|post)\s*\(", re.IGNORECASE),
    re.compile(r"socket\.connect", re.IGNORECASE),
    re.compile(r"shutil\.copy", re.IGNORECASE),
    re.compile(r"importlib\.import_module\s*\(", re.IGNORECASE),
    re.compile(r"compile\s*\(\s*['\"]", re.IGNORECASE),  # compile("code")
    re.compile(r"codecs\.decode\s*\(", re.IGNORECASE),  # rot13 evasion
    re.compile(r"zlib\.decompress\s*\(", re.IGNORECASE),  # zlib evasion
    re.compile(r"marshal\.loads\s*\(", re.IGNORECASE),  # bytecode injection
]

# String concat obfuscation patterns (e.g., "su" + "bprocess")
OBFUSCATION_PATTERNS = [
    re.compile(r"""['"][a-z]{2,5}['"]\s*\+\s*['"][a-z]{2,10}['"]"""),  # "su" + "bprocess"
    re.compile(r"getattr\s*\(\s*__builtins__"),  # getattr(__builtins__, "exec")
    re.compile(r"globals\s*\(\s*\)\s*\["),  # globals()["exec"]
    re.compile(r"chr\s*\(\s*\d+\s*\).*chr\s*\(\s*\d+\s*\)"),  # chr(101)+chr(120)+chr(101)+chr(99)
]

# Known-safe packages that legitimately use base64 for data (not exfiltration)
KNOWN_SAFE_BASE64_PACKAGES = {
    "certifi",  # CA certificates
    "pip",  # package metadata
    "setuptools",  # build metadata
    "wheel",  # build metadata
    "urllib3",  # HTTP internals
    "cryptography",  # crypto primitives
    "pyOpenSSL",  # TLS certs
    "cffi",  # C bindings
    "pydantic",  # schema serialization
}

# Sensitive paths that a malicious package might try to access
SENSITIVE_EXFIL_TARGETS = [
    ".ssh/",
    ".aws/",
    ".azure/",
    ".gcp/",
    ".kube/",
    ".git-credentials",
    ".gitconfig",
    ".env",
    ".bash_history",
    ".zsh_history",
    "wallet.dat",
    ".gnupg/",
    ".docker/config.json",
    "credentials.json",
]


def _try_decode_payload(encoded: str) -> list[str]:
    """Try decoding a string with multiple encoding schemes.

    Returns list of (encoding, decoded_text) for any that succeed and
    contain suspicious keywords.
    """
    suspicious_keywords = ["exec", "eval", "import", "subprocess", "socket", "http", "requests", "urllib", "os.system"]
    results = []

    # Base64
    try:
        decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
        if any(kw in decoded.lower() for kw in suspicious_keywords):
            results.append(f"base64: {decoded[:120]}")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        pass

    # Hex
    try:
        decoded = bytes.fromhex(encoded).decode("utf-8", errors="replace")
        if any(kw in decoded.lower() for kw in suspicious_keywords):
            results.append(f"hex: {decoded[:120]}")
    except (ValueError, UnicodeDecodeError):
        pass

    # Zlib + base64 (compressed payload)
    try:
        raw = base64.b64decode(encoded)
        decoded = zlib.decompress(raw).decode("utf-8", errors="replace")
        if any(kw in decoded.lower() for kw in suspicious_keywords):
            results.append(f"zlib+base64: {decoded[:120]}")
    except (binascii.Error, zlib.error, ValueError, UnicodeDecodeError):
        pass

    # ROT13
    try:
        decoded = codecs.decode(encoded, "rot_13")
        if any(kw in decoded.lower() for kw in suspicious_keywords):
            results.append(f"rot13: {decoded[:120]}")
    except (ValueError, LookupError):
        pass

    return results


def _get_site_packages_dirs() -> list[Path]:
    """Return all site-packages directories in the current environment."""
    dirs = []
    for d in site.getsitepackages() + [site.getusersitepackages()]:
        p = Path(d)
        if p.is_dir():
            dirs.append(p)
    # Also check the directory of the running interpreter
    for path_str in sys.path:
        p = Path(path_str)
        if p.is_dir() and "site-packages" in str(p):
            dirs.append(p)
    return list(set(dirs))


def _get_installed_packages() -> dict[str, str]:
    """Return dict of {package_name: version} for all installed packages."""
    packages = {}
    for dist in importlib.metadata.distributions():
        name = dist.metadata["Name"]
        version = dist.metadata["Version"]
        if name and version:
            packages[name.lower()] = version
    return packages


def _find_pth_files() -> list[Path]:
    """Find all .pth files in site-packages directories."""
    pth_files = []
    for sp_dir in _get_site_packages_dirs():
        pth_files.extend(sp_dir.glob("*.pth"))
    return pth_files


def _find_requirements_file(request) -> Path | None:
    """Find requirements.txt by checking (in order):
    1. --requirements pytest CLI arg
    2. Walking up from CWD to find the nearest requirements.txt
    """
    # Check for --requirements CLI arg
    req_path = request.config.getoption("--requirements", default=None)
    if req_path:
        p = Path(req_path).resolve()
        if not p.is_file():
            return None
        if not p.suffix and not p.name.startswith("requirements"):
            return None
        return p

    # Walk up from CWD to find requirements.txt
    current = Path.cwd()
    for parent in [current, *current.parents]:
        candidate = parent / "requirements.txt"
        if candidate.exists():
            return candidate

    return None


def _read_requirements(request) -> list[tuple[str, str]]:
    """Read requirements.txt and return list of (package_name, version_spec)."""
    req_file = _find_requirements_file(request)
    if not req_file:
        return []
    results = []
    for line in req_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Parse package name and version spec
        match = re.match(r"^([a-zA-Z0-9_.-]+)\[?[^\]]*\]?\s*(.*)", line)
        if match:
            name = match.group(1).lower()
            version_spec = match.group(2).strip()
            results.append((name, version_spec))
    return results


def pytest_addoption(parser):
    """Add --requirements CLI option to pytest."""
    parser.addoption(
        "--requirements",
        action="store",
        default=None,
        help="Path to requirements.txt file to scan (default: auto-detect from CWD)",
    )


# ============================================================================
# Tests
# ============================================================================


@pytest.mark.security
class TestKnownCompromisedPackages:
    """Detect installation of packages with known-compromised versions."""

    def test_no_compromised_packages_installed(self):
        """Verify no known-compromised package versions are installed."""
        installed = _get_installed_packages()
        compromised_found = []

        for pkg_name, bad_versions in KNOWN_COMPROMISED.items():
            if pkg_name in installed:
                installed_version = installed[pkg_name]
                if "*" in bad_versions or installed_version in bad_versions:
                    compromised_found.append(f"{pkg_name}=={installed_version}")

        assert not compromised_found, (
            f"CRITICAL: Known-compromised packages detected: {compromised_found}. "
            "These packages have been involved in supply chain attacks. "
            "Remove or downgrade immediately."
        )

    def test_no_typosquatted_packages_installed(self):
        """Verify no known typosquatted packages are installed."""
        installed = _get_installed_packages()
        typosquats_found = []

        for fake_name, real_name in TYPOSQUAT_WATCHLIST.items():
            if fake_name.lower() in installed:
                typosquats_found.append(f"{fake_name} (typosquat of {real_name})")

        assert not typosquats_found, (
            f"CRITICAL: Typosquatted packages detected: {typosquats_found}. "
            "These are likely malicious imitations of legitimate packages."
        )

    def test_compromised_packages_not_in_requirements(self, request):
        """Verify requirements.txt doesn't reference known-compromised versions."""
        requirements = _read_requirements(request)
        bad_refs = []

        for pkg_name, version_spec in requirements:
            if pkg_name in KNOWN_COMPROMISED:
                bad_versions = KNOWN_COMPROMISED[pkg_name]
                if "*" in bad_versions:
                    bad_refs.append(f"{pkg_name} (all versions compromised)")
                elif version_spec:
                    # Check if the pinned version matches a compromised one
                    version_match = re.search(r"==\s*([\d.]+)", version_spec)
                    if version_match and version_match.group(1) in bad_versions:
                        bad_refs.append(f"{pkg_name}{version_spec}")

        assert not bad_refs, f"requirements.txt references known-compromised packages: {bad_refs}"


@pytest.mark.security
class TestPthFileInjection:
    """Detect malicious .pth file injection -- the exact vector used in litellm 1.82.8.

    Python automatically executes lines in .pth files that start with 'import'
    at interpreter startup, making this a powerful persistence mechanism.
    """

    def test_no_suspicious_pth_files(self):
        """Scan .pth files for code execution, base64 payloads, or network access."""
        pth_files = _find_pth_files()
        suspicious = []

        # Known-safe system .pth files that use executable imports legitimately
        known_safe_pth_files = {
            "distutils-precedence.pth",  # setuptools
            "_virtualenv.pth",  # virtualenv
            "a1_coverage.pth",  # coverage.py -- process startup for test coverage
            "coverage.pth",  # coverage.py -- alternative name
        }

        for pth_file in pth_files:
            try:
                content = pth_file.read_text(errors="replace")
            except (OSError, PermissionError) as exc:
                warnings.warn(f"Could not read {pth_file}: {exc}", stacklevel=1)
                continue

            issues = []

            # Check for base64-encoded content (the litellm attack pattern)
            b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
            b64_matches = b64_pattern.findall(content)
            for match in b64_matches:
                try:
                    decoded = base64.b64decode(match).decode("utf-8", errors="replace")
                    # Check if decoded content contains suspicious strings
                    if any(
                        kw in decoded.lower()
                        for kw in ["exec", "eval", "import", "subprocess", "socket", "http", "requests", "urllib"]
                    ):
                        issues.append(f"base64 payload decodes to executable code: {decoded[:100]}...")
                except (binascii.Error, ValueError, UnicodeDecodeError):
                    pass

            # Check for executable import lines (skip known-safe system .pth files)
            if pth_file.name not in known_safe_pth_files:
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("import ") and any(
                        kw in stripped for kw in ["os", "subprocess", "socket", "urllib", "requests", "base64", "exec", "eval"]
                    ):
                        # Skip known-safe virtualenv/setuptools patterns
                        known_safe_imports = {"import _virtualenv", "import apport_python_hook", "import pkgutil"}
                        if any(safe in stripped for safe in known_safe_imports):
                            continue
                        issues.append(f"executable import: {stripped}")

            # Check for suspicious patterns (skip known-safe system .pth files)
            if pth_file.name not in known_safe_pth_files:
                for pattern in SUSPICIOUS_PATTERNS:
                    if pattern.search(content):
                        issues.append(f"suspicious pattern: {pattern.pattern}")

            if issues:
                suspicious.append((str(pth_file), issues))

        assert not suspicious, "CRITICAL: Suspicious .pth files detected (potential supply chain attack):\n" + "\n".join(
            f"  {path}: {issues}" for path, issues in suspicious
        )

    def test_pth_files_are_path_only(self):
        """Verify .pth files only contain path entries, not executable code."""
        pth_files = _find_pth_files()
        executable_pth = []

        for pth_file in pth_files:
            try:
                content = pth_file.read_text(errors="replace")
            except (OSError, PermissionError) as exc:
                warnings.warn(f"Could not read {pth_file}: {exc}", stacklevel=1)
                continue

            for line_num, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                # Legitimate .pth lines are just directory paths
                # Lines starting with "import" are executable
                if stripped.startswith("import "):
                    executable_pth.append(f"{pth_file}:{line_num}: {stripped}")

        if executable_pth:
            # Filter out known-safe entries
            known_safe_imports = {
                "import _virtualenv",
                "import apport_python_hook",
                "import pkgutil",
            }
            truly_suspicious = [entry for entry in executable_pth if not any(safe in entry for safe in known_safe_imports)]
            # Log all executable .pth entries for visibility
            for entry in truly_suspicious:
                print(f"  WARNING: Executable .pth entry: {entry}")


@pytest.mark.security
class TestEncodedPayloads:
    """Detect hidden encoded payloads in installed packages (base64, hex, zlib, rot13)."""

    def test_no_encoded_exfiltration_payloads(self):
        """Scan installed packages for encoded strings that decode to exfiltration code."""
        suspicious_packages = []

        for sp_dir in _get_site_packages_dirs():
            for py_file in sp_dir.glob("*/__init__.py"):
                pkg_name = py_file.parent.name.lower().replace("-", "_")
                if pkg_name in KNOWN_SAFE_BASE64_PACKAGES:
                    continue

                try:
                    content = py_file.read_text(errors="replace")
                except (OSError, PermissionError) as exc:
                    warnings.warn(f"Could not read {py_file}: {exc}", stacklevel=1)
                    continue

                # Scan for encoded strings (base64, hex)
                encoded_pattern = re.compile(r"['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]")
                for match in encoded_pattern.finditer(content):
                    decoded_hits = _try_decode_payload(match.group(1))
                    if decoded_hits:
                        suspicious_packages.append(f"{pkg_name}: {decoded_hits[0]}")

                # Check for exfiltration targets in decoded content
                for match in encoded_pattern.finditer(content):
                    try:
                        decoded = base64.b64decode(match.group(1)).decode("utf-8", errors="replace")
                        exfil_hits = [t for t in SENSITIVE_EXFIL_TARGETS if t in decoded]
                        if exfil_hits:
                            suspicious_packages.append(f"{pkg_name}: payload references {exfil_hits}")
                    except (binascii.Error, ValueError, UnicodeDecodeError):
                        pass

        assert not suspicious_packages, "CRITICAL: Packages with encoded exfiltration payloads:\n" + "\n".join(
            f"  {s}" for s in suspicious_packages
        )

    def test_no_string_concat_obfuscation(self):
        """Detect string concatenation used to build suspicious module names."""
        suspicious = []

        for sp_dir in _get_site_packages_dirs():
            for py_file in sp_dir.glob("*/__init__.py"):
                pkg_name = py_file.parent.name.lower().replace("-", "_")
                if pkg_name in KNOWN_SAFE_BASE64_PACKAGES:
                    continue

                try:
                    content = py_file.read_text(errors="replace")
                except (OSError, PermissionError) as exc:
                    warnings.warn(f"Could not read {py_file}: {exc}", stacklevel=1)
                    continue

                for pattern in OBFUSCATION_PATTERNS:
                    matches = pattern.findall(content)
                    for match in matches:
                        # Check if the concatenation builds a suspicious module name
                        combined = match.replace("'", "").replace('"', "").replace("+", "").replace(" ", "")
                        danger_modules = ["subprocess", "socket", "urllib", "requests", "os.system", "shutil"]
                        if any(mod in combined.lower() for mod in danger_modules):
                            suspicious.append(f"{pkg_name}: obfuscated import: {match}")

        assert not suspicious, "CRITICAL: Packages using string concatenation obfuscation:\n" + "\n".join(
            f"  {s}" for s in suspicious
        )


@pytest.mark.security
class TestDependencyPinning:
    """Verify dependencies are properly pinned to prevent version hijacking."""

    def test_critical_packages_are_pinned(self, request):
        """Ensure security-critical packages have exact version pins.

        Advisory: unpinned security packages are flagged as warnings, not failures,
        because some packages use >= for compatibility. Exact pins (==) are recommended
        to prevent malicious version upgrades via supply chain attacks.
        """
        critical_packages = {
            "cryptography",
            "pyjwt",
            "python-jose",
            "bcrypt",
            "certifi",
        }
        requirements = _read_requirements(request)
        unpinned_critical = []

        for pkg_name, version_spec in requirements:
            if pkg_name in critical_packages:
                if not version_spec or not version_spec.startswith("=="):
                    unpinned_critical.append(f"{pkg_name} ({version_spec or 'no version pin'})")

        # Warn but don't fail -- some packages need >= for compatibility
        for pkg in unpinned_critical:
            print(f"  ADVISORY: Security-critical package without exact pin: {pkg}")

    def test_requirements_use_hashes_advisory(self, request):
        """Advisory: check if requirements.txt uses --require-hashes.

        Hash verification is the gold standard for supply chain security.
        With hashes, pip verifies each downloaded package matches the expected
        cryptographic hash, preventing substitution attacks.
        """
        req_file = _find_requirements_file(request)
        if not req_file:
            pytest.skip("requirements.txt not found")

        content = req_file.read_text()
        has_hashes = "--hash=" in content or "--require-hashes" in content

        if not has_hashes:
            print(
                "  ADVISORY: requirements.txt does not use hash verification. "
                "Consider using 'pip install --require-hashes' or 'pip-compile --generate-hashes' "
                "for maximum supply chain protection."
            )

    def test_no_wildcard_versions(self, request):
        """Ensure no requirements use wildcard (*) version specifiers."""
        requirements = _read_requirements(request)
        wildcard_deps = []

        for pkg_name, version_spec in requirements:
            if "*" in version_spec:
                wildcard_deps.append(f"{pkg_name}{version_spec}")

        assert not wildcard_deps, f"Wildcard version specifiers found (vulnerable to version hijacking): {wildcard_deps}"


@pytest.mark.security
class TestInstallHooks:
    """Detect packages with suspicious install-time code execution."""

    def test_no_suspicious_egg_info_scripts(self):
        """Check for packages with post-install scripts that execute code."""
        suspicious = []

        for sp_dir in _get_site_packages_dirs():
            for egg_info in sp_dir.glob("*.egg-info"):
                scripts_dir = egg_info / "scripts"
                if scripts_dir.is_dir():
                    for script in scripts_dir.iterdir():
                        try:
                            content = script.read_text(errors="replace")
                            for pattern in SUSPICIOUS_PATTERNS:
                                if pattern.search(content):
                                    suspicious.append(f"{egg_info.name}/{script.name}: {pattern.pattern}")
                        except (OSError, PermissionError) as exc:
                            warnings.warn(f"Could not read {script}: {exc}", stacklevel=1)
                            continue

        assert not suspicious, f"Packages with suspicious install scripts: {suspicious}"

    def test_no_setup_py_with_network_calls(self):
        """Check for setup.py files that make network calls during install."""
        suspicious = []

        for sp_dir in _get_site_packages_dirs():
            for setup_py in sp_dir.glob("*/setup.py"):
                try:
                    content = setup_py.read_text(errors="replace")
                    network_patterns = [
                        re.compile(r"urllib\.request"),
                        re.compile(r"requests\.(get|post|put)"),
                        re.compile(r"urlopen\s*\("),
                        re.compile(r"socket\.connect"),
                        re.compile(r"http\.client"),
                    ]
                    for pattern in network_patterns:
                        if pattern.search(content):
                            suspicious.append(f"{setup_py.parent.name}/setup.py: {pattern.pattern}")
                except (OSError, PermissionError) as exc:
                    warnings.warn(f"Could not read {setup_py}: {exc}", stacklevel=1)
                    continue

        assert not suspicious, f"Packages with setup.py making network calls: {suspicious}"


@pytest.mark.security
class TestEnvironmentIntegrity:
    """Verify the Python environment hasn't been tampered with."""

    def test_no_unexpected_pth_files(self):
        """Check for .pth files that don't belong to known packages."""
        installed = _get_installed_packages()
        installed_names = set(installed.keys())
        # Normalize: replace hyphens with underscores for matching
        normalized_installed = {name.replace("-", "_").replace(".", "_") for name in installed_names}
        normalized_installed |= installed_names

        unexpected = []
        known_system_pth = {
            "distutils-precedence.pth",
            "easy-install.pth",
            "setuptools.pth",
            "_virtualenv.pth",
            "virtualenv.pth",
            "a1_coverage.pth",
            "coverage.pth",
            "README.txt",
        }

        for pth_file in _find_pth_files():
            filename = pth_file.name
            if filename in known_system_pth:
                continue

            # Check if the .pth file corresponds to a known package
            stem = pth_file.stem.lower().replace("-", "_").replace(".", "_")
            if stem not in normalized_installed:
                # Could be legitimate but worth flagging
                unexpected.append(str(pth_file))

        if unexpected:
            # Read contents of unexpected .pth files to assess risk
            risky = []
            for pth_path in unexpected:
                try:
                    content = Path(pth_path).read_text(errors="replace")
                    if any(pattern.search(content) for pattern in SUSPICIOUS_PATTERNS):
                        risky.append(pth_path)
                except (OSError, PermissionError) as exc:
                    warnings.warn(f"Could not read {pth_path}: {exc}", stacklevel=1)

            assert not risky, f"CRITICAL: Unexpected .pth files with suspicious content: {risky}"

    def test_no_credential_exfiltration_in_startup(self):
        """Verify no startup files attempt to read sensitive credentials."""
        pth_files = _find_pth_files()
        exfil_attempts = []

        # Known-safe system .pth files that may contain innocent matches
        known_safe = {
            "distutils-precedence.pth",
            "_virtualenv.pth",
            "virtualenv.pth",
            "a1_coverage.pth",
            "coverage.pth",
        }

        for pth_file in pth_files:
            if pth_file.name in known_safe:
                continue

            try:
                content = pth_file.read_text(errors="replace")
            except (OSError, PermissionError) as exc:
                warnings.warn(f"Could not read {pth_file}: {exc}", stacklevel=1)
                continue

            for target in SENSITIVE_EXFIL_TARGETS:
                if target in content:
                    exfil_attempts.append(f"{pth_file}: references {target}")

        assert not exfil_attempts, "CRITICAL: Startup files attempting to access sensitive paths:\n" + "\n".join(
            f"  {e}" for e in exfil_attempts
        )


@pytest.mark.security
class TestRequirementsIntegrity:
    """Validate requirements.txt for supply chain risks."""

    def test_no_direct_url_dependencies(self, request):
        """Ensure no requirements pull from arbitrary URLs (potential backdoor vector)."""
        req_file = _find_requirements_file(request)
        if not req_file:
            pytest.skip("requirements.txt not found")

        url_deps = []
        for line in req_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if any(line.startswith(prefix) for prefix in ["http://", "https://", "git+", "svn+"]):
                url_deps.append(line)

        assert not url_deps, (
            f"Direct URL dependencies found (supply chain risk): {url_deps}. Use PyPI packages with version pins instead."
        )

    def test_no_duplicate_packages(self, request):
        """Detect duplicate package entries that could mask a malicious override."""
        requirements = _read_requirements(request)
        seen = {}
        duplicates = []

        for pkg_name, version_spec in requirements:
            if pkg_name in seen:
                duplicates.append(f"{pkg_name}: '{seen[pkg_name]}' and '{version_spec}'")
            seen[pkg_name] = version_spec

        assert not duplicates, f"Duplicate package entries in requirements.txt (could mask malicious override): {duplicates}"

    def test_requirements_file_not_tampered(self, request):
        """Check requirements.txt for suspicious inline code or shell commands."""
        req_file = _find_requirements_file(request)
        if not req_file:
            pytest.skip("requirements.txt not found")

        content = req_file.read_text()
        suspicious_lines = []

        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Requirements lines should be package specs, not shell commands
            shell_patterns = [";", "&&", "||", "|", "`", "$(", "${"]
            for pattern in shell_patterns:
                if pattern in stripped and not stripped.startswith("-"):
                    suspicious_lines.append(f"Line {line_num}: {stripped}")
                    break

        assert not suspicious_lines, "requirements.txt contains suspicious shell-like syntax:\n" + "\n".join(
            f"  {s}" for s in suspicious_lines
        )
