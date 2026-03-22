import json
import logging
import os
import re
import subprocess
from pathlib import Path

from app.scanners.base_scanner import BaseScanner, VulnerabilityResult

logger = logging.getLogger(__name__)

SEMGREP_SEVERITY_TO_CVSS = {"ERROR": 8.0, "WARNING": 5.0, "INFO": 2.0}
SEMGREP_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

RULES_DIR = Path(__file__).parent / "rules"

# Directories to skip when walking the repo
SKIP_DIRS = {"node_modules", ".git", "vendor", "__pycache__", "dist", "build"}

# Max file size to scan (1 MB)
MAX_FILE_SIZE = 1_048_576

# ---------------------------------------------------------------------------
# Language-to-extension mapping
# ---------------------------------------------------------------------------
LANG_EXTENSIONS: dict[str, set[str]] = {
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx", ".mts", ".cts"},
    "python": {".py"},
    "java": {".java"},
    "go": {".go"},
    "csharp": {".cs"},
    "rust": {".rs"},
    "ruby": {".rb"},
}

# ---------------------------------------------------------------------------
# Regex SAST rules – per language
# ---------------------------------------------------------------------------


def _pat(pattern: str) -> re.Pattern:
    return re.compile(pattern)


# Each rule: (compiled regex, title, description, cwe_id, severity, cvss, auto_fixable)
RuleEntry = tuple[re.Pattern, str, str, str, str, float, bool]

# Rules that apply to ALL languages (checked against every text file)
UNIVERSAL_RULES: list[RuleEntry] = [
    (
        _pat(
            r"""(?i)(?:execute|query|select|insert|update|delete)\s*\(\s*["'`]"""
            r"""[^"'`]*["'`]\s*[\+%]"""
        ),
        "sql-injection-string-concat",
        "SQL query built via string concatenation/interpolation – use parameterised queries instead.",
        "CWE-89",
        "high",
        8.0,
        True,
    ),
    (
        _pat(
            r"""(?i)(?:exec|system|popen|spawn|execFile)\s*\(.*[\+`\$]"""
        ),
        "command-injection",
        "System command built with dynamic input – use parameterised execution or an allowlist.",
        "CWE-78",
        "high",
        8.5,
        True,
    ),
    (
        _pat(
            r"""(?i)(password|passwd|pwd|secret|token)\s*=\s*["'][^"']{4,}["']"""
        ),
        "hardcoded-credential",
        "Credential appears to be hardcoded – move to environment variables or a secrets manager.",
        "CWE-798",
        "high",
        7.5,
        True,
    ),
]

# JavaScript / TypeScript rules
JS_TS_RULES: list[RuleEntry] = [
    (
        _pat(r"""\beval\s*\("""),
        "js-eval",
        "Use of eval() can lead to code injection – avoid eval or use safer alternatives.",
        "CWE-95",
        "high",
        8.0,
        True,
    ),
    (
        _pat(r"""\.innerHTML\s*="""),
        "js-innerhtml-xss",
        "Direct innerHTML assignment may enable XSS – use textContent or a sanitisation library.",
        "CWE-79",
        "medium",
        6.0,
        True,
    ),
    (
        _pat(r"""dangerouslySetInnerHTML"""),
        "js-dangerously-set-inner-html",
        "dangerouslySetInnerHTML bypasses React XSS protection – ensure input is sanitised.",
        "CWE-79",
        "medium",
        6.0,
        True,
    ),
    (
        _pat(r"""document\.write\s*\("""),
        "js-document-write",
        "document.write() can introduce XSS – prefer safer DOM manipulation methods.",
        "CWE-79",
        "medium",
        5.5,
        True,
    ),
    (
        _pat(r"""(?i)helmet\s*\.\s*disable|app\.disable\s*\(\s*['\"]x-powered-by"""),
        "js-disabled-security-header",
        "Security header appears to be disabled – ensure helmet or equivalent middleware is active.",
        "CWE-693",
        "low",
        3.0,
        True,
    ),
]

# Python rules
PYTHON_RULES: list[RuleEntry] = [
    (
        _pat(r"""\beval\s*\("""),
        "py-eval",
        "Use of eval() can lead to arbitrary code execution – avoid or use ast.literal_eval.",
        "CWE-95",
        "high",
        8.0,
        True,
    ),
    (
        _pat(r"""\bexec\s*\("""),
        "py-exec",
        "Use of exec() can lead to arbitrary code execution – avoid or restrict scope.",
        "CWE-95",
        "high",
        8.0,
        True,
    ),
    (
        _pat(r"""pickle\.loads?\s*\("""),
        "py-pickle-deserialization",
        "pickle.load(s) deserialises untrusted data – consider using JSON or a safer format.",
        "CWE-502",
        "high",
        8.5,
        True,
    ),
    (
        _pat(r"""(?:os\.system|subprocess\.call)\s*\(.*shell\s*=\s*True"""),
        "py-shell-injection",
        "Shell=True with dynamic input can lead to command injection – use a list of arguments.",
        "CWE-78",
        "high",
        8.5,
        True,
    ),
    (
        _pat(r"""yaml\.load\s*\([^)]*\)(?!.*Loader\s*=\s*SafeLoader)"""),
        "py-yaml-unsafe-load",
        "yaml.load() without SafeLoader allows arbitrary code execution – use yaml.safe_load().",
        "CWE-502",
        "high",
        8.0,
        True,
    ),
]

# Java rules
JAVA_RULES: list[RuleEntry] = [
    (
        _pat(r"""Runtime\.getRuntime\(\)\.exec\s*\(.*[\+]"""),
        "java-runtime-exec-injection",
        "Runtime.exec() with string concatenation may allow command injection.",
        "CWE-78",
        "high",
        8.5,
        True,
    ),
    (
        _pat(r"""XMLInputFactory"""),
        "java-xxe-xmlinputfactory",
        "XMLInputFactory may be vulnerable to XXE – disable external entity processing.",
        "CWE-611",
        "high",
        8.0,
        True,
    ),
    (
        _pat(r"""ObjectInputStream"""),
        "java-deserialization",
        "ObjectInputStream deserialises untrusted data – validate or use a look-ahead stream.",
        "CWE-502",
        "high",
        8.5,
        True,
    ),
]

# Go rules
GO_RULES: list[RuleEntry] = [
    (
        _pat(r"""fmt\.Sprintf\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)"""),
        "go-sql-injection-sprintf",
        "SQL query built with fmt.Sprintf – use parameterised queries instead.",
        "CWE-89",
        "high",
        8.0,
        True,
    ),
    (
        _pat(r"""exec\.Command\s*\(.*[\+]"""),
        "go-command-injection",
        "exec.Command with dynamic input may allow command injection – validate input first.",
        "CWE-78",
        "high",
        8.5,
        True,
    ),
]

# C# rules
CSHARP_RULES: list[RuleEntry] = [
    (
        _pat(r"""BinaryFormatter"""),
        "csharp-binary-formatter",
        "BinaryFormatter is insecure for deserialisation – use JsonSerializer or XmlSerializer.",
        "CWE-502",
        "high",
        8.5,
        True,
    ),
    (
        _pat(r"""SqlCommand\s*\(.*[\+]"""),
        "csharp-sql-injection",
        "SqlCommand with string concatenation may allow SQL injection – use parameterised queries.",
        "CWE-89",
        "high",
        8.0,
        True,
    ),
    (
        _pat(r"""Process\.Start\s*\(.*[\+]"""),
        "csharp-command-injection",
        "Process.Start with dynamic input may allow command injection.",
        "CWE-78",
        "high",
        8.5,
        True,
    ),
]

# Rust rules
RUST_RULES: list[RuleEntry] = [
    (
        _pat(r"""\bunsafe\s*\{"""),
        "rust-unsafe-block",
        "Unsafe block detected – ensure memory safety invariants are upheld.",
        "CWE-676",
        "low",
        2.0,
        False,
    ),
    (
        _pat(r"""\.unwrap\s*\(\s*\)"""),
        "rust-unwrap-user-input",
        ".unwrap() on potentially fallible input may panic at runtime – use proper error handling.",
        "CWE-252",
        "low",
        2.0,
        True,
    ),
]

# Ruby rules
RUBY_RULES: list[RuleEntry] = [
    (
        _pat(r"""\beval\s*[\(]"""),
        "ruby-eval",
        "eval() can execute arbitrary code – avoid or validate input strictly.",
        "CWE-95",
        "high",
        8.0,
        True,
    ),
    (
        _pat(r"""\bsend\s*\("""),
        "ruby-send-dynamic",
        "send() with dynamic input can invoke arbitrary methods – validate input.",
        "CWE-95",
        "medium",
        6.0,
        True,
    ),
    (
        _pat(r"""(?:\bsystem\s*\(|`[^`]*`)"""),
        "ruby-system-exec",
        "system()/backtick execution with dynamic input may allow command injection.",
        "CWE-78",
        "high",
        8.5,
        True,
    ),
    (
        _pat(r"""YAML\.load\s*\("""),
        "ruby-yaml-unsafe-load",
        "YAML.load() can deserialise arbitrary objects – use YAML.safe_load() instead.",
        "CWE-502",
        "high",
        8.0,
        True,
    ),
]

# Map language names to their specific rule sets
LANG_RULES: dict[str, list[RuleEntry]] = {
    "javascript": JS_TS_RULES,
    "typescript": JS_TS_RULES,
    "python": PYTHON_RULES,
    "java": JAVA_RULES,
    "go": GO_RULES,
    "csharp": CSHARP_RULES,
    "rust": RUST_RULES,
    "ruby": RUBY_RULES,
}


def _is_binary(file_path: str) -> bool:
    """Return True if the file appears to be binary."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except (OSError, IOError):
        return True


class SASTScanner(BaseScanner):
    """Runs Semgrep with language-specific custom rules for SAST analysis.
    Falls back to built-in regex checks when Semgrep is not installed."""

    async def scan(self) -> list[VulnerabilityResult]:
        results: list[VulnerabilityResult] = []
        rules_path = RULES_DIR / self.language

        try:
            if not rules_path.exists():
                # No custom Semgrep rules for this language – still try auto config
                cmd = [
                    "semgrep",
                    "--config",
                    "auto",
                    "--json",
                    self.repo_path,
                ]
            else:
                cmd = [
                    "semgrep",
                    "--config",
                    str(rules_path),
                    "--json",
                    self.repo_path,
                ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            data = json.loads(proc.stdout) if proc.stdout else {}
            for match in data.get("results", []):
                metadata = match.get("extra", {}).get("metadata", {})
                level = match.get("extra", {}).get("severity", "WARNING")

                results.append(
                    VulnerabilityResult(
                        category=metadata.get("category", "sast"),
                        severity=SEMGREP_SEVERITY_MAP.get(level, "medium"),
                        cvss_score=SEMGREP_SEVERITY_TO_CVSS.get(level, 5.0),
                        cwe_id=metadata.get("cwe"),
                        cve_id=None,
                        title=match.get("check_id", "Unknown rule"),
                        description=match.get("extra", {}).get(
                            "message", "Semgrep finding"
                        ),
                        file_path=match.get("path"),
                        line_start=match.get("start", {}).get("line"),
                        line_end=match.get("end", {}).get("line"),
                        code_snippet=match.get("extra", {}).get("lines"),
                        scanner="sast-semgrep",
                        is_auto_fixable=metadata.get("auto_fixable", False),
                    )
                )
        except FileNotFoundError:
            logger.info(
                "Semgrep not installed, falling back to regex-based SAST scan"
            )
            results = self._scan_regex_sast()
        except Exception as e:
            logger.error(f"SAST scan failed: {e}")

        return results

    # ------------------------------------------------------------------
    # Regex-based SAST fallback
    # ------------------------------------------------------------------

    def _scan_regex_sast(self) -> list[VulnerabilityResult]:
        """Walk the repo and apply regex SAST rules.  Used as a fallback
        when Semgrep is not available."""
        results: list[VulnerabilityResult] = []

        # Determine which file extensions to check
        lang_exts = LANG_EXTENSIONS.get(self.language, set())
        # Language-specific rules
        lang_rules = LANG_RULES.get(self.language, [])
        # Combined rules for this language
        all_rules = UNIVERSAL_RULES + lang_rules

        for dirpath, dirnames, filenames in os.walk(self.repo_path):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                _, ext = os.path.splitext(filename)

                # If we know this language's extensions, limit to those files
                if lang_exts and ext not in lang_exts:
                    continue

                # Skip files larger than 1 MB
                try:
                    if os.path.getsize(file_path) > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue

                if _is_binary(file_path):
                    continue

                try:
                    with open(file_path, "r", errors="replace") as f:
                        lines = f.readlines()
                except (OSError, IOError):
                    continue

                rel_path = os.path.relpath(file_path, self.repo_path)

                for line_num, line in enumerate(lines, start=1):
                    for rule in all_rules:
                        pattern, title, desc, cwe, severity, cvss, fixable = rule
                        if pattern.search(line):
                            snippet = line.rstrip("\n\r")
                            results.append(
                                VulnerabilityResult(
                                    category="sast",
                                    severity=severity,
                                    cvss_score=cvss,
                                    cwe_id=cwe,
                                    cve_id=None,
                                    title=title,
                                    description=desc,
                                    file_path=rel_path,
                                    line_start=line_num,
                                    line_end=line_num,
                                    code_snippet=snippet,
                                    scanner="sast-regex",
                                    is_auto_fixable=fixable,
                                )
                            )

        return results

    def is_applicable(self) -> bool:
        return self.language in (
            "csharp", "typescript", "javascript", "python", "java", "go",
            "rust", "ruby",
        )
