import json
import logging
import os
import re
import subprocess
import tempfile

from app.scanners.base_scanner import BaseScanner, VulnerabilityResult

logger = logging.getLogger(__name__)

# Directories to skip when walking the repo
SKIP_DIRS = {"node_modules", ".git", "vendor", "__pycache__", "dist", "build"}

# Max file size to scan (1 MB)
MAX_FILE_SIZE = 1_048_576

# Regex patterns for common secrets
SECRET_PATTERNS = [
    {
        "rule_id": "aws-access-key",
        "description": "AWS Access Key ID found",
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "high",
        "cvss_score": 8.0,
    },
    {
        "rule_id": "aws-secret-key",
        "description": "AWS Secret Access Key found",
        "pattern": re.compile(
            r"(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{40}"
        ),
        "severity": "high",
        "cvss_score": 8.0,
    },
    {
        "rule_id": "generic-api-key",
        "description": "Generic API key or secret found",
        "pattern": re.compile(
            r"(?i)(api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*[\"']?[A-Za-z0-9_\-]{20,}"
        ),
        "severity": "high",
        "cvss_score": 7.0,
    },
    {
        "rule_id": "private-key",
        "description": "Private key file detected",
        "pattern": re.compile(
            r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
        "severity": "critical",
        "cvss_score": 9.0,
    },
    {
        "rule_id": "github-token",
        "description": "GitHub personal access token found",
        "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        "severity": "high",
        "cvss_score": 8.0,
    },
    {
        "rule_id": "generic-token",
        "description": "Generic token, secret, or password found",
        "pattern": re.compile(
            r"(?i)(token|secret|password|passwd|pwd)\s*[=:]\s*[\"']?[A-Za-z0-9_\-./+=]{8,}"
        ),
        "severity": "medium",
        "cvss_score": 6.0,
    },
    {
        "rule_id": "connection-string",
        "description": "Database or service connection string found",
        "pattern": re.compile(
            r"(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s\"']+"
        ),
        "severity": "high",
        "cvss_score": 7.5,
    },
    {
        "rule_id": "jwt-token",
        "description": "JSON Web Token (JWT) found",
        "pattern": re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        ),
        "severity": "medium",
        "cvss_score": 6.0,
    },
]


def _is_binary(file_path: str) -> bool:
    """Return True if the file appears to be binary."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except (OSError, IOError):
        return True


class SecretsScanner(BaseScanner):
    """Scans for hardcoded secrets using Gitleaks 8.x, with a built-in
    regex fallback when Gitleaks is not installed."""

    async def scan(self) -> list[VulnerabilityResult]:
        results: list[VulnerabilityResult] = []
        report_path = tempfile.mktemp(suffix=".json")

        try:
            proc = subprocess.run(
                [
                    "gitleaks",
                    "detect",
                    "--source",
                    self.repo_path,
                    "--report-format",
                    "json",
                    "--report-path",
                    report_path,
                    "--no-git",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )

            try:
                with open(report_path) as f:
                    findings = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                findings = []

            for finding in findings:
                results.append(
                    VulnerabilityResult(
                        category="secret",
                        severity="high",
                        cvss_score=7.5,
                        cwe_id="CWE-798",
                        cve_id=None,
                        title=f"Hardcoded secret: {finding.get('RuleID', 'unknown')}",
                        description=(
                            f"{finding.get('Description', 'Secret detected')}. "
                            "Extract to environment variables or a secret manager."
                        ),
                        file_path=finding.get("File"),
                        line_start=finding.get("StartLine"),
                        line_end=finding.get("EndLine"),
                        code_snippet=finding.get("Match"),
                        scanner="secrets-gitleaks",
                        is_auto_fixable=True,
                    )
                )
        except FileNotFoundError:
            logger.info(
                "Gitleaks not installed, falling back to regex-based secrets scan"
            )
            results = self._scan_regex_secrets()
        except Exception as e:
            logger.error(f"Secrets scan failed: {e}")

        return results

    # ------------------------------------------------------------------
    # Regex-based fallback
    # ------------------------------------------------------------------

    def _scan_regex_secrets(self) -> list[VulnerabilityResult]:
        """Walk the repo and scan each text file against known secret
        patterns.  Used when Gitleaks is not available."""
        results: list[VulnerabilityResult] = []

        for dirpath, dirnames, filenames in os.walk(self.repo_path):
            # Prune skipped directories in-place so os.walk doesn't descend
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

            for filename in filenames:
                file_path = os.path.join(dirpath, filename)

                # Skip files larger than 1 MB
                try:
                    if os.path.getsize(file_path) > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue

                # Skip binary files
                if _is_binary(file_path):
                    continue

                try:
                    with open(file_path, "r", errors="replace") as f:
                        lines = f.readlines()
                except (OSError, IOError):
                    continue

                rel_path = os.path.relpath(file_path, self.repo_path)

                for line_num, line in enumerate(lines, start=1):
                    for secret_pat in SECRET_PATTERNS:
                        match = secret_pat["pattern"].search(line)
                        if match:
                            snippet = line.rstrip("\n\r")
                            results.append(
                                VulnerabilityResult(
                                    category="secret",
                                    severity=secret_pat["severity"],
                                    cvss_score=secret_pat["cvss_score"],
                                    cwe_id="CWE-798",
                                    cve_id=None,
                                    title=f"Hardcoded secret: {secret_pat['rule_id']}",
                                    description=(
                                        f"{secret_pat['description']}. "
                                        "Extract to environment variables or a secret manager."
                                    ),
                                    file_path=rel_path,
                                    line_start=line_num,
                                    line_end=line_num,
                                    code_snippet=snippet,
                                    scanner="secrets-regex",
                                    is_auto_fixable=True,
                                )
                            )

        return results

    def is_applicable(self) -> bool:
        return True
