from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class VulnerabilityResult:
    """Standard result format shared by all scanners."""

    category: str
    severity: str
    cvss_score: float | None
    cwe_id: str | None
    cve_id: str | None
    title: str
    description: str
    file_path: str | None
    line_start: int | None
    line_end: int | None
    code_snippet: str | None
    scanner: str
    is_auto_fixable: bool


class BaseScanner(ABC):
    """Abstract base class for all vulnerability scanners."""

    def __init__(self, repo_path: str, language: str, framework: str):
        self.repo_path = repo_path
        self.language = language
        self.framework = framework

    @abstractmethod
    async def scan(self) -> list[VulnerabilityResult]:
        """Run the scan and return discovered vulnerabilities."""
        ...

    @abstractmethod
    def is_applicable(self) -> bool:
        """Check if this scanner applies to the given language/framework."""
        ...
