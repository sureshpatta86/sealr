from app.scanners.base_scanner import BaseScanner
from app.scanners.dependency_scanner import DependencyScanner
from app.scanners.secrets_scanner import SecretsScanner
from app.scanners.sast_scanner import SASTScanner
from app.scanners.malware_scanner import MalwareScanner
from app.scanners.config_scanner import ConfigScanner
from app.scanners.license_scanner import LicenseScanner

SCANNER_REGISTRY: list[type[BaseScanner]] = [
    DependencyScanner,
    SecretsScanner,
    SASTScanner,
    MalwareScanner,
    ConfigScanner,
    LicenseScanner,
]


def get_applicable_scanners(
    repo_path: str, language: str, framework: str
) -> list[BaseScanner]:
    """Return scanner instances applicable to the given language/framework."""
    scanners = []
    for scanner_cls in SCANNER_REGISTRY:
        scanner = scanner_cls(repo_path, language, framework)
        if scanner.is_applicable():
            scanners.append(scanner)
    return scanners
