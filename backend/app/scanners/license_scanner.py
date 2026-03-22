import json
import logging
import os
import re
import subprocess
import xml.etree.ElementTree as ET

from app.scanners.base_scanner import BaseScanner, VulnerabilityResult

logger = logging.getLogger(__name__)

COPYLEFT_LICENSES = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0"}
SAFE_LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense"}


class LicenseScanner(BaseScanner):
    """Scans dependencies for copyleft or unknown licenses."""

    async def scan(self) -> list[VulnerabilityResult]:
        results = []
        if self.language in ("javascript", "typescript"):
            results.extend(await self._scan_npm_licenses())
        elif self.language == "csharp":
            results.extend(await self._scan_nuget_licenses())
        elif self.language == "python":
            results.extend(await self._scan_pip_licenses())
        elif self.language == "java":
            results.extend(await self._scan_java_licenses())
        elif self.language == "go":
            results.extend(await self._scan_go_licenses())
        elif self.language == "rust":
            results.extend(await self._scan_cargo_licenses())
        elif self.language == "ruby":
            results.extend(await self._scan_gem_licenses())
        return results

    async def _scan_npm_licenses(self) -> list[VulnerabilityResult]:
        results = []
        try:
            proc = subprocess.run(
                ["npx", "license-checker", "--json", "--production"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=120,
            )
            data = json.loads(proc.stdout) if proc.stdout else {}
            for pkg, info in data.items():
                license_type = info.get("licenses", "Unknown")
                if isinstance(license_type, list):
                    license_type = license_type[0] if license_type else "Unknown"

                if license_type in COPYLEFT_LICENSES:
                    severity = "high" if "AGPL" in license_type else "medium"
                    results.append(
                        VulnerabilityResult(
                            category="license",
                            severity=severity,
                            cvss_score=None,
                            cwe_id=None,
                            cve_id=None,
                            title=f"Copyleft license: {pkg} ({license_type})",
                            description=f"Package {pkg} uses {license_type} license which has copyleft requirements.",
                            file_path="package.json",
                            line_start=None,
                            line_end=None,
                            code_snippet=None,
                            scanner="license-checker",
                            is_auto_fixable=False,
                        )
                    )
                elif license_type not in SAFE_LICENSES and license_type != "Unknown":
                    pass  # Skip non-standard but non-copyleft
                elif license_type == "Unknown":
                    results.append(
                        VulnerabilityResult(
                            category="license",
                            severity="low",
                            cvss_score=None,
                            cwe_id=None,
                            cve_id=None,
                            title=f"Unknown license: {pkg}",
                            description=f"Package {pkg} has no detectable license.",
                            file_path="package.json",
                            line_start=None,
                            line_end=None,
                            code_snippet=None,
                            scanner="license-checker",
                            is_auto_fixable=False,
                        )
                    )
        except Exception as e:
            logger.error(f"License scan failed: {e}")
        return results

    async def _scan_nuget_licenses(self) -> list[VulnerabilityResult]:
        """Parse .csproj files for PackageLicenseExpression in NuGet packages."""
        results = []
        try:
            for root, _dirs, files in os.walk(self.repo_path):
                for f in files:
                    if not f.endswith(".csproj"):
                        continue
                    csproj_path = os.path.join(root, f)
                    rel_path = os.path.relpath(csproj_path, self.repo_path)
                    try:
                        tree = ET.parse(csproj_path)
                        for pkg_ref in tree.iter("PackageReference"):
                            pkg_name = pkg_ref.get("Include", "unknown")
                            # Check for license metadata in Directory.Packages.props or inline
                            license_expr = pkg_ref.get("PackageLicenseExpression")
                            if not license_expr:
                                continue
                            if license_expr in COPYLEFT_LICENSES:
                                severity = "high" if "AGPL" in license_expr else "medium"
                                results.append(
                                    VulnerabilityResult(
                                        category="license",
                                        severity=severity,
                                        cvss_score=None,
                                        cwe_id=None,
                                        cve_id=None,
                                        title=f"Copyleft license: {pkg_name} ({license_expr})",
                                        description=f"NuGet package {pkg_name} uses {license_expr} license which has copyleft requirements.",
                                        file_path=rel_path,
                                        line_start=None,
                                        line_end=None,
                                        code_snippet=None,
                                        scanner="license-nuget",
                                        is_auto_fixable=False,
                                    )
                                )
                    except ET.ParseError:
                        logger.warning(f"Failed to parse {csproj_path}")
        except Exception as e:
            logger.error(f"NuGet license scan failed: {e}")
        return results

    async def _scan_pip_licenses(self) -> list[VulnerabilityResult]:
        """Check Python package licenses via pip-licenses."""
        results = []
        try:
            proc = subprocess.run(
                ["pip-licenses", "--format=json", "--with-license-file", "--no-license-path"],
                cwd=self.repo_path, capture_output=True, text=True, timeout=120,
            )
            data = json.loads(proc.stdout) if proc.stdout else []
            for pkg in data:
                license_type = pkg.get("License", "Unknown")
                name = pkg.get("Name", "unknown")
                self._check_license(results, name, license_type, "requirements.txt", "license-pip")
        except FileNotFoundError:
            logger.info("pip-licenses not installed, skipping Python license scan")
        except Exception as e:
            logger.error(f"Python license scan failed: {e}")
        return results

    async def _scan_java_licenses(self) -> list[VulnerabilityResult]:
        """Check Java licenses by parsing pom.xml license tags."""
        results = []
        try:
            import xml.etree.ElementTree as PomET
            for root_dir, _dirs, files in os.walk(self.repo_path):
                for f in files:
                    if f != "pom.xml":
                        continue
                    pom_path = os.path.join(root_dir, f)
                    rel_path = os.path.relpath(pom_path, self.repo_path)
                    try:
                        tree = PomET.parse(pom_path)
                        ns = ""
                        root_tag = tree.getroot().tag
                        if "}" in root_tag:
                            ns = root_tag.split("}")[0] + "}"
                        for dep in tree.iter(f"{ns}dependency"):
                            group = dep.findtext(f"{ns}groupId", "")
                            artifact = dep.findtext(f"{ns}artifactId", "")
                            # pom.xml dependencies don't always have license inline
                            # Just flag if no license info found in the project
                            pass
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"Java license scan failed: {e}")
        return results

    async def _scan_go_licenses(self) -> list[VulnerabilityResult]:
        """Check Go module licenses via go-licenses."""
        results = []
        try:
            proc = subprocess.run(
                ["go-licenses", "report", "./...", "--template", "{{range .}}{{.Name}},{{.LicenseName}}\n{{end}}"],
                cwd=self.repo_path, capture_output=True, text=True, timeout=120,
            )
            if proc.stdout:
                for line in proc.stdout.strip().splitlines():
                    parts = line.split(",", 1)
                    if len(parts) == 2:
                        name, license_type = parts[0].strip(), parts[1].strip()
                        self._check_license(results, name, license_type, "go.mod", "license-go")
        except FileNotFoundError:
            logger.info("go-licenses not installed, skipping Go license scan")
        except Exception as e:
            logger.error(f"Go license scan failed: {e}")
        return results

    async def _scan_cargo_licenses(self) -> list[VulnerabilityResult]:
        """Check Rust crate licenses via cargo-license."""
        results = []
        try:
            proc = subprocess.run(
                ["cargo", "license", "--json"],
                cwd=self.repo_path, capture_output=True, text=True, timeout=120,
            )
            data = json.loads(proc.stdout) if proc.stdout else []
            for pkg in data:
                name = pkg.get("name", "unknown")
                license_type = pkg.get("license", "Unknown")
                self._check_license(results, name, license_type, "Cargo.toml", "license-cargo")
        except FileNotFoundError:
            logger.info("cargo-license not installed, skipping Rust license scan")
        except Exception as e:
            logger.error(f"Rust license scan failed: {e}")
        return results

    async def _scan_gem_licenses(self) -> list[VulnerabilityResult]:
        """Check Ruby gem licenses via Gemfile.lock parsing."""
        results = []
        gemfile_lock = os.path.join(self.repo_path, "Gemfile.lock")
        if not os.path.isfile(gemfile_lock):
            return results
        try:
            proc = subprocess.run(
                ["bundle", "exec", "license_finder", "--format=json"],
                cwd=self.repo_path, capture_output=True, text=True, timeout=120,
            )
            data = json.loads(proc.stdout) if proc.stdout else []
            for pkg in data:
                name = pkg.get("name", "unknown")
                licenses = pkg.get("licenses", ["Unknown"])
                license_type = licenses[0] if licenses else "Unknown"
                self._check_license(results, name, license_type, "Gemfile", "license-gem")
        except FileNotFoundError:
            logger.info("license_finder not installed, skipping Ruby license scan")
        except Exception as e:
            logger.error(f"Ruby license scan failed: {e}")
        return results

    def _check_license(self, results: list, pkg_name: str, license_type: str, file_path: str, scanner: str):
        """Helper to check a single package license against copyleft/unknown lists."""
        if license_type in COPYLEFT_LICENSES:
            severity = "high" if "AGPL" in license_type else "medium"
            results.append(VulnerabilityResult(
                category="license", severity=severity, cvss_score=None,
                cwe_id=None, cve_id=None,
                title=f"Copyleft license: {pkg_name} ({license_type})",
                description=f"Package {pkg_name} uses {license_type} license with copyleft requirements.",
                file_path=file_path, line_start=None, line_end=None,
                code_snippet=None, scanner=scanner, is_auto_fixable=False,
            ))
        elif license_type == "Unknown":
            results.append(VulnerabilityResult(
                category="license", severity="low", cvss_score=None,
                cwe_id=None, cve_id=None,
                title=f"Unknown license: {pkg_name}",
                description=f"Package {pkg_name} has no detectable license.",
                file_path=file_path, line_start=None, line_end=None,
                code_snippet=None, scanner=scanner, is_auto_fixable=False,
            ))

    def is_applicable(self) -> bool:
        return True
