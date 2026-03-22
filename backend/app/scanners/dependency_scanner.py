import json
import logging
import os
import shutil
import subprocess

import httpx

from app.scanners.base_scanner import BaseScanner, VulnerabilityResult
from app.scanners.manifest_parsers import (
    parse_build_gradle,
    parse_cargo_lock,
    parse_gemfile_lock,
    parse_go_mod,
    parse_pom_xml,
)


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "Critical": "critical",
    "High": "high",
    "Moderate": "medium",
    "Low": "low",
}


class DependencyScanner(BaseScanner):
    """Scans for vulnerable dependencies using language-specific tools + OSV API."""

    async def scan(self) -> list[VulnerabilityResult]:
        if self.language == "csharp":
            return await self._scan_dotnet()
        elif self.language in ("javascript", "typescript"):
            return await self._scan_npm()
        elif self.language == "python":
            return await self._scan_pip()
        elif self.language == "java":
            return await self._scan_java()
        elif self.language == "go":
            return await self._scan_go()
        elif self.language == "rust":
            return await self._scan_rust()
        elif self.language == "ruby":
            return await self._scan_ruby()
        return []

    def is_applicable(self) -> bool:
        return True

    async def _scan_dotnet(self) -> list[VulnerabilityResult]:
        results = []
        try:
            proc = subprocess.run(
                ["dotnet", "list", "package", "--vulnerable", "--format", "json"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                data = json.loads(proc.stdout)
                for project in data.get("projects", []):
                    for fw in project.get("frameworks", []):
                        for pkg in fw.get("topLevelPackages", []):
                            for vuln in pkg.get("vulnerabilities", []):
                                results.append(
                                    VulnerabilityResult(
                                        category="dependency",
                                        severity=SEVERITY_MAP.get(
                                            vuln.get("severity", ""), "medium"
                                        ),
                                        cvss_score=vuln.get("cvssScore"),
                                        cwe_id=None,
                                        cve_id=vuln.get("advisoryUrl", "").split("/")[-1]
                                        if vuln.get("advisoryUrl")
                                        else None,
                                        title=f"Vulnerable package: {pkg['id']} {pkg.get('resolvedVersion', '')}",
                                        description=f"Upgrade to {pkg.get('latestVersion', 'latest')}. Advisory: {vuln.get('advisoryUrl', 'N/A')}",
                                        file_path=project.get("path"),
                                        line_start=None,
                                        line_end=None,
                                        code_snippet=None,
                                        scanner="dependency-dotnet",
                                        is_auto_fixable=True,
                                    )
                                )
        except Exception as e:
            logger.error(f"Dotnet dependency scan failed: {e}")
        return results

    async def _scan_npm(self) -> list[VulnerabilityResult]:
        results = []
        try:
            proc = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=120,
            )
            data = json.loads(proc.stdout) if proc.stdout else {}
            for name, advisory in data.get("vulnerabilities", {}).items():
                # Check if npm reports a fix is available for this package
                fix_available = advisory.get("fixAvailable", False)
                results.append(
                    VulnerabilityResult(
                        category="dependency",
                        severity=SEVERITY_MAP.get(
                            advisory.get("severity", ""), "medium"
                        ),
                        cvss_score=None,
                        cwe_id=None,
                        cve_id=None,
                        title=f"Vulnerable npm package: {name}",
                        description=advisory.get("title", ""),
                        file_path="package.json",
                        line_start=None,
                        line_end=None,
                        code_snippet=None,
                        scanner="dependency-npm",
                        is_auto_fixable=bool(fix_available),
                    )
                )
        except Exception as e:
            logger.error(f"npm audit failed: {e}")
        return results

    async def _scan_pip(self) -> list[VulnerabilityResult]:
        results = []
        try:
            proc = subprocess.run(
                ["pip-audit", "--format", "json"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=120,
            )
            data = json.loads(proc.stdout) if proc.stdout else []
            for finding in data:
                results.append(
                    VulnerabilityResult(
                        category="dependency",
                        severity="high",
                        cvss_score=None,
                        cwe_id=None,
                        cve_id=finding.get("id"),
                        title=f"Vulnerable pip package: {finding.get('name', '')}",
                        description=finding.get("description", ""),
                        file_path="requirements.txt",
                        line_start=None,
                        line_end=None,
                        code_snippet=None,
                        scanner="dependency-pip",
                        is_auto_fixable=True,
                    )
                )
        except Exception as e:
            logger.error(f"pip-audit failed: {e}")
        return results

    async def _scan_java(self) -> list[VulnerabilityResult]:
        results: list[VulnerabilityResult] = []
        try:
            # Determine if this is a Maven or Gradle project
            pom_path = os.path.join(self.repo_path, "pom.xml")
            gradle_path = os.path.join(self.repo_path, "build.gradle")

            if os.path.isfile(pom_path):
                # Try mvn dependency:tree first
                if _tool_available("mvn"):
                    try:
                        proc = subprocess.run(
                            ["mvn", "dependency:tree", "-DoutputType=json"],
                            cwd=self.repo_path,
                            capture_output=True,
                            text=True,
                            timeout=120,
                        )
                        if proc.returncode == 0 and proc.stdout.strip():
                            # mvn output may contain non-JSON preamble; best-effort parse
                            logger.debug("mvn dependency:tree succeeded, falling through to OSV for vuln data")
                    except Exception as e:
                        logger.debug(f"mvn dependency:tree failed, falling back to manifest parsing: {e}")

                # Parse pom.xml and query OSV
                deps = parse_pom_xml(pom_path)
                for name, version in deps:
                    vulns = await self._query_osv(name, version, "Maven")
                    for v in vulns:
                        results.append(
                            VulnerabilityResult(
                                category=v.category,
                                severity=v.severity,
                                cvss_score=v.cvss_score,
                                cwe_id=v.cwe_id,
                                cve_id=v.cve_id,
                                title=v.title,
                                description=v.description,
                                file_path="pom.xml",
                                line_start=None,
                                line_end=None,
                                code_snippet=None,
                                scanner="dependency-maven",
                                is_auto_fixable=True,
                            )
                        )

            elif os.path.isfile(gradle_path):
                deps = parse_build_gradle(gradle_path)
                for name, version in deps:
                    vulns = await self._query_osv(name, version, "Maven")
                    for v in vulns:
                        results.append(
                            VulnerabilityResult(
                                category=v.category,
                                severity=v.severity,
                                cvss_score=v.cvss_score,
                                cwe_id=v.cwe_id,
                                cve_id=v.cve_id,
                                title=v.title,
                                description=v.description,
                                file_path="build.gradle",
                                line_start=None,
                                line_end=None,
                                code_snippet=None,
                                scanner="dependency-gradle",
                                is_auto_fixable=True,
                            )
                        )
        except Exception as e:
            logger.error(f"Java dependency scan failed: {e}")
        return results

    async def _scan_go(self) -> list[VulnerabilityResult]:
        results: list[VulnerabilityResult] = []
        try:
            # Try govulncheck first
            if _tool_available("govulncheck"):
                try:
                    proc = subprocess.run(
                        ["govulncheck", "-json", "./..."],
                        cwd=self.repo_path,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if proc.returncode == 0 and proc.stdout.strip():
                        data = json.loads(proc.stdout)
                        for vuln in data.get("vulns", []):
                            osv_entry = vuln.get("osv", {})
                            aliases = osv_entry.get("aliases", [])
                            cve_id = next((a for a in aliases if a.startswith("CVE-")), osv_entry.get("id"))

                            severity = "medium"
                            cvss_score = None
                            for s in osv_entry.get("severity", []):
                                if s.get("type") == "CVSS_V3":
                                    try:
                                        score = float(s["score"].split("/")[0]) if "/" in s["score"] else float(s["score"])
                                        cvss_score = score
                                        if score >= 9.0:
                                            severity = "critical"
                                        elif score >= 7.0:
                                            severity = "high"
                                        elif score >= 4.0:
                                            severity = "medium"
                                        else:
                                            severity = "low"
                                    except (ValueError, IndexError):
                                        pass

                            results.append(
                                VulnerabilityResult(
                                    category="dependency",
                                    severity=severity,
                                    cvss_score=cvss_score,
                                    cwe_id=None,
                                    cve_id=cve_id,
                                    title=f"Vulnerable Go module: {osv_entry.get('id', 'unknown')}",
                                    description=osv_entry.get("summary", osv_entry.get("details", "")[:300]),
                                    file_path="go.mod",
                                    line_start=None,
                                    line_end=None,
                                    code_snippet=None,
                                    scanner="dependency-go",
                                    is_auto_fixable=True,
                                )
                            )
                        if results:
                            return results
                except Exception as e:
                    logger.debug(f"govulncheck failed, falling back to manifest parsing: {e}")

            # Fallback: parse go.mod and query OSV
            go_mod_path = os.path.join(self.repo_path, "go.mod")
            if os.path.isfile(go_mod_path):
                deps = parse_go_mod(go_mod_path)
                for name, version in deps:
                    vulns = await self._query_osv(name, version, "Go")
                    for v in vulns:
                        results.append(
                            VulnerabilityResult(
                                category=v.category,
                                severity=v.severity,
                                cvss_score=v.cvss_score,
                                cwe_id=v.cwe_id,
                                cve_id=v.cve_id,
                                title=v.title,
                                description=v.description,
                                file_path="go.mod",
                                line_start=None,
                                line_end=None,
                                code_snippet=None,
                                scanner="dependency-go",
                                is_auto_fixable=True,
                            )
                        )
        except Exception as e:
            logger.error(f"Go dependency scan failed: {e}")
        return results

    async def _scan_rust(self) -> list[VulnerabilityResult]:
        results: list[VulnerabilityResult] = []
        try:
            # Try cargo audit first
            if _tool_available("cargo") and _tool_available("cargo-audit"):
                try:
                    proc = subprocess.run(
                        ["cargo", "audit", "--json"],
                        cwd=self.repo_path,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if proc.stdout.strip():
                        data = json.loads(proc.stdout)
                        for vuln in data.get("vulnerabilities", {}).get("list", []):
                            advisory = vuln.get("advisory", {})
                            severity = SEVERITY_MAP.get(advisory.get("severity", ""), "medium")
                            cve_id = advisory.get("id")
                            # Check aliases for a CVE id
                            aliases = advisory.get("aliases", [])
                            cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
                            if cve_alias:
                                cve_id = cve_alias

                            results.append(
                                VulnerabilityResult(
                                    category="dependency",
                                    severity=severity,
                                    cvss_score=advisory.get("cvss"),
                                    cwe_id=None,
                                    cve_id=cve_id,
                                    title=f"Vulnerable crate: {vuln.get('package', {}).get('name', 'unknown')}",
                                    description=advisory.get("description", advisory.get("title", "")),
                                    file_path="Cargo.toml",
                                    line_start=None,
                                    line_end=None,
                                    code_snippet=None,
                                    scanner="dependency-rust",
                                    is_auto_fixable=True,
                                )
                            )
                        if results:
                            return results
                except Exception as e:
                    logger.debug(f"cargo audit failed, falling back to manifest parsing: {e}")

            # Fallback: parse Cargo.lock and query OSV
            cargo_lock_path = os.path.join(self.repo_path, "Cargo.lock")
            if os.path.isfile(cargo_lock_path):
                deps = parse_cargo_lock(cargo_lock_path)
                for name, version in deps:
                    vulns = await self._query_osv(name, version, "crates.io")
                    for v in vulns:
                        results.append(
                            VulnerabilityResult(
                                category=v.category,
                                severity=v.severity,
                                cvss_score=v.cvss_score,
                                cwe_id=v.cwe_id,
                                cve_id=v.cve_id,
                                title=v.title,
                                description=v.description,
                                file_path="Cargo.toml",
                                line_start=None,
                                line_end=None,
                                code_snippet=None,
                                scanner="dependency-rust",
                                is_auto_fixable=True,
                            )
                        )
        except Exception as e:
            logger.error(f"Rust dependency scan failed: {e}")
        return results

    async def _scan_ruby(self) -> list[VulnerabilityResult]:
        results: list[VulnerabilityResult] = []
        try:
            # Try bundle audit first
            if _tool_available("bundle"):
                try:
                    proc = subprocess.run(
                        ["bundle", "audit", "check", "--format", "json"],
                        cwd=self.repo_path,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if proc.stdout.strip():
                        data = json.loads(proc.stdout)
                        for advisory in data.get("advisories", []):
                            severity = SEVERITY_MAP.get(advisory.get("criticality", ""), "medium")
                            results.append(
                                VulnerabilityResult(
                                    category="dependency",
                                    severity=severity,
                                    cvss_score=advisory.get("cvss_v3"),
                                    cwe_id=advisory.get("cwe"),
                                    cve_id=advisory.get("cve"),
                                    title=f"Vulnerable gem: {advisory.get('gem', {}).get('name', 'unknown')}",
                                    description=advisory.get("description", advisory.get("title", "")),
                                    file_path="Gemfile",
                                    line_start=None,
                                    line_end=None,
                                    code_snippet=None,
                                    scanner="dependency-ruby",
                                    is_auto_fixable=True,
                                )
                            )
                        if results:
                            return results
                except Exception as e:
                    logger.debug(f"bundle audit failed, falling back to manifest parsing: {e}")

            # Fallback: parse Gemfile.lock and query OSV
            gemfile_lock_path = os.path.join(self.repo_path, "Gemfile.lock")
            if os.path.isfile(gemfile_lock_path):
                deps = parse_gemfile_lock(gemfile_lock_path)
                for name, version in deps:
                    vulns = await self._query_osv(name, version, "RubyGems")
                    for v in vulns:
                        results.append(
                            VulnerabilityResult(
                                category=v.category,
                                severity=v.severity,
                                cvss_score=v.cvss_score,
                                cwe_id=v.cwe_id,
                                cve_id=v.cve_id,
                                title=v.title,
                                description=v.description,
                                file_path="Gemfile",
                                line_start=None,
                                line_end=None,
                                code_snippet=None,
                                scanner="dependency-ruby",
                                is_auto_fixable=True,
                            )
                        )
        except Exception as e:
            logger.error(f"Ruby dependency scan failed: {e}")
        return results

    async def _query_osv(self, package_name: str, version: str, ecosystem: str) -> list[VulnerabilityResult]:
        """Fallback: query the OSV.dev API for known vulnerabilities."""
        results = []
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    "https://api.osv.dev/v1/query",
                    json={
                        "package": {"name": package_name, "ecosystem": ecosystem},
                        "version": version,
                    },
                )
                if resp.status_code != 200:
                    return results
                data = resp.json()
                for vuln in data.get("vulns", []):
                    severity = "medium"
                    cvss_score = None
                    for s in vuln.get("severity", []):
                        if s.get("type") == "CVSS_V3":
                            try:
                                score = float(s["score"].split("/")[0]) if "/" in s["score"] else float(s["score"])
                                cvss_score = score
                                if score >= 9.0:
                                    severity = "critical"
                                elif score >= 7.0:
                                    severity = "high"
                                elif score >= 4.0:
                                    severity = "medium"
                                else:
                                    severity = "low"
                            except (ValueError, IndexError):
                                pass

                    aliases = vuln.get("aliases", [])
                    cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id"))

                    results.append(
                        VulnerabilityResult(
                            category="dependency",
                            severity=severity,
                            cvss_score=cvss_score,
                            cwe_id=None,
                            cve_id=cve_id,
                            title=f"Vulnerable package: {package_name}@{version}",
                            description=vuln.get("summary", vuln.get("details", "")[:300]),
                            file_path=None,
                            line_start=None,
                            line_end=None,
                            code_snippet=None,
                            scanner="dependency-osv",
                            is_auto_fixable=False,
                        )
                    )
        except Exception as e:
            logger.error(f"OSV API query failed for {package_name}@{version}: {e}")
        return results
