import json
import logging
import re
from pathlib import Path

from app.scanners.base_scanner import BaseScanner, VulnerabilityResult

logger = logging.getLogger(__name__)


class ConfigScanner(BaseScanner):
    """Scans configuration files for security misconfigurations."""

    async def scan(self) -> list[VulnerabilityResult]:
        results = []
        if self.language == "csharp":
            results.extend(self._scan_appsettings())
            results.extend(self._scan_program_cs())
        if self.language in ("javascript", "typescript"):
            results.extend(self._scan_node_config())
        if self.language == "python":
            results.extend(self._scan_python_config())
        if self.language == "java":
            results.extend(self._scan_java_config())
        if self.language == "go":
            results.extend(self._scan_go_config())
        # All languages: check for insecure Dockerfiles
        results.extend(self._scan_dockerfile())
        return results

    def _scan_appsettings(self) -> list[VulnerabilityResult]:
        results = []
        repo = Path(self.repo_path)
        for config_file in repo.rglob("appsettings*.json"):
            try:
                data = json.loads(config_file.read_text())
                rel_path = str(config_file.relative_to(repo))

                # Check for debug logging in production config
                logging_config = data.get("Logging", {})
                log_level = logging_config.get("LogLevel", {}).get("Default", "")
                if log_level in ("Debug", "Trace"):
                    results.append(
                        VulnerabilityResult(
                            category="config_misconfig",
                            severity="medium",
                            cvss_score=4.0,
                            cwe_id="CWE-215",
                            cve_id=None,
                            title="Debug logging enabled",
                            description="Debug/Trace logging may expose sensitive information in production.",
                            file_path=rel_path,
                            line_start=None,
                            line_end=None,
                            code_snippet=f'"LogLevel": {{"Default": "{log_level}"}}',
                            scanner="config-custom",
                            is_auto_fixable=True,
                        )
                    )

                # Check for development mode
                env = data.get("Environment") or data.get("ASPNETCORE_ENVIRONMENT", "")
                if env == "Development" and "Production" in config_file.name:
                    results.append(
                        VulnerabilityResult(
                            category="config_misconfig",
                            severity="medium",
                            cvss_score=5.0,
                            cwe_id="CWE-489",
                            cve_id=None,
                            title="Development mode in production config",
                            description="Production config has environment set to Development.",
                            file_path=rel_path,
                            line_start=None,
                            line_end=None,
                            code_snippet=None,
                            scanner="config-custom",
                            is_auto_fixable=True,
                        )
                    )
            except Exception as e:
                logger.error(f"Config scan error for {config_file}: {e}")
        return results

    def _scan_program_cs(self) -> list[VulnerabilityResult]:
        results = []
        repo = Path(self.repo_path)
        for cs_file in repo.rglob("Program.cs"):
            try:
                content = cs_file.read_text()
                rel_path = str(cs_file.relative_to(repo))

                # Missing HTTPS redirection
                if "UseHttpsRedirection" not in content and "builder" in content.lower():
                    results.append(
                        VulnerabilityResult(
                            category="config_misconfig",
                            severity="high",
                            cvss_score=7.0,
                            cwe_id="CWE-319",
                            cve_id=None,
                            title="Missing HTTPS redirection",
                            description="app.UseHttpsRedirection() is not called.",
                            file_path=rel_path,
                            line_start=None,
                            line_end=None,
                            code_snippet=None,
                            scanner="config-custom",
                            is_auto_fixable=True,
                        )
                    )

                # Permissive CORS
                if re.search(r"AllowAnyOrigin|WithOrigins\(\s*\"\*\"\s*\)", content):
                    results.append(
                        VulnerabilityResult(
                            category="config_misconfig",
                            severity="high",
                            cvss_score=6.5,
                            cwe_id="CWE-942",
                            cve_id=None,
                            title="Permissive CORS policy",
                            description="CORS allows any origin, which could enable cross-origin attacks.",
                            file_path=rel_path,
                            line_start=None,
                            line_end=None,
                            code_snippet=None,
                            scanner="config-custom",
                            is_auto_fixable=True,
                        )
                    )
            except Exception as e:
                logger.error(f"Program.cs scan error: {e}")
        return results

    def _scan_node_config(self) -> list[VulnerabilityResult]:
        """Check Node.js/Next.js config for security issues."""
        results = []
        repo = Path(self.repo_path)

        # Check for DEBUG=true or NODE_ENV=development in .env files
        for env_file in list(repo.glob(".env*")) + list(repo.glob("**/.env*")):
            if ".git" in str(env_file):
                continue
            try:
                content = env_file.read_text()
                rel_path = str(env_file.relative_to(repo))
                if re.search(r"(?i)NODE_ENV\s*=\s*development", content) and "production" in env_file.name.lower():
                    results.append(VulnerabilityResult(
                        category="config_misconfig", severity="medium", cvss_score=4.0,
                        cwe_id="CWE-489", cve_id=None,
                        title="Development mode in production env file",
                        description="NODE_ENV is set to 'development' in a production config file.",
                        file_path=rel_path, line_start=None, line_end=None,
                        code_snippet=None, scanner="config-custom", is_auto_fixable=True,
                    ))
            except Exception:
                pass

        # Check next.config.js/ts for security headers
        for cfg_name in ("next.config.js", "next.config.ts", "next.config.mjs"):
            cfg = repo / cfg_name
            if cfg.exists():
                try:
                    content = cfg.read_text()
                    rel_path = str(cfg.relative_to(repo))
                    if "poweredByHeader" not in content:
                        results.append(VulnerabilityResult(
                            category="security_header", severity="low", cvss_score=2.0,
                            cwe_id="CWE-200", cve_id=None,
                            title="X-Powered-By header not disabled",
                            description="Set poweredByHeader: false in next.config to hide framework info.",
                            file_path=rel_path, line_start=None, line_end=None,
                            code_snippet=None, scanner="config-custom", is_auto_fixable=True,
                        ))
                except Exception:
                    pass

        # Check package.json for missing security-related scripts
        pkg = repo / "package.json"
        if pkg.exists():
            try:
                data = json.loads(pkg.read_text())
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                # Express without helmet
                if "express" in deps and "helmet" not in deps:
                    results.append(VulnerabilityResult(
                        category="config_misconfig", severity="medium", cvss_score=5.0,
                        cwe_id="CWE-693", cve_id=None,
                        title="Express without Helmet security headers",
                        description="Consider adding 'helmet' middleware for HTTP security headers.",
                        file_path="package.json", line_start=None, line_end=None,
                        code_snippet=None, scanner="config-custom", is_auto_fixable=False,
                    ))
            except Exception:
                pass

        return results

    def _scan_python_config(self) -> list[VulnerabilityResult]:
        """Check Python project config for security issues."""
        results = []
        repo = Path(self.repo_path)

        # Django settings checks
        for settings_file in repo.rglob("settings.py"):
            try:
                content = settings_file.read_text()
                rel_path = str(settings_file.relative_to(repo))
                if re.search(r"DEBUG\s*=\s*True", content):
                    results.append(VulnerabilityResult(
                        category="config_misconfig", severity="high", cvss_score=6.0,
                        cwe_id="CWE-489", cve_id=None,
                        title="Django DEBUG=True",
                        description="DEBUG should be False in production. It exposes stack traces and sensitive info.",
                        file_path=rel_path, line_start=None, line_end=None,
                        code_snippet="DEBUG = True", scanner="config-custom", is_auto_fixable=True,
                    ))
                if re.search(r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]?\*['\"]?\s*\]", content):
                    results.append(VulnerabilityResult(
                        category="config_misconfig", severity="high", cvss_score=6.5,
                        cwe_id="CWE-942", cve_id=None,
                        title="Django ALLOWED_HOSTS allows all",
                        description="ALLOWED_HOSTS=['*'] allows requests from any host. Restrict to specific domains.",
                        file_path=rel_path, line_start=None, line_end=None,
                        code_snippet=None, scanner="config-custom", is_auto_fixable=True,
                    ))
                if "SECRET_KEY" in content and re.search(r"SECRET_KEY\s*=\s*['\"][^'\"]{5,}['\"]", content):
                    results.append(VulnerabilityResult(
                        category="config_misconfig", severity="high", cvss_score=7.0,
                        cwe_id="CWE-798", cve_id=None,
                        title="Hardcoded Django SECRET_KEY",
                        description="SECRET_KEY is hardcoded. Use environment variables instead.",
                        file_path=rel_path, line_start=None, line_end=None,
                        code_snippet=None, scanner="config-custom", is_auto_fixable=True,
                    ))
            except Exception:
                pass

        # Flask app checks
        for app_file in list(repo.rglob("app.py")) + list(repo.rglob("wsgi.py")):
            try:
                content = app_file.read_text()
                rel_path = str(app_file.relative_to(repo))
                if re.search(r"app\.run\(.*debug\s*=\s*True", content):
                    results.append(VulnerabilityResult(
                        category="config_misconfig", severity="medium", cvss_score=5.0,
                        cwe_id="CWE-489", cve_id=None,
                        title="Flask debug mode enabled",
                        description="app.run(debug=True) should not be used in production.",
                        file_path=rel_path, line_start=None, line_end=None,
                        code_snippet=None, scanner="config-custom", is_auto_fixable=True,
                    ))
            except Exception:
                pass

        return results

    def _scan_java_config(self) -> list[VulnerabilityResult]:
        """Check Java config for security issues."""
        results = []
        repo = Path(self.repo_path)

        # Spring application.properties / application.yml
        for props_file in list(repo.rglob("application.properties")) + list(repo.rglob("application.yml")) + list(repo.rglob("application.yaml")):
            try:
                content = props_file.read_text()
                rel_path = str(props_file.relative_to(repo))

                # CSRF disabled
                if re.search(r"(?i)(csrf|cross-site).*disable", content):
                    results.append(VulnerabilityResult(
                        category="config_misconfig", severity="high", cvss_score=6.5,
                        cwe_id="CWE-352", cve_id=None,
                        title="CSRF protection disabled",
                        description="Cross-Site Request Forgery protection is disabled in Spring config.",
                        file_path=rel_path, line_start=None, line_end=None,
                        code_snippet=None, scanner="config-custom", is_auto_fixable=True,
                    ))

                # H2 console enabled (common dev backdoor)
                if "h2-console" in content and re.search(r"enabled\s*[=:]\s*true", content):
                    results.append(VulnerabilityResult(
                        category="config_misconfig", severity="high", cvss_score=7.0,
                        cwe_id="CWE-489", cve_id=None,
                        title="H2 database console enabled",
                        description="H2 console should be disabled in production — it provides direct DB access.",
                        file_path=rel_path, line_start=None, line_end=None,
                        code_snippet=None, scanner="config-custom", is_auto_fixable=True,
                    ))

                # Actuator endpoints exposed
                if re.search(r"management\.endpoints\.web\.exposure\.include\s*[=:]\s*\*", content):
                    results.append(VulnerabilityResult(
                        category="config_misconfig", severity="medium", cvss_score=5.5,
                        cwe_id="CWE-200", cve_id=None,
                        title="All Spring Actuator endpoints exposed",
                        description="Exposing all actuator endpoints can leak sensitive operational data.",
                        file_path=rel_path, line_start=None, line_end=None,
                        code_snippet=None, scanner="config-custom", is_auto_fixable=True,
                    ))
            except Exception:
                pass

        return results

    def _scan_go_config(self) -> list[VulnerabilityResult]:
        """Check Go project for common security misconfigurations."""
        results = []
        repo = Path(self.repo_path)

        for go_file in repo.rglob("*.go"):
            if ".git" in str(go_file) or "vendor" in str(go_file):
                continue
            try:
                content = go_file.read_text()
                rel_path = str(go_file.relative_to(repo))

                # TLS InsecureSkipVerify
                if "InsecureSkipVerify" in content and re.search(r"InsecureSkipVerify\s*:\s*true", content):
                    results.append(VulnerabilityResult(
                        category="config_misconfig", severity="high", cvss_score=7.0,
                        cwe_id="CWE-295", cve_id=None,
                        title="TLS certificate verification disabled",
                        description="InsecureSkipVerify: true disables TLS cert validation, enabling MITM attacks.",
                        file_path=rel_path, line_start=None, line_end=None,
                        code_snippet=None, scanner="config-custom", is_auto_fixable=True,
                    ))

                # CORS wildcard
                if re.search(r'AllowAllOrigins\s*:\s*true|Access-Control-Allow-Origin.*\*', content):
                    results.append(VulnerabilityResult(
                        category="config_misconfig", severity="medium", cvss_score=5.0,
                        cwe_id="CWE-942", cve_id=None,
                        title="Permissive CORS: allow all origins",
                        description="CORS allows any origin. Restrict to specific trusted domains.",
                        file_path=rel_path, line_start=None, line_end=None,
                        code_snippet=None, scanner="config-custom", is_auto_fixable=True,
                    ))
            except Exception:
                pass

        return results

    def _scan_dockerfile(self) -> list[VulnerabilityResult]:
        """Check Dockerfiles for security issues (all languages)."""
        results = []
        repo = Path(self.repo_path)

        for dockerfile in list(repo.glob("Dockerfile*")) + list(repo.rglob("**/Dockerfile*")):
            if ".git" in str(dockerfile):
                continue
            try:
                content = dockerfile.read_text()
                rel_path = str(dockerfile.relative_to(repo))

                # Running as root
                if "USER" not in content and "FROM" in content:
                    results.append(VulnerabilityResult(
                        category="config_misconfig", severity="medium", cvss_score=5.0,
                        cwe_id="CWE-250", cve_id=None,
                        title="Docker container runs as root",
                        description="No USER instruction found. Container runs as root by default.",
                        file_path=rel_path, line_start=None, line_end=None,
                        code_snippet=None, scanner="config-custom", is_auto_fixable=True,
                    ))

                # Using latest tag
                if re.search(r"FROM\s+\S+:latest", content):
                    results.append(VulnerabilityResult(
                        category="config_misconfig", severity="low", cvss_score=3.0,
                        cwe_id="CWE-1104", cve_id=None,
                        title="Docker image uses 'latest' tag",
                        description="Pin to a specific image version for reproducible builds.",
                        file_path=rel_path, line_start=None, line_end=None,
                        code_snippet=None, scanner="config-custom", is_auto_fixable=True,
                    ))
            except Exception:
                pass

        return results

    def is_applicable(self) -> bool:
        return True
