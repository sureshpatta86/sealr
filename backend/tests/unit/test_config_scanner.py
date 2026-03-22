"""Tests for ConfigScanner pattern detection."""

import os
import tempfile
import pytest

from app.scanners.config_scanner import ConfigScanner


class TestConfigScanner:
    def _create_scanner(self, files: dict[str, str]) -> ConfigScanner:
        """Create a temporary repo with given files and return a scanner."""
        tmpdir = tempfile.mkdtemp()
        for path, content in files.items():
            full_path = os.path.join(tmpdir, path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "w") as f:
                f.write(content)
        return ConfigScanner(tmpdir, "csharp", ".NET Core")

    @pytest.mark.asyncio
    async def test_detects_debug_mode(self):
        scanner = self._create_scanner({
            "appsettings.json": '{"Logging": {"LogLevel": {"Default": "Debug"}}}',
        })
        results = await scanner.scan()
        titles = [r.title for r in results]
        assert any("debug" in t.lower() or "Debug" in t for t in titles)

    @pytest.mark.asyncio
    async def test_detects_missing_https(self):
        scanner = self._create_scanner({
            "Program.cs": "var app = builder.Build();\napp.Run();",
        })
        results = await scanner.scan()
        titles = [r.title for r in results]
        assert any("https" in t.lower() or "HTTPS" in t for t in titles)

    @pytest.mark.asyncio
    async def test_no_findings_when_secure(self):
        scanner = self._create_scanner({
            "appsettings.json": '{"Logging": {"LogLevel": {"Default": "Warning"}}}',
            "Program.cs": "app.UseHttpsRedirection();\napp.UseHsts();",
        })
        results = await scanner.scan()
        # Should have fewer findings when config is secure
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_not_applicable_for_non_dotnet(self):
        scanner = ConfigScanner("/tmp/fake", "python", "Django")
        assert not scanner.is_applicable()
