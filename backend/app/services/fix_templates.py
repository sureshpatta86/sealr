"""Pre-built fix templates for common vulnerability patterns (no AI needed)."""

import re
from typing import Any


class FixTemplates:
    """Match vulnerabilities against known patterns and return deterministic fixes."""

    def match(
        self, vulnerability: dict, file_content: str, language: str
    ) -> dict[str, Any] | None:
        category = vulnerability.get("category", "")

        if language == "csharp":
            return self._match_csharp(category, file_content)
        return None

    def _match_csharp(
        self, category: str, file_content: str
    ) -> dict[str, Any] | None:
        if category == "crypto":
            return self._fix_csharp_crypto(file_content)
        if category == "deserialization":
            return self._fix_csharp_deserialization(file_content)
        return None

    def _fix_csharp_crypto(self, content: str) -> dict[str, Any] | None:
        """Replace MD5/SHA1 with SHA256."""
        if "MD5.Create()" in content:
            fixed = content.replace("MD5.Create()", "SHA256.Create()")
            return {
                "diff": self._make_diff(content, fixed),
                "explanation": "Replaced MD5 with SHA256 for collision resistance.",
            }
        if "SHA1.Create()" in content:
            fixed = content.replace("SHA1.Create()", "SHA256.Create()")
            return {
                "diff": self._make_diff(content, fixed),
                "explanation": "Replaced deprecated SHA1 with SHA256.",
            }
        if "DES.Create()" in content:
            fixed = content.replace("DES.Create()", "Aes.Create()")
            return {
                "diff": self._make_diff(content, fixed),
                "explanation": "Replaced legacy DES with AES.",
            }
        return None

    def _fix_csharp_deserialization(self, content: str) -> dict[str, Any] | None:
        """Replace BinaryFormatter with System.Text.Json."""
        if "new BinaryFormatter()" in content:
            fixed = content.replace(
                "new BinaryFormatter()",
                "System.Text.Json.JsonSerializer  // BinaryFormatter removed for security",
            )
            return {
                "diff": self._make_diff(content, fixed),
                "explanation": "Removed BinaryFormatter (RCE risk) in favor of System.Text.Json.",
            }
        return None

    @staticmethod
    def _make_diff(original: str, fixed: str) -> str:
        """Generate a simple unified diff string."""
        orig_lines = original.splitlines(keepends=True)
        fixed_lines = fixed.splitlines(keepends=True)

        diff_lines = []
        for i, (o, f) in enumerate(zip(orig_lines, fixed_lines)):
            if o != f:
                diff_lines.append(f"-{o.rstrip()}")
                diff_lines.append(f"+{f.rstrip()}")
            else:
                diff_lines.append(f" {o.rstrip()}")

        return "\n".join(diff_lines)
