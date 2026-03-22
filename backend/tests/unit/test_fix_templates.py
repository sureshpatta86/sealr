"""Tests for FixTemplates — deterministic fix matching."""

from app.services.fix_templates import FixTemplates


class TestFixTemplates:
    def setup_method(self):
        self.templates = FixTemplates()

    def test_md5_to_sha256(self):
        content = "var hash = MD5.Create();"
        result = self.templates.match({"category": "crypto"}, content, "csharp")
        assert result is not None
        assert "SHA256.Create()" in result["diff"]
        assert "MD5" in result["explanation"]

    def test_sha1_to_sha256(self):
        content = "var hash = SHA1.Create();"
        result = self.templates.match({"category": "crypto"}, content, "csharp")
        assert result is not None
        assert "SHA256.Create()" in result["diff"]

    def test_des_to_aes(self):
        content = "var cipher = DES.Create();"
        result = self.templates.match({"category": "crypto"}, content, "csharp")
        assert result is not None
        assert "Aes.Create()" in result["diff"]

    def test_binary_formatter_removal(self):
        content = "var formatter = new BinaryFormatter();"
        result = self.templates.match({"category": "deserialization"}, content, "csharp")
        assert result is not None
        assert "System.Text.Json" in result["diff"]
        assert "RCE" in result["explanation"]

    def test_no_match_for_safe_code(self):
        content = "var hash = SHA256.Create();"
        result = self.templates.match({"category": "crypto"}, content, "csharp")
        assert result is None

    def test_no_match_for_unsupported_language(self):
        content = "var hash = MD5.Create();"
        result = self.templates.match({"category": "crypto"}, content, "python")
        assert result is None

    def test_no_match_for_unknown_category(self):
        content = "var hash = MD5.Create();"
        result = self.templates.match({"category": "xss"}, content, "csharp")
        assert result is None

    def test_diff_format(self):
        content = "line1\nvar hash = MD5.Create();\nline3"
        result = self.templates.match({"category": "crypto"}, content, "csharp")
        assert result is not None
        diff = result["diff"]
        assert "-" in diff
        assert "+" in diff
