"""Shared test fixtures."""

import os
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock

# Use SQLite for tests
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_sealr.db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENCRYPTION_KEY", "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXRlc3Q=")
os.environ.setdefault("OPENAI_API_KEY", "")
os.environ.setdefault("ANTHROPIC_API_KEY", "")


@pytest.fixture
def mock_openai_client():
    client = AsyncMock()
    response = MagicMock()
    response.choices = [MagicMock()]
    response.choices[0].message.content = """<explanation>Fixed MD5 to SHA256</explanation>
<confidence>0.95</confidence>
<diff>
--- a/file.cs
+++ b/file.cs
@@ -1 +1 @@
-MD5.Create()
+SHA256.Create()
</diff>"""
    response.usage.prompt_tokens = 100
    response.usage.completion_tokens = 50
    client.chat.completions.create = AsyncMock(return_value=response)
    return client


@pytest.fixture
def mock_anthropic_client():
    client = AsyncMock()
    response = MagicMock()
    response.content = [MagicMock()]
    response.content[0].text = """<explanation>Fixed MD5 to SHA256</explanation>
<confidence>0.92</confidence>
<diff>
--- a/file.cs
+++ b/file.cs
@@ -1 +1 @@
-MD5.Create()
+SHA256.Create()
</diff>"""
    response.usage.input_tokens = 100
    response.usage.output_tokens = 50
    client.messages.create = AsyncMock(return_value=response)
    return client
