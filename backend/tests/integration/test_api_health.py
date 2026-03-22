"""Integration tests for the health endpoint."""

import pytest
from fastapi.testclient import TestClient
from app.main import app


class TestHealthEndpoint:
    def setup_method(self):
        self.client = TestClient(app)

    def test_health_returns_200(self):
        response = self.client.get("/health")
        assert response.status_code == 200

    def test_health_returns_ok(self):
        response = self.client.get("/health")
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data
