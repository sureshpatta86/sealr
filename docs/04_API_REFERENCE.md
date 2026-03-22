# 📡 Sealr — API Reference

> Complete REST API and WebSocket event documentation.

---

## Base URL

```
Development: http://localhost:8000/api
Production:  https://api.sealr.dev/api
```

---

## Authentication

All endpoints (except `/languages` and `/auth/*`) require a GitHub token passed via header:

```http
Authorization: Bearer ghp_xxxxxxxxxxxxxxxxxxxx
```

---

## 1. Auth Endpoints

### Validate Token

```http
POST /api/auth/validate-token
```

**Request Body:**
```json
{
  "github_token": "ghp_xxxxxxxxxxxxxxxxxxxx"
}
```

**Response `200`:**
```json
{
  "valid": true,
  "user": {
    "login": "sureshdev",
    "avatar_url": "https://avatars.githubusercontent.com/..."
  },
  "scopes": "repo, read:org"
}
```

**Response `401`:**
```json
{ "detail": "Invalid GitHub token" }
```

---

## 2. Languages

### List Supported Languages

```http
GET /api/languages
```

**Response `200`:**
```json
[
  {
    "id": 1,
    "language": "csharp",
    "framework": ".NET Core",
    "display_name": "C# / .NET Core",
    "project_file_pattern": "*.csproj;*.sln",
    "build_command": "dotnet build --no-restore",
    "test_command": "dotnet test --no-build",
    "package_manager": "nuget",
    "docker_image": "mcr.microsoft.com/dotnet/sdk:8.0",
    "is_enabled": true,
    "sort_order": 1
  },
  {
    "id": 3,
    "language": "typescript",
    "framework": "Next.js",
    "display_name": "TypeScript / Next.js",
    "is_enabled": false,
    "sort_order": 3
  }
]
```

---

## 3. Scans

### Create Scan

```http
POST /api/scans
```

**Request Body:**
```json
{
  "repo_url": "https://github.com/owner/repo",
  "github_token": "ghp_xxxxxxxxxxxxxxxxxxxx",
  "language": "csharp",
  "framework": ".NET Core",
  "branch": "main"
}
```

> Set `language` to `null` for auto-detection.

**Response `201`:**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "repository_id": "...",
  "status": "queued",
  "language": "csharp",
  "framework": ".NET Core",
  "branch": "main",
  "total_vulnerabilities": 0,
  "fixed_count": 0,
  "created_at": "2026-03-21T10:30:00Z"
}
```

### List Scans

```http
GET /api/scans?page=1&page_size=20
```

### Get Scan Detail

```http
GET /api/scans/{scan_id}
```

### Get Scan Vulnerabilities

```http
GET /api/scans/{scan_id}/vulnerabilities?severity=high&category=sql_injection&status=open
```

**Query Parameters:**

| Param | Type | Values |
|:------|:-----|:-------|
| `severity` | string | `critical`, `high`, `medium`, `low`, `informational` |
| `category` | string | `dependency`, `secret`, `sql_injection`, `xss`, `deserialization`, `crypto`, `csrf`, `auth_misconfig`, `path_traversal`, `malware`, `license`, `config_misconfig`, `security_header`, `logging_sensitive` |
| `status` | string | `open`, `fix_generated`, `fix_validated`, `pr_created`, `pr_merged`, `dismissed` |

### Fix All Vulnerabilities

```http
POST /api/scans/{scan_id}/fix-all
```

**Response `200`:**
```json
{ "message": "Fix generation started", "scan_id": "..." }
```

---

## 4. Vulnerabilities

### Get Vulnerability Detail

```http
GET /api/vulnerabilities/{vuln_id}
```

**Response `200`:**
```json
{
  "id": "...",
  "scan_id": "...",
  "category": "sql_injection",
  "severity": "high",
  "cvss_score": 8.6,
  "cwe_id": "CWE-89",
  "cve_id": null,
  "title": "SQL injection in UserController",
  "description": "String concatenation in SqlCommand allows SQL injection.",
  "file_path": "Controllers/UserController.cs",
  "line_start": 42,
  "line_end": 45,
  "code_snippet": "new SqlCommand(\"SELECT * FROM Users WHERE Id = \" + userId)",
  "scanner": "sast-semgrep",
  "is_auto_fixable": true,
  "status": "open"
}
```

### Fix Single Vulnerability

```http
POST /api/vulnerabilities/{vuln_id}/fix
```

### Dismiss Vulnerability

```http
POST /api/vulnerabilities/{vuln_id}/dismiss
```

---

## 5. Fixes

### Get Fix Detail

```http
GET /api/fixes/{fix_id}
```

**Response `200`:**
```json
{
  "id": "...",
  "vulnerability_id": "...",
  "status": "build_passed",
  "diff_content": "--- a/Controllers/UserController.cs\n+++ b/...",
  "confidence_score": 0.92,
  "ai_model": "gpt-5.4-thinking",
  "build_output": "Build succeeded. 0 Warning(s). 0 Error(s).",
  "test_output": "Passed! - Failed: 0, Passed: 24, Skipped: 0",
  "retry_count": 0,
  "pr_url": "https://github.com/owner/repo/pull/42",
  "pr_number": 42,
  "branch_name": "sealr/fix-a1b2c3d4"
}
```

### Create PR for Fix

```http
POST /api/fixes/{fix_id}/create-pr
```

### Retry Fix Generation

```http
POST /api/fixes/{fix_id}/retry
```

---

## 6. Dashboard

### Get Stats

```http
GET /api/dashboard/stats
```

**Response `200`:**
```json
{
  "total_scans": 47,
  "total_vulnerabilities": 312,
  "fixed_vulnerabilities": 248,
  "fix_rate": 79.5,
  "by_severity": {
    "critical": 23,
    "high": 87,
    "medium": 142,
    "low": 60
  }
}
```

---

## 7. WebSocket Events

### Connection

```javascript
import { io } from "socket.io-client";

const socket = io("ws://localhost:8000", {
  path: "/ws/socket.io",
  transports: ["websocket"],
});

// Join a scan room
socket.emit("join_scan", { scan_id: "a1b2c3d4-..." });

// Listen for events
socket.on("scan.progress", (data) => {
  console.log(data);
  // { scan_id: "...", scanner: "dependency", progress: 75, message: "..." }
});
```

### Event Reference

| Event | Payload | Trigger |
|:------|:--------|:--------|
| `scan.started` | `{ scan_id, status }` | Scan execution begins |
| `scan.progress` | `{ scan_id, scanner, progress, message }` | Per-scanner progress |
| `scan.vulnerability.found` | `{ scan_id, vulnerability }` | New vuln discovered |
| `scan.fix.generated` | `{ scan_id, fix }` | AI generated a fix |
| `scan.fix.validated` | `{ scan_id, fix_id, build_passed }` | Build validation done |
| `scan.pr.created` | `{ scan_id, fix_id, pr_url }` | PR opened |
| `scan.completed` | `{ scan_id, summary }` | Scan finished |
| `scan.failed` | `{ scan_id, error }` | Scan errored |

---

## 8. Error Responses

All errors follow this format:

```json
{
  "detail": "Human-readable error message"
}
```

| Status | Meaning |
|:-------|:--------|
| `400` | Bad request (validation error) |
| `401` | Invalid or missing GitHub token |
| `403` | Insufficient permissions |
| `404` | Resource not found |
| `409` | Conflict (scan already running) |
| `429` | Rate limit exceeded |
| `500` | Internal server error |

---

*Sealr API Reference — v2.0*
