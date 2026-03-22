# Sealr — Complete Project Development Guide

## GitHub Vulnerability Scanner & Auto-Fix Platform

**Version:** 2.0 | **Date:** March 2026 | **Target:** Multi-Language (Starting with .NET Core/C#)

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Updated Tech Stack](#2-updated-tech-stack)
3. [System Architecture](#3-system-architecture)
4. [Vulnerability Coverage Matrix](#4-vulnerability-coverage-matrix)
5. [Database Design (SQL Server)](#5-database-design-sql-server)
6. [Backend API (Python FastAPI)](#6-backend-api-python-fastapi)
7. [Frontend (Next.js 16)](#7-frontend-nextjs-16)
8. [Scanner Engine](#8-scanner-engine)
9. [AI Fix Engine](#9-ai-fix-engine)
10. [GitHub Integration](#10-github-integration)
11. [Build Validation Sandbox](#11-build-validation-sandbox)
12. [Project Structure](#12-project-structure)
13. [Step-by-Step Development Guide](#13-step-by-step-development-guide)
14. [Environment Setup](#14-environment-setup)
15. [API Endpoints Reference](#15-api-endpoints-reference)
16. [WebSocket Events](#16-websocket-events)
17. [Configuration & Environment Variables](#17-configuration--environment-variables)
18. [Deployment Guide](#18-deployment-guide)
19. [Testing Strategy](#19-testing-strategy)
20. [Expansion Roadmap](#20-expansion-roadmap)

---

## 1. Project Overview

### What Sealr Does

Sealr is a web-based platform where users provide a GitHub repository URL and a GitHub Personal Access Token. The platform then:

1. Clones the repository
2. Detects the project language and framework
3. Runs comprehensive vulnerability scanning (dependencies, secrets, SAST, malware, misconfigurations)
4. Generates AI-powered fixes using GPT-5.4 (primary) with Claude as backup
5. Validates fixes by building and testing in a Docker sandbox
6. Opens Pull Requests with detailed fix descriptions

### Key Design Decisions (Updated)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Frontend | Next.js 16 (App Router) | Latest stable, SSR, RSC, Turbopack, great DX |
| Backend | Python 3.12 + FastAPI | Async-first, great ecosystem for security tools |
| Database | SQL Server (via pyodbc/SQLAlchemy) | Your requirement, enterprise-grade |
| Primary AI | GPT-5.4 Thinking (OpenAI) | Latest frontier model, best code understanding |
| Backup AI | Claude Opus 4.6 (Anthropic) | Fallback for when GPT is unavailable/rate-limited |
| Auth | GitHub PAT (Personal Access Token) | Simple, user provides token directly |
| Language Selection | UI dropdown at scan time | Extensible — user selects language+framework |

---

## 2. Updated Tech Stack

### Frontend

```
Framework:      Next.js 16.2 (App Router + Turbopack)
Language:       TypeScript 5.x
Styling:        Tailwind CSS 4.x
State:          Zustand + TanStack Query v5
Diff Viewer:    Monaco Editor (@monaco-editor/react)
Charts:         Recharts
Real-time:      Socket.io-client
Forms:          React Hook Form + Zod validation
UI Components:  shadcn/ui
Icons:          Lucide React
```

### Backend

```
Framework:      Python 3.12 + FastAPI 0.110+
ORM:            SQLAlchemy 2.x + Alembic (migrations)
DB Driver:      pyodbc + aioodbc (async SQL Server)
Task Queue:     Celery 5.x + Redis (broker)
WebSocket:      FastAPI WebSocket + Socket.io (python-socketio)
HTTP Client:    httpx (async)
Git Operations: GitPython + subprocess
AI SDK:         openai (GPT-5.4) + anthropic (Claude backup)
```

### Infrastructure

```
Database:       SQL Server 2022 (or Azure SQL)
Cache/Queue:    Redis 7
Object Storage: S3 / MinIO (for cloned repos, scan artifacts)
Containers:     Docker + Docker-in-Docker (build validation)
CI/CD:          GitHub Actions
Monitoring:     Sentry + Prometheus + Grafana
Reverse Proxy:  Nginx
```

### Security Scanning Tools

```
Dependency:     dotnet list package --vulnerable, npm audit, pip-audit, OSV API
Secrets:        Gitleaks 8.x (regex + entropy-based)
SAST:           Semgrep (custom rulesets per language)
Malware:        ClamAV + YARA rules + custom signatures
Configuration:  Custom analyzers per framework
License Audit:  licensee / license-checker
```

---

## 3. System Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                        NEXT.JS 16 FRONTEND                          │
│  ┌──────────┐ ┌────────────┐ ┌───────────┐ ┌────────────────────┐  │
│  │ Scan Form│ │ Vuln Table │ │ Diff View │ │ Language/Framework │  │
│  │ +Token   │ │ + Filters  │ │ (Monaco)  │ │    Selector        │  │
│  └────┬─────┘ └─────┬──────┘ └─────┬─────┘ └────────┬───────────┘  │
│       │              │              │                 │              │
└───────┼──────────────┼──────────────┼─────────────────┼──────────────┘
        │              │              │                 │
        ▼              ▼              ▼                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        NGINX REVERSE PROXY                          │
│              (SSL termination, rate limiting, routing)               │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     PYTHON FASTAPI BACKEND                          │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────────┐ │
│  │ REST API     │  │ WebSocket    │  │ Celery Task Dispatcher    │ │
│  │ Endpoints    │  │ Server       │  │ (scan jobs, fix jobs)     │ │
│  └──────┬───────┘  └──────┬───────┘  └───────────┬───────────────┘ │
│         │                 │                       │                  │
└─────────┼─────────────────┼───────────────────────┼──────────────────┘
          │                 │                       │
          ▼                 ▼                       ▼
    ┌───────────┐    ┌───────────┐          ┌─────────────┐
    │ SQL Server│    │   Redis   │          │   Celery    │
    │ Database  │    │ Cache +   │          │   Workers   │
    │           │    │ Broker    │          │             │
    └───────────┘    └───────────┘          └──────┬──────┘
                                                   │
                          ┌────────────────────────┼────────────────────────┐
                          │                        │                        │
                          ▼                        ▼                        ▼
                   ┌─────────────┐          ┌─────────────┐         ┌─────────────┐
                   │ Scanner     │          │ AI Fix      │         │ Build       │
                   │ Workers     │          │ Engine      │         │ Validator   │
                   │             │          │             │         │ (Docker)    │
                   │ • Dependency│          │ • GPT-5.4   │         │             │
                   │ • Secrets   │          │   (primary) │         │ • dotnet    │
                   │ • SAST      │          │ • Claude    │         │ • npm       │
                   │ • Malware   │          │   (backup)  │         │ • pip       │
                   │ • Config    │          │             │         │             │
                   │ • License   │          │             │         │             │
                   └─────────────┘          └─────────────┘         └─────────────┘
```

### Scan Pipeline (Detailed)

```
User submits repo URL + GitHub token + selects language/framework
    │
    ▼
[1] INPUT VALIDATION
    • Validate GitHub URL format
    • Test token with GitHub API (repos scope check)
    • Verify repo accessibility (public or private with token)
    │
    ▼
[2] REPO CLONE
    • Shallow clone (depth=1) default branch
    • Store in ephemeral Docker volume or temp directory
    • Calculate repo size, file count
    │
    ▼
[3] PROJECT DISCOVERY
    • If user selected language → validate project structure
    • If "Auto-Detect" → scan for project files:
      - .csproj/.sln → .NET Core
      - package.json → Node.js
      - requirements.txt/pyproject.toml → Python
      - pom.xml/build.gradle → Java
      - go.mod → Go
    • Detect framework version, SDK version
    │
    ▼
[4] PARALLEL SCANNING (fan-out to workers)
    ├── Dependency Scanner → CVEs, outdated packages, EOL frameworks
    ├── Secrets Scanner → API keys, tokens, connection strings in code + git history
    ├── SAST Scanner → SQL injection, XSS, insecure deserialization, etc.
    ├── Malware Scanner → Known malicious patterns, suspicious binaries, crypto miners
    ├── Configuration Scanner → Security misconfigs in app config files
    └── License Scanner → Copyleft/incompatible licenses
    │
    ▼
[5] VULNERABILITY AGGREGATION
    • Deduplicate across scanners
    • Assign severity (CVSS 3.1 scoring)
    • Categorize: Critical / High / Medium / Low / Informational
    • Determine fixability (auto-fixable vs. manual review needed)
    │
    ▼
[6] AI FIX GENERATION (per vulnerability)
    • Build context: full file + surrounding files + vulnerability metadata
    • Call GPT-5.4 Thinking API with few-shot prompt
    • If GPT fails/times out → fallback to Claude Opus 4.6
    • Parse response into unified diff format
    • Assign confidence score
    │
    ▼
[7] BUILD VALIDATION (Docker sandbox)
    • Create ephemeral container with language SDK
    • Apply patch via `git apply`
    • Run build command (dotnet build / npm run build / etc.)
    • Run test suite (dotnet test / npm test / etc.)
    • If FAIL → feed error back to AI engine (max 3 retries)
    • If PASS → mark fix as validated
    │
    ▼
[8] PR CREATION
    • Create branch: sealr/fix-{scan-id}-{vuln-category}
    • Commit validated fixes
    • Open PR with detailed description:
      - Vulnerability description + CVE/CWE IDs
      - Severity + CVSS score
      - Before/after code snippets
      - Build/test validation results
    • Add labels: security, sealr, severity-*
    │
    ▼
[9] REPORTING
    • Update dashboard with scan summary
    • Send notification (email/webhook)
    • Store scan history for trend analysis
```

---

## 4. Vulnerability Coverage Matrix

### Security Categories

| # | Category | Subcategories | Scanner Used | Auto-Fixable? |
|---|----------|---------------|--------------|---------------|
| 1 | **Dependency Vulnerabilities** | Known CVEs in packages, transitive dependency vulns | Dependency Scanner + OSV API | ✅ Yes — bump version |
| 2 | **Outdated/EOL Frameworks** | EOL runtime versions, deprecated APIs | Dependency Scanner | ⚠️ Partial — flag + suggest |
| 3 | **Hardcoded Secrets** | API keys, tokens, connection strings, passwords | Gitleaks | ✅ Yes — extract to config |
| 4 | **SQL Injection** | Raw SQL concatenation, unparameterized queries | Semgrep SAST | ✅ Yes — parameterize |
| 5 | **XSS (Cross-Site Scripting)** | Unencoded output, raw HTML rendering | Semgrep SAST | ✅ Yes — encode/sanitize |
| 6 | **Insecure Deserialization** | Unsafe deserializers, TypeNameHandling.All | Semgrep SAST | ✅ Yes — safe alternatives |
| 7 | **Insecure Cryptography** | MD5/SHA1, weak keys, ECB mode, no salt | Semgrep SAST | ✅ Yes — upgrade algos |
| 8 | **CSRF Missing** | Missing anti-forgery tokens on mutations | Semgrep SAST | ✅ Yes — add attributes |
| 9 | **Auth Misconfigurations** | Missing [Authorize], permissive CORS, cookie flags | Config Scanner | ✅ Yes — tighten config |
| 10 | **Path Traversal** | User input in file paths without validation | Semgrep SAST | ✅ Yes — sanitize paths |
| 11 | **Malware Detection** | Known malicious code patterns, crypto miners, backdoors | ClamAV + YARA | ❌ No — flag for removal |
| 12 | **Dependency Confusion** | Internal package name collisions with public registry | Dependency Scanner | ⚠️ Partial — add source pins |
| 13 | **License Compliance** | GPL/copyleft in MIT projects, incompatible licenses | License Scanner | ❌ No — flag for review |
| 14 | **Security Header Gaps** | Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options | Config Scanner | ✅ Yes — add middleware |
| 15 | **Logging Sensitive Data** | PII/secrets in log output | Semgrep SAST | ✅ Yes — mask/remove |

### Language-Specific Vulnerability Rules

Each supported language has its own ruleset. The UI language/framework selector determines which rules are applied.

#### .NET Core / C# (Phase 1)

| Vulnerability | Detection Pattern | Fix Strategy |
|--------------|-------------------|--------------|
| SQL Injection | `SqlCommand` + string concat, raw EF `FromSqlRaw` | Parameterized queries, `FromSqlInterpolated` |
| XSS | `@Html.Raw()`, missing `HtmlEncoder` | `@Html.Encode()`, `@` Razor syntax |
| Insecure Deserialization | `BinaryFormatter`, `TypeNameHandling.All` | `System.Text.Json`, `TypeNameHandling.None` |
| Hardcoded Secrets | Strings matching `"Server=..."`, `"Bearer ..."` | `IConfiguration` + User Secrets / Key Vault |
| Weak Crypto | `MD5.Create()`, `SHA1.Create()`, `DES`, `RC2` | `SHA256`, `SHA512`, `Aes` with GCM |
| Missing CSRF | `[HttpPost]` without `[ValidateAntiForgeryToken]` | Add attribute + configure antiforgery |
| Missing Auth | `[AllowAnonymous]` on sensitive endpoints | Add `[Authorize]` with proper policies |
| Insecure Cookie | `CookieOptions` without `Secure`, `HttpOnly` | Set `Secure = true`, `HttpOnly = true`, `SameSite = Strict` |
| Open Redirect | `Redirect(userInput)` without validation | `LocalRedirect()` or URL allowlist |
| CORS Misconfiguration | `AllowAnyOrigin().AllowCredentials()` | Specific origins, remove credentials with wildcard |

#### Node.js / TypeScript (Phase 2 — Planned)

| Vulnerability | Detection Pattern | Fix Strategy |
|--------------|-------------------|--------------|
| SQL Injection | String concat in `mysql.query()`, raw Sequelize | Parameterized queries, ORM methods |
| XSS | `innerHTML`, `dangerouslySetInnerHTML`, unescaped EJS | `textContent`, DOMPurify, auto-escaping |
| Prototype Pollution | `Object.assign(target, userInput)`, lodash merge | Input validation, `Object.create(null)` |
| ReDoS | Complex regexes on user input | Regex validation, `re2` library |
| Path Traversal | `fs.readFile(userInput)` | `path.resolve()` + root check |
| Dependency Vulns | `npm audit` findings | `npm update`, version bumps |

#### Python (Phase 3 — Planned)

| Vulnerability | Detection Pattern | Fix Strategy |
|--------------|-------------------|--------------|
| SQL Injection | f-string in `cursor.execute()` | Parameterized queries |
| Command Injection | `os.system(userInput)`, `subprocess.call(shell=True)` | `subprocess.run(args_list)` |
| Pickle Deserialization | `pickle.loads(untrusted)` | JSON, protobuf |
| SSRF | `requests.get(userInput)` | URL allowlist, `ipaddress` validation |
| Dependency Vulns | `pip-audit` findings | Version bumps |

---

## 5. Database Design (SQL Server)

### Entity Relationship Diagram

```
┌──────────────────┐     ┌──────────────────────┐     ┌────────────────────┐
│      Users       │     │     Repositories      │     │    ScanConfigs     │
├──────────────────┤     ├──────────────────────┤     ├────────────────────┤
│ Id (PK, GUID)    │────<│ Id (PK, GUID)         │     │ Id (PK, GUID)      │
│ Email            │     │ UserId (FK)           │>────│ UserId (FK)        │
│ GitHubUsername   │     │ GitHubUrl             │     │ RepositoryId (FK)  │
│ GitHubTokenEnc   │     │ Owner                 │     │ EnabledScanners    │
│ PlanTier         │     │ Name                  │     │ AutoCreatePR       │
│ CreatedAt        │     │ DefaultBranch         │     │ ScheduleCron       │
│ UpdatedAt        │     │ Language              │     │ ExcludedPaths      │
│ IsActive         │     │ Framework             │     │ SeverityThreshold  │
└──────────────────┘     │ LastScannedAt         │     │ CreatedAt          │
                         │ CreatedAt             │     └────────────────────┘
                         └──────────┬────────────┘
                                    │
                                    │ 1:N
                                    ▼
                         ┌──────────────────────┐
                         │        Scans         │
                         ├──────────────────────┤
                         │ Id (PK, GUID)        │
                         │ RepositoryId (FK)    │
                         │ UserId (FK)          │
                         │ Status               │──── Enum: Queued, Cloning, Scanning,
                         │ Language             │      Fixing, Validating, CreatingPRs,
                         │ Framework            │      Completed, Failed
                         │ Branch               │
                         │ CommitSha            │
                         │ TotalVulnerabilities │
                         │ FixedCount           │
                         │ StartedAt            │
                         │ CompletedAt          │
                         │ ErrorMessage         │
                         │ ScanDurationSec      │
                         │ CreatedAt            │
                         └──────────┬───────────┘
                                    │
                                    │ 1:N
                                    ▼
                         ┌──────────────────────────┐
                         │     Vulnerabilities      │
                         ├──────────────────────────┤
                         │ Id (PK, GUID)            │
                         │ ScanId (FK)              │
                         │ Category                 │──── Enum: Dependency, Secret, SQLInjection,
                         │ Severity                 │      XSS, Deserialization, Crypto, CSRF,
                         │ CvssScore (DECIMAL 3,1)  │      AuthMisconfig, PathTraversal, Malware,
                         │ CweId                    │      LicenseIssue, ConfigMisconfig, etc.
                         │ CveId (nullable)         │
                         │ Title                    │
                         │ Description              │
                         │ FilePath                 │
                         │ LineStart                │
                         │ LineEnd                  │
                         │ CodeSnippet              │
                         │ Scanner                  │──── Which scanner found it
                         │ IsAutoFixable            │
                         │ Status                   │──── Enum: Open, FixGenerated, FixValidated,
                         │ CreatedAt                │      PRCreated, PRMerged, Dismissed
                         └──────────┬───────────────┘
                                    │
                                    │ 1:0..1
                                    ▼
                         ┌──────────────────────────┐
                         │         Fixes            │
                         ├──────────────────────────┤
                         │ Id (PK, GUID)            │
                         │ VulnerabilityId (FK)     │
                         │ Status                   │──── Enum: Generating, Generated,
                         │ DiffContent (NVARCHAR MAX)│     BuildPassed, BuildFailed,
                         │ ConfidenceScore (DECIMAL) │     PRCreated, PRMerged, Failed
                         │ AIModel                  │──── "gpt-5.4-thinking" or "claude-opus-4-6"
                         │ AIPromptTokens           │
                         │ AICompletionTokens       │
                         │ BuildOutput              │
                         │ TestOutput               │
                         │ RetryCount               │
                         │ PRUrl (nullable)         │
                         │ PRNumber (nullable)       │
                         │ BranchName               │
                         │ CreatedAt                │
                         │ ValidatedAt              │
                         └──────────────────────────┘

                         ┌──────────────────────────┐
                         │      ScanEvents          │
                         ├──────────────────────────┤
                         │ Id (PK, BIGINT IDENTITY) │
                         │ ScanId (FK)              │
                         │ EventType                │──── scan.started, scan.progress,
                         │ WorkerName               │      vuln.found, fix.generated,
                         │ Message                  │      fix.validated, scan.completed
                         │ Metadata (NVARCHAR MAX)  │──── JSON blob
                         │ CreatedAt                │
                         └──────────────────────────┘

                         ┌──────────────────────────┐
                         │  SupportedLanguages      │
                         ├──────────────────────────┤
                         │ Id (PK, INT IDENTITY)    │
                         │ Language                 │──── "C#", "TypeScript", "Python", etc.
                         │ Framework                │──── ".NET Core", "Express", "Django", etc.
                         │ DisplayName              │
                         │ ProjectFilePattern       │──── "*.csproj", "package.json", etc.
                         │ BuildCommand             │
                         │ TestCommand              │
                         │ PackageManager           │
                         │ DockerImage              │──── SDK image for build validation
                         │ IsEnabled                │
                         │ SortOrder                │
                         └──────────────────────────┘
```

### SQL Server Migration Script (Initial)

```sql
-- File: migrations/001_initial_schema.sql

CREATE TABLE Users (
    Id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Email NVARCHAR(255) NOT NULL,
    GitHubUsername NVARCHAR(100) NOT NULL,
    GitHubTokenEncrypted VARBINARY(MAX) NOT NULL,
    PlanTier NVARCHAR(20) NOT NULL DEFAULT 'free',
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    UpdatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    IsActive BIT NOT NULL DEFAULT 1,
    CONSTRAINT UQ_Users_Email UNIQUE (Email),
    CONSTRAINT UQ_Users_GitHubUsername UNIQUE (GitHubUsername)
);

CREATE TABLE Repositories (
    Id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    UserId UNIQUEIDENTIFIER NOT NULL REFERENCES Users(Id),
    GitHubUrl NVARCHAR(500) NOT NULL,
    Owner NVARCHAR(100) NOT NULL,
    Name NVARCHAR(100) NOT NULL,
    DefaultBranch NVARCHAR(100) NOT NULL DEFAULT 'main',
    Language NVARCHAR(50) NULL,
    Framework NVARCHAR(100) NULL,
    LastScannedAt DATETIME2 NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT UQ_Repos_User_Url UNIQUE (UserId, GitHubUrl)
);

CREATE TABLE Scans (
    Id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    RepositoryId UNIQUEIDENTIFIER NOT NULL REFERENCES Repositories(Id),
    UserId UNIQUEIDENTIFIER NOT NULL REFERENCES Users(Id),
    Status NVARCHAR(30) NOT NULL DEFAULT 'queued',
    Language NVARCHAR(50) NOT NULL,
    Framework NVARCHAR(100) NULL,
    Branch NVARCHAR(100) NOT NULL,
    CommitSha NVARCHAR(40) NULL,
    TotalVulnerabilities INT NOT NULL DEFAULT 0,
    FixedCount INT NOT NULL DEFAULT 0,
    StartedAt DATETIME2 NULL,
    CompletedAt DATETIME2 NULL,
    ErrorMessage NVARCHAR(MAX) NULL,
    ScanDurationSec INT NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);
CREATE INDEX IX_Scans_UserId ON Scans(UserId);
CREATE INDEX IX_Scans_RepositoryId ON Scans(RepositoryId);
CREATE INDEX IX_Scans_Status ON Scans(Status);

CREATE TABLE Vulnerabilities (
    Id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    ScanId UNIQUEIDENTIFIER NOT NULL REFERENCES Scans(Id) ON DELETE CASCADE,
    Category NVARCHAR(50) NOT NULL,
    Severity NVARCHAR(20) NOT NULL,
    CvssScore DECIMAL(3,1) NULL,
    CweId NVARCHAR(20) NULL,
    CveId NVARCHAR(30) NULL,
    Title NVARCHAR(500) NOT NULL,
    Description NVARCHAR(MAX) NOT NULL,
    FilePath NVARCHAR(1000) NULL,
    LineStart INT NULL,
    LineEnd INT NULL,
    CodeSnippet NVARCHAR(MAX) NULL,
    Scanner NVARCHAR(50) NOT NULL,
    IsAutoFixable BIT NOT NULL DEFAULT 0,
    Status NVARCHAR(30) NOT NULL DEFAULT 'open',
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);
CREATE INDEX IX_Vulns_ScanId ON Vulnerabilities(ScanId);
CREATE INDEX IX_Vulns_Severity ON Vulnerabilities(Severity);
CREATE INDEX IX_Vulns_Category ON Vulnerabilities(Category);

CREATE TABLE Fixes (
    Id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    VulnerabilityId UNIQUEIDENTIFIER NOT NULL REFERENCES Vulnerabilities(Id) ON DELETE CASCADE,
    Status NVARCHAR(30) NOT NULL DEFAULT 'generating',
    DiffContent NVARCHAR(MAX) NULL,
    ConfidenceScore DECIMAL(5,2) NULL,
    AIModel NVARCHAR(50) NOT NULL,
    AIPromptTokens INT NULL,
    AICompletionTokens INT NULL,
    BuildOutput NVARCHAR(MAX) NULL,
    TestOutput NVARCHAR(MAX) NULL,
    RetryCount INT NOT NULL DEFAULT 0,
    PRUrl NVARCHAR(500) NULL,
    PRNumber INT NULL,
    BranchName NVARCHAR(200) NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    ValidatedAt DATETIME2 NULL
);
CREATE INDEX IX_Fixes_VulnId ON Fixes(VulnerabilityId);

CREATE TABLE ScanEvents (
    Id BIGINT IDENTITY(1,1) PRIMARY KEY,
    ScanId UNIQUEIDENTIFIER NOT NULL REFERENCES Scans(Id) ON DELETE CASCADE,
    EventType NVARCHAR(50) NOT NULL,
    WorkerName NVARCHAR(50) NULL,
    Message NVARCHAR(500) NULL,
    Metadata NVARCHAR(MAX) NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);
CREATE INDEX IX_ScanEvents_ScanId ON ScanEvents(ScanId);

CREATE TABLE SupportedLanguages (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    Language NVARCHAR(50) NOT NULL,
    Framework NVARCHAR(100) NOT NULL,
    DisplayName NVARCHAR(100) NOT NULL,
    ProjectFilePattern NVARCHAR(200) NOT NULL,
    BuildCommand NVARCHAR(500) NOT NULL,
    TestCommand NVARCHAR(500) NULL,
    PackageManager NVARCHAR(50) NOT NULL,
    DockerImage NVARCHAR(200) NOT NULL,
    IsEnabled BIT NOT NULL DEFAULT 1,
    SortOrder INT NOT NULL DEFAULT 0
);

-- Seed supported languages
INSERT INTO SupportedLanguages (Language, Framework, DisplayName, ProjectFilePattern, BuildCommand, TestCommand, PackageManager, DockerImage, IsEnabled, SortOrder)
VALUES
    ('csharp', '.NET Core', 'C# / .NET Core', '*.csproj;*.sln', 'dotnet build --no-restore', 'dotnet test --no-build', 'nuget', 'mcr.microsoft.com/dotnet/sdk:8.0', 1, 1),
    ('csharp', '.NET Framework', 'C# / .NET Framework', '*.csproj;*.sln', 'msbuild /restore', 'dotnet test', 'nuget', 'mcr.microsoft.com/dotnet/framework/sdk:4.8', 0, 2),
    ('typescript', 'Next.js', 'TypeScript / Next.js', 'package.json;next.config.*', 'npm run build', 'npm test', 'npm', 'node:20-alpine', 0, 3),
    ('typescript', 'Express', 'TypeScript / Express', 'package.json;tsconfig.json', 'npm run build', 'npm test', 'npm', 'node:20-alpine', 0, 4),
    ('javascript', 'Node.js', 'JavaScript / Node.js', 'package.json', 'npm run build', 'npm test', 'npm', 'node:20-alpine', 0, 5),
    ('python', 'Django', 'Python / Django', 'manage.py;requirements.txt', 'python -m py_compile', 'python manage.py test', 'pip', 'python:3.12-slim', 0, 6),
    ('python', 'FastAPI', 'Python / FastAPI', 'requirements.txt;pyproject.toml', 'python -m py_compile', 'pytest', 'pip', 'python:3.12-slim', 0, 7),
    ('java', 'Spring Boot', 'Java / Spring Boot', 'pom.xml;build.gradle', 'mvn compile', 'mvn test', 'maven', 'maven:3.9-eclipse-temurin-21', 0, 8),
    ('go', 'Go Standard', 'Go', 'go.mod', 'go build ./...', 'go test ./...', 'go modules', 'golang:1.22-alpine', 0, 9);

CREATE TABLE ScanConfigs (
    Id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    UserId UNIQUEIDENTIFIER NOT NULL REFERENCES Users(Id),
    RepositoryId UNIQUEIDENTIFIER NULL REFERENCES Repositories(Id),
    EnabledScanners NVARCHAR(MAX) NOT NULL DEFAULT '["dependency","secrets","sast","malware","config"]',
    AutoCreatePR BIT NOT NULL DEFAULT 1,
    ScheduleCron NVARCHAR(100) NULL,
    ExcludedPaths NVARCHAR(MAX) NULL,
    SeverityThreshold NVARCHAR(20) NOT NULL DEFAULT 'low',
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);
```

---

## 6. Backend API (Python FastAPI)

### Project Structure

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py                    # FastAPI app, CORS, middleware
│   ├── config.py                  # Settings from env vars
│   ├── database.py                # SQLAlchemy engine + session
│   │
│   ├── models/                    # SQLAlchemy ORM models
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── repository.py
│   │   ├── scan.py
│   │   ├── vulnerability.py
│   │   ├── fix.py
│   │   ├── scan_event.py
│   │   └── supported_language.py
│   │
│   ├── schemas/                   # Pydantic request/response schemas
│   │   ├── __init__.py
│   │   ├── scan.py
│   │   ├── vulnerability.py
│   │   ├── fix.py
│   │   └── language.py
│   │
│   ├── api/                       # Route handlers
│   │   ├── __init__.py
│   │   ├── router.py              # Main router that includes sub-routers
│   │   ├── scans.py
│   │   ├── vulnerabilities.py
│   │   ├── fixes.py
│   │   ├── repositories.py
│   │   ├── languages.py
│   │   ├── dashboard.py
│   │   └── webhooks.py
│   │
│   ├── services/                  # Business logic
│   │   ├── __init__.py
│   │   ├── github_service.py      # Clone, branch, PR creation
│   │   ├── scan_orchestrator.py   # Manages scan lifecycle
│   │   ├── ai_fix_service.py      # GPT-5.4 + Claude fallback
│   │   └── build_validator.py     # Docker sandbox builds
│   │
│   ├── scanners/                  # Individual scanner implementations
│   │   ├── __init__.py
│   │   ├── base_scanner.py        # Abstract base class
│   │   ├── dependency_scanner.py  # NuGet/npm/pip vulnerability checks
│   │   ├── secrets_scanner.py     # Gitleaks integration
│   │   ├── sast_scanner.py        # Semgrep integration
│   │   ├── malware_scanner.py     # ClamAV + YARA
│   │   ├── config_scanner.py      # Framework config checks
│   │   └── license_scanner.py     # License compliance
│   │
│   ├── scanners/rules/            # Language-specific rules
│   │   ├── csharp/
│   │   │   ├── semgrep-rules.yaml
│   │   │   └── config-rules.yaml
│   │   ├── typescript/
│   │   │   └── semgrep-rules.yaml
│   │   └── python/
│   │       └── semgrep-rules.yaml
│   │
│   ├── workers/                   # Celery task definitions
│   │   ├── __init__.py
│   │   ├── celery_app.py
│   │   ├── scan_tasks.py
│   │   ├── fix_tasks.py
│   │   └── pr_tasks.py
│   │
│   ├── websocket/                 # Real-time events
│   │   ├── __init__.py
│   │   └── manager.py
│   │
│   └── utils/
│       ├── __init__.py
│       ├── encryption.py          # Token encryption/decryption
│       ├── github_helpers.py
│       └── docker_helpers.py
│
├── alembic/                       # Database migrations
│   ├── env.py
│   └── versions/
│
├── tests/
│   ├── test_scanners/
│   ├── test_services/
│   ├── test_api/
│   └── conftest.py
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── alembic.ini
└── pyproject.toml
```

### Key Implementation Files

#### `app/main.py`

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.router import api_router
from app.config import settings
from app.database import engine
from app.websocket.manager import setup_socketio

app = FastAPI(
    title="Sealr API",
    version="2.0.0",
    description="GitHub Vulnerability Scanner & Auto-Fix Platform"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")

# Attach Socket.IO
sio_app = setup_socketio(app)
```

#### `app/config.py`

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Database
    SQL_SERVER_HOST: str = "localhost"
    SQL_SERVER_PORT: int = 1433
    SQL_SERVER_DB: str = "sealr"
    SQL_SERVER_USER: str = "sa"
    SQL_SERVER_PASSWORD: str = ""

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # AI Models
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-5.4"               # Primary
    OPENAI_THINKING_MODEL: str = "gpt-5.4-thinking"
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-opus-4-6"     # Backup

    # GitHub (for Sealr's own operations if needed)
    GITHUB_APP_ID: str = ""
    GITHUB_APP_PRIVATE_KEY: str = ""

    # Security
    ENCRYPTION_KEY: str = ""     # For encrypting user tokens at rest
    JWT_SECRET: str = ""

    # Frontend
    FRONTEND_URL: str = "http://localhost:3000"

    # Docker
    DOCKER_HOST: str = "unix:///var/run/docker.sock"

    # S3/MinIO
    S3_ENDPOINT: str = "http://localhost:9000"
    S3_ACCESS_KEY: str = ""
    S3_SECRET_KEY: str = ""
    S3_BUCKET: str = "sealr-scans"

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"mssql+pyodbc://{self.SQL_SERVER_USER}:{self.SQL_SERVER_PASSWORD}"
            f"@{self.SQL_SERVER_HOST}:{self.SQL_SERVER_PORT}/{self.SQL_SERVER_DB}"
            f"?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
        )

    class Config:
        env_file = ".env"

settings = Settings()
```

#### `app/database.py`

```python
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.config import settings

# Use aioodbc for async SQL Server
ASYNC_DATABASE_URL = settings.DATABASE_URL.replace("mssql+pyodbc", "mssql+aioodbc")

engine = create_async_engine(ASYNC_DATABASE_URL, echo=False, pool_size=20, max_overflow=10)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db():
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
```

#### `app/services/ai_fix_service.py`

```python
import openai
import anthropic
from app.config import settings

class AIFixService:
    """Generates vulnerability fixes using GPT-5.4 (primary) with Claude fallback."""

    def __init__(self):
        self.openai_client = openai.AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        self.anthropic_client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)

    async def generate_fix(
        self,
        vulnerability: dict,
        file_content: str,
        project_context: dict,
        language: str,
        framework: str,
    ) -> dict:
        """Try GPT-5.4 first, fall back to Claude on failure."""
        prompt = self._build_prompt(vulnerability, file_content, project_context, language, framework)

        # Try GPT-5.4 Thinking (primary)
        try:
            result = await self._call_gpt(prompt)
            return {"model": settings.OPENAI_THINKING_MODEL, **result}
        except Exception as e:
            print(f"GPT-5.4 failed: {e}, falling back to Claude")

        # Fallback to Claude
        try:
            result = await self._call_claude(prompt)
            return {"model": settings.ANTHROPIC_MODEL, **result}
        except Exception as e:
            raise RuntimeError(f"Both AI providers failed. GPT: {e}, Claude: {e}")

    async def _call_gpt(self, prompt: str) -> dict:
        response = await self.openai_client.chat.completions.create(
            model=settings.OPENAI_THINKING_MODEL,
            messages=[
                {"role": "system", "content": self._system_prompt()},
                {"role": "user", "content": prompt}
            ],
            max_tokens=4096,
            temperature=0.1,
        )
        content = response.choices[0].message.content
        return {
            "diff": self._extract_diff(content),
            "explanation": self._extract_explanation(content),
            "confidence": self._extract_confidence(content),
            "prompt_tokens": response.usage.prompt_tokens,
            "completion_tokens": response.usage.completion_tokens,
        }

    async def _call_claude(self, prompt: str) -> dict:
        response = await self.anthropic_client.messages.create(
            model=settings.ANTHROPIC_MODEL,
            max_tokens=4096,
            system=self._system_prompt(),
            messages=[{"role": "user", "content": prompt}],
        )
        content = response.content[0].text
        return {
            "diff": self._extract_diff(content),
            "explanation": self._extract_explanation(content),
            "confidence": self._extract_confidence(content),
            "prompt_tokens": response.usage.input_tokens,
            "completion_tokens": response.usage.output_tokens,
        }

    def _system_prompt(self) -> str:
        return """You are Sealr, an expert security engineer that fixes vulnerabilities in code.

Given a vulnerability description and the affected code, generate a fix as a unified diff.

Rules:
1. Output ONLY a valid unified diff that can be applied with `git apply`
2. The fix must be minimal — change only what's necessary
3. The fix must not break existing functionality
4. Include a brief explanation of what was changed and why
5. Assign a confidence score (0.0 to 1.0) based on how certain you are the fix is correct

Format your response EXACTLY as:

<explanation>
Brief explanation of the fix
</explanation>

<confidence>
0.95
</confidence>

<diff>
--- a/path/to/file.cs
+++ b/path/to/file.cs
@@ ... @@
 context line
-removed line
+added line
 context line
</diff>"""

    def _build_prompt(self, vulnerability, file_content, project_context, language, framework):
        return f"""## Vulnerability Details
- **Category:** {vulnerability['category']}
- **Severity:** {vulnerability['severity']}
- **CWE:** {vulnerability.get('cwe_id', 'N/A')}
- **CVE:** {vulnerability.get('cve_id', 'N/A')}
- **Description:** {vulnerability['description']}
- **File:** {vulnerability['file_path']}
- **Lines:** {vulnerability.get('line_start', '?')} - {vulnerability.get('line_end', '?')}
- **Language:** {language}
- **Framework:** {framework}

## Affected File Content
```
{file_content}
```

## Project Context
- Target Framework: {project_context.get('target_framework', 'Unknown')}
- Dependencies: {project_context.get('dependencies', [])}
- Has Tests: {project_context.get('has_tests', False)}

## Code Snippet (vulnerable section)
```
{vulnerability.get('code_snippet', 'See full file above')}
```

Generate a fix for this vulnerability."""

    def _extract_diff(self, content: str) -> str:
        if "<diff>" in content and "</diff>" in content:
            return content.split("<diff>")[1].split("</diff>")[0].strip()
        return content

    def _extract_explanation(self, content: str) -> str:
        if "<explanation>" in content and "</explanation>" in content:
            return content.split("<explanation>")[1].split("</explanation>")[0].strip()
        return ""

    def _extract_confidence(self, content: str) -> float:
        try:
            if "<confidence>" in content and "</confidence>" in content:
                score = content.split("<confidence>")[1].split("</confidence>")[0].strip()
                return float(score)
        except ValueError:
            pass
        return 0.5
```

#### `app/scanners/base_scanner.py`

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

@dataclass
class VulnerabilityResult:
    category: str
    severity: str          # critical, high, medium, low, informational
    cvss_score: Optional[float]
    cwe_id: Optional[str]
    cve_id: Optional[str]
    title: str
    description: str
    file_path: Optional[str]
    line_start: Optional[int]
    line_end: Optional[int]
    code_snippet: Optional[str]
    scanner: str
    is_auto_fixable: bool

class BaseScanner(ABC):
    """Abstract base class for all vulnerability scanners."""

    def __init__(self, repo_path: str, language: str, framework: str):
        self.repo_path = repo_path
        self.language = language
        self.framework = framework

    @abstractmethod
    async def scan(self) -> list[VulnerabilityResult]:
        """Run the scan and return a list of vulnerabilities."""
        pass

    @abstractmethod
    def is_applicable(self) -> bool:
        """Check if this scanner applies to the current language/framework."""
        pass
```

#### `app/scanners/dependency_scanner.py`

```python
import subprocess
import json
import httpx
from app.scanners.base_scanner import BaseScanner, VulnerabilityResult

class DependencyScanner(BaseScanner):
    """Scans for vulnerable dependencies using language-specific tools + OSV API."""

    async def scan(self) -> list[VulnerabilityResult]:
        if self.language == "csharp":
            return await self._scan_dotnet()
        elif self.language in ("javascript", "typescript"):
            return await self._scan_npm()
        elif self.language == "python":
            return await self._scan_pip()
        return []

    def is_applicable(self) -> bool:
        return True  # Dependency scanning applies to all languages

    async def _scan_dotnet(self) -> list[VulnerabilityResult]:
        results = []
        # Run dotnet list package --vulnerable
        proc = subprocess.run(
            ["dotnet", "list", "package", "--vulnerable", "--format", "json"],
            cwd=self.repo_path,
            capture_output=True, text=True, timeout=120
        )
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            for project in data.get("projects", []):
                for framework in project.get("frameworks", []):
                    for pkg in framework.get("topLevelPackages", []):
                        for vuln in pkg.get("vulnerabilities", []):
                            results.append(VulnerabilityResult(
                                category="dependency",
                                severity=self._map_severity(vuln.get("severity", "unknown")),
                                cvss_score=vuln.get("cvssScore"),
                                cwe_id=None,
                                cve_id=vuln.get("advisoryUrl", "").split("/")[-1] if "advisoryUrl" in vuln else None,
                                title=f"Vulnerable package: {pkg['id']} {pkg.get('resolvedVersion', '')}",
                                description=f"Package {pkg['id']} version {pkg.get('resolvedVersion', 'unknown')} has a known vulnerability. Recommended: upgrade to {pkg.get('latestVersion', 'latest')}.",
                                file_path=project.get("path"),
                                line_start=None,
                                line_end=None,
                                code_snippet=None,
                                scanner="dependency-dotnet",
                                is_auto_fixable=True,
                            ))

        # Also check OSV API for broader coverage
        results.extend(await self._check_osv_api())
        return results

    async def _check_osv_api(self) -> list[VulnerabilityResult]:
        """Cross-reference packages against OSV.dev for additional advisories."""
        results = []
        # Parse .csproj files for package references
        # Call https://api.osv.dev/v1/query with package info
        # ... implementation
        return results

    async def _scan_npm(self) -> list[VulnerabilityResult]:
        results = []
        proc = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=self.repo_path,
            capture_output=True, text=True, timeout=120
        )
        if proc.stdout:
            data = json.loads(proc.stdout)
            for advisory_id, advisory in data.get("vulnerabilities", {}).items():
                results.append(VulnerabilityResult(
                    category="dependency",
                    severity=advisory.get("severity", "unknown"),
                    cvss_score=None,
                    cwe_id=None,
                    cve_id=advisory.get("cve"),
                    title=f"Vulnerable package: {advisory_id}",
                    description=advisory.get("title", ""),
                    file_path="package.json",
                    line_start=None,
                    line_end=None,
                    code_snippet=None,
                    scanner="dependency-npm",
                    is_auto_fixable=True,
                ))
        return results

    async def _scan_pip(self) -> list[VulnerabilityResult]:
        results = []
        proc = subprocess.run(
            ["pip-audit", "--format", "json", "--requirement", "requirements.txt"],
            cwd=self.repo_path,
            capture_output=True, text=True, timeout=120
        )
        if proc.returncode == 0 and proc.stdout:
            data = json.loads(proc.stdout)
            for vuln in data:
                results.append(VulnerabilityResult(
                    category="dependency",
                    severity=self._map_severity(vuln.get("severity", "unknown")),
                    cvss_score=None,
                    cwe_id=None,
                    cve_id=vuln.get("id"),
                    title=f"Vulnerable package: {vuln['name']} {vuln.get('version', '')}",
                    description=vuln.get("description", ""),
                    file_path="requirements.txt",
                    line_start=None,
                    line_end=None,
                    code_snippet=None,
                    scanner="dependency-pip",
                    is_auto_fixable=True,
                ))
        return results

    def _map_severity(self, sev: str) -> str:
        mapping = {"Critical": "critical", "High": "high", "Moderate": "medium", "Low": "low"}
        return mapping.get(sev, "medium")
```

#### `app/scanners/malware_scanner.py`

```python
import subprocess
from app.scanners.base_scanner import BaseScanner, VulnerabilityResult

class MalwareScanner(BaseScanner):
    """Detects malware patterns using ClamAV + YARA rules."""

    async def scan(self) -> list[VulnerabilityResult]:
        results = []
        results.extend(await self._run_clamav())
        results.extend(await self._run_yara())
        results.extend(await self._check_suspicious_patterns())
        return results

    def is_applicable(self) -> bool:
        return True  # Malware scanning applies to all languages

    async def _run_clamav(self) -> list[VulnerabilityResult]:
        """Run ClamAV scan on the repository."""
        results = []
        proc = subprocess.run(
            ["clamscan", "--recursive", "--infected", "--no-summary", self.repo_path],
            capture_output=True, text=True, timeout=300
        )
        for line in proc.stdout.strip().split("\n"):
            if ": " in line and "FOUND" in line:
                file_path, malware_name = line.rsplit(": ", 1)
                malware_name = malware_name.replace(" FOUND", "")
                results.append(VulnerabilityResult(
                    category="malware",
                    severity="critical",
                    cvss_score=9.8,
                    cwe_id="CWE-506",
                    cve_id=None,
                    title=f"Malware detected: {malware_name}",
                    description=f"ClamAV detected malicious code signature '{malware_name}' in this file. This file should be removed or quarantined immediately.",
                    file_path=file_path.replace(self.repo_path + "/", ""),
                    line_start=None,
                    line_end=None,
                    code_snippet=None,
                    scanner="malware-clamav",
                    is_auto_fixable=False,
                ))
        return results

    async def _run_yara(self) -> list[VulnerabilityResult]:
        """Run YARA rules for known malicious patterns."""
        results = []
        # YARA rules for:
        # - Cryptocurrency miners
        # - Reverse shells
        # - Obfuscated payloads
        # - Known backdoor patterns
        # - Data exfiltration code
        proc = subprocess.run(
            ["yara", "-r", "/opt/sealr/yara-rules/malware.yar", self.repo_path],
            capture_output=True, text=True, timeout=300
        )
        for line in proc.stdout.strip().split("\n"):
            if line.strip():
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    rule_name, file_path = parts
                    results.append(VulnerabilityResult(
                        category="malware",
                        severity="critical",
                        cvss_score=9.0,
                        cwe_id="CWE-506",
                        cve_id=None,
                        title=f"Suspicious pattern: {rule_name}",
                        description=f"YARA rule '{rule_name}' matched. This may indicate malicious code, crypto mining, or a backdoor.",
                        file_path=file_path.replace(self.repo_path + "/", ""),
                        line_start=None,
                        line_end=None,
                        code_snippet=None,
                        scanner="malware-yara",
                        is_auto_fixable=False,
                    ))
        return results

    async def _check_suspicious_patterns(self) -> list[VulnerabilityResult]:
        """Custom checks for suspicious code patterns."""
        results = []
        # Check for:
        # - Base64-encoded executables
        # - eval() with network-fetched content
        # - Hidden files with executable content
        # - Typosquatted package names
        # - Post-install scripts that download external code
        # Implementation uses regex + AST analysis
        return results
```

#### `app/services/github_service.py`

```python
import httpx
import subprocess
import tempfile
import shutil
from pathlib import Path

class GitHubService:
    """Handles all GitHub operations using the user's PAT."""

    def __init__(self, token: str):
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        self.client = httpx.AsyncClient(
            base_url="https://api.github.com",
            headers=self.headers,
            timeout=30.0
        )

    async def validate_token(self) -> dict:
        """Verify the token has required scopes."""
        resp = await self.client.get("/user")
        resp.raise_for_status()
        scopes = resp.headers.get("X-OAuth-Scopes", "")
        return {"user": resp.json(), "scopes": scopes}

    async def get_repo_info(self, owner: str, repo: str) -> dict:
        resp = await self.client.get(f"/repos/{owner}/{repo}")
        resp.raise_for_status()
        return resp.json()

    def clone_repo(self, owner: str, repo: str, branch: str = "main") -> str:
        """Clone repo to temp directory. Returns the clone path."""
        clone_dir = tempfile.mkdtemp(prefix="sealr-")
        clone_url = f"https://x-access-token:{self.token}@github.com/{owner}/{repo}.git"
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, clone_url, clone_dir],
            check=True, capture_output=True, timeout=300
        )
        return clone_dir

    async def create_branch(self, owner: str, repo: str, branch_name: str, base_sha: str):
        resp = await self.client.post(
            f"/repos/{owner}/{repo}/git/refs",
            json={"ref": f"refs/heads/{branch_name}", "sha": base_sha}
        )
        resp.raise_for_status()
        return resp.json()

    async def create_or_update_file(self, owner, repo, path, content, message, branch, sha=None):
        import base64
        data = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch,
        }
        if sha:
            data["sha"] = sha
        resp = await self.client.put(f"/repos/{owner}/{repo}/contents/{path}", json=data)
        resp.raise_for_status()
        return resp.json()

    async def create_pull_request(self, owner, repo, title, body, head_branch, base_branch="main"):
        resp = await self.client.post(
            f"/repos/{owner}/{repo}/pulls",
            json={
                "title": title,
                "body": body,
                "head": head_branch,
                "base": base_branch,
            }
        )
        resp.raise_for_status()
        pr = resp.json()

        # Add labels
        await self.client.post(
            f"/repos/{owner}/{repo}/issues/{pr['number']}/labels",
            json={"labels": ["security", "sealr", "automated-fix"]}
        )
        return pr

    def cleanup(self, clone_dir: str):
        shutil.rmtree(clone_dir, ignore_errors=True)

    async def close(self):
        await self.client.aclose()
```

#### `app/services/build_validator.py`

```python
import docker
import tempfile
from pathlib import Path
from app.config import settings

class BuildValidator:
    """Validates fixes by building and testing in Docker sandbox."""

    def __init__(self):
        self.docker_client = docker.from_env()

    async def validate_fix(
        self,
        repo_path: str,
        diff_content: str,
        language_config: dict,
    ) -> dict:
        """
        Apply the diff, build, and test in isolated container.
        Returns {success: bool, build_output: str, test_output: str}
        """
        # Apply the diff to a working copy
        work_dir = tempfile.mkdtemp(prefix="sealr-build-")
        try:
            # Copy repo to work dir
            import shutil
            shutil.copytree(repo_path, work_dir, dirs_exist_ok=True)

            # Write diff to file and apply
            diff_path = Path(work_dir) / "sealr-fix.patch"
            diff_path.write_text(diff_content)

            # Run in Docker container
            container = self.docker_client.containers.run(
                image=language_config["docker_image"],
                command=self._build_command(language_config),
                volumes={work_dir: {"bind": "/app", "mode": "rw"}},
                working_dir="/app",
                detach=True,
                network_disabled=True,  # No network access for security
                mem_limit="2g",
                cpu_period=100000,
                cpu_quota=200000,  # 2 CPU cores max
                remove=False,
            )

            # Wait with timeout
            result = container.wait(timeout=300)
            logs = container.logs().decode("utf-8")
            exit_code = result["StatusCode"]
            container.remove()

            return {
                "success": exit_code == 0,
                "build_output": logs,
                "test_output": logs,  # Combined for now
                "exit_code": exit_code,
            }
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    def _build_command(self, language_config: dict) -> str:
        """Generate the build + test command for the container."""
        build_cmd = language_config["build_command"]
        test_cmd = language_config.get("test_command", "")

        script = f"""
        cd /app &&
        git apply sealr-fix.patch &&
        {build_cmd}
        """
        if test_cmd:
            script += f" && {test_cmd}"

        return ["sh", "-c", script]
```

---

## 7. Frontend (Next.js 16)

### Project Structure

```
frontend/
├── app/                           # Next.js 16 App Router
│   ├── layout.tsx                 # Root layout
│   ├── page.tsx                   # Home / Landing page
│   ├── globals.css                # Tailwind imports
│   │
│   ├── (auth)/
│   │   ├── login/page.tsx         # GitHub token input
│   │   └── layout.tsx
│   │
│   ├── (dashboard)/
│   │   ├── layout.tsx             # Dashboard layout with sidebar
│   │   ├── page.tsx               # Dashboard overview
│   │   │
│   │   ├── scan/
│   │   │   ├── page.tsx           # New scan form
│   │   │   └── [id]/
│   │   │       ├── page.tsx       # Scan detail + progress
│   │   │       ├── vulnerabilities/
│   │   │       │   └── page.tsx   # Vulnerability list for scan
│   │   │       └── fixes/
│   │   │           └── page.tsx   # Fixes + PR status
│   │   │
│   │   ├── history/
│   │   │   └── page.tsx           # Scan history
│   │   │
│   │   ├── repositories/
│   │   │   └── page.tsx           # Connected repos
│   │   │
│   │   └── settings/
│   │       └── page.tsx           # User settings, token management
│   │
│   └── api/                       # Next.js API routes (if needed for BFF)
│       └── auth/[...nextauth]/route.ts
│
├── components/
│   ├── ui/                        # shadcn/ui components
│   │   ├── button.tsx
│   │   ├── card.tsx
│   │   ├── badge.tsx
│   │   ├── dialog.tsx
│   │   ├── dropdown-menu.tsx
│   │   ├── input.tsx
│   │   ├── select.tsx
│   │   ├── table.tsx
│   │   ├── tabs.tsx
│   │   └── toast.tsx
│   │
│   ├── layout/
│   │   ├── sidebar.tsx
│   │   ├── header.tsx
│   │   └── footer.tsx
│   │
│   ├── scan/
│   │   ├── scan-form.tsx          # Repo URL + token + language selector
│   │   ├── scan-progress.tsx      # Real-time progress via WebSocket
│   │   ├── language-selector.tsx  # Language/framework dropdown
│   │   └── scan-summary.tsx
│   │
│   ├── vulnerability/
│   │   ├── vuln-table.tsx         # Filterable/sortable vulnerability table
│   │   ├── vuln-detail.tsx        # Single vulnerability detail view
│   │   ├── severity-badge.tsx     # Color-coded severity badges
│   │   └── category-filter.tsx
│   │
│   ├── fix/
│   │   ├── diff-viewer.tsx        # Monaco-based side-by-side diff
│   │   ├── fix-card.tsx
│   │   ├── pr-status.tsx
│   │   └── fix-actions.tsx
│   │
│   └── dashboard/
│       ├── stats-cards.tsx
│       ├── vuln-trend-chart.tsx
│       └── recent-scans.tsx
│
├── lib/
│   ├── api-client.ts              # Axios/fetch wrapper for backend API
│   ├── socket.ts                  # Socket.IO client setup
│   ├── utils.ts                   # Helper utilities
│   └── constants.ts
│
├── stores/
│   ├── scan-store.ts              # Zustand store for scan state
│   ├── auth-store.ts              # Token management
│   └── ui-store.ts                # UI state (sidebar, theme)
│
├── hooks/
│   ├── use-scan.ts                # TanStack Query hooks for scans
│   ├── use-vulnerabilities.ts
│   ├── use-languages.ts
│   └── use-socket.ts              # WebSocket hook
│
├── types/
│   ├── scan.ts
│   ├── vulnerability.ts
│   ├── fix.ts
│   └── language.ts
│
├── public/
│   └── logo.svg
│
├── next.config.ts
├── tailwind.config.ts
├── tsconfig.json
├── package.json
└── .env.local
```

### Key UI Components

#### `components/scan/language-selector.tsx`

```tsx
"use client";

import { useLanguages } from "@/hooks/use-languages";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface LanguageSelectorProps {
  value: string;
  onChange: (value: string) => void;
}

export function LanguageSelector({ value, onChange }: LanguageSelectorProps) {
  const { data: languages, isLoading } = useLanguages();

  // Group by language
  const grouped = languages?.reduce((acc, lang) => {
    if (!acc[lang.language]) acc[lang.language] = [];
    acc[lang.language].push(lang);
    return acc;
  }, {} as Record<string, typeof languages>);

  return (
    <div className="space-y-2">
      <label className="text-sm font-medium text-zinc-300">
        Language & Framework
      </label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger className="w-full bg-zinc-900 border-zinc-700">
          <SelectValue placeholder="Select language & framework..." />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="auto">
            Auto-Detect (scan project files)
          </SelectItem>
          {grouped && Object.entries(grouped).map(([lang, frameworks]) => (
            frameworks.map((fw) => (
              <SelectItem
                key={`${fw.language}-${fw.framework}`}
                value={`${fw.language}:${fw.framework}`}
                disabled={!fw.isEnabled}
              >
                {fw.displayName}
                {!fw.isEnabled && " (Coming Soon)"}
              </SelectItem>
            ))
          ))}
        </SelectContent>
      </Select>
      <p className="text-xs text-zinc-500">
        Selecting a language ensures the correct vulnerability rules and fix
        templates are used. Auto-detect works for most projects.
      </p>
    </div>
  );
}
```

#### `components/scan/scan-form.tsx`

```tsx
"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { LanguageSelector } from "./language-selector";
import { useAuthStore } from "@/stores/auth-store";
import { apiClient } from "@/lib/api-client";

const scanSchema = z.object({
  repoUrl: z
    .string()
    .url("Must be a valid URL")
    .regex(/github\.com\/[\w.-]+\/[\w.-]+/, "Must be a valid GitHub repo URL"),
  githubToken: z.string().min(1, "GitHub token is required"),
  language: z.string().default("auto"),
  branch: z.string().optional(),
});

type ScanFormData = z.infer<typeof scanSchema>;

export function ScanForm() {
  const router = useRouter();
  const { token, setToken } = useAuthStore();
  const [isSubmitting, setIsSubmitting] = useState(false);

  const {
    register,
    handleSubmit,
    setValue,
    watch,
    formState: { errors },
  } = useForm<ScanFormData>({
    resolver: zodResolver(scanSchema),
    defaultValues: {
      githubToken: token || "",
      language: "auto",
    },
  });

  const selectedLanguage = watch("language");

  const onSubmit = async (data: ScanFormData) => {
    setIsSubmitting(true);
    try {
      // Save token for future use
      setToken(data.githubToken);

      // Create scan
      const scan = await apiClient.post("/api/scans", {
        repo_url: data.repoUrl,
        github_token: data.githubToken,
        language: data.language === "auto" ? null : data.language.split(":")[0],
        framework: data.language === "auto" ? null : data.language.split(":")[1],
        branch: data.branch || undefined,
      });

      router.push(`/scan/${scan.data.id}`);
    } catch (error) {
      console.error("Scan creation failed:", error);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Card className="p-8 bg-zinc-950 border-zinc-800 max-w-2xl mx-auto">
      <h2 className="text-2xl font-bold text-white mb-6">
        Start a New Scan
      </h2>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        {/* Repository URL */}
        <div className="space-y-2">
          <label className="text-sm font-medium text-zinc-300">
            GitHub Repository URL
          </label>
          <Input
            {...register("repoUrl")}
            placeholder="https://github.com/owner/repo"
            className="bg-zinc-900 border-zinc-700 text-white"
          />
          {errors.repoUrl && (
            <p className="text-sm text-red-400">{errors.repoUrl.message}</p>
          )}
        </div>

        {/* GitHub Token */}
        <div className="space-y-2">
          <label className="text-sm font-medium text-zinc-300">
            GitHub Personal Access Token
          </label>
          <Input
            {...register("githubToken")}
            type="password"
            placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
            className="bg-zinc-900 border-zinc-700 text-white"
          />
          {errors.githubToken && (
            <p className="text-sm text-red-400">{errors.githubToken.message}</p>
          )}
          <p className="text-xs text-zinc-500">
            Needs <code>repo</code> scope for private repos, or <code>public_repo</code> for public repos.
          </p>
        </div>

        {/* Language/Framework Selector */}
        <LanguageSelector
          value={selectedLanguage}
          onChange={(val) => setValue("language", val)}
        />

        {/* Branch (optional) */}
        <div className="space-y-2">
          <label className="text-sm font-medium text-zinc-300">
            Branch <span className="text-zinc-500">(optional, defaults to main)</span>
          </label>
          <Input
            {...register("branch")}
            placeholder="main"
            className="bg-zinc-900 border-zinc-700 text-white"
          />
        </div>

        <Button
          type="submit"
          disabled={isSubmitting}
          className="w-full bg-emerald-600 hover:bg-emerald-700 text-white font-semibold py-3"
        >
          {isSubmitting ? "Starting Scan..." : "Scan Repository"}
        </Button>
      </form>
    </Card>
  );
}
```

#### `types/scan.ts`

```typescript
export interface Scan {
  id: string;
  repositoryId: string;
  userId: string;
  status: ScanStatus;
  language: string;
  framework: string | null;
  branch: string;
  commitSha: string | null;
  totalVulnerabilities: number;
  fixedCount: number;
  startedAt: string | null;
  completedAt: string | null;
  errorMessage: string | null;
  scanDurationSec: number | null;
  createdAt: string;
}

export type ScanStatus =
  | "queued"
  | "cloning"
  | "scanning"
  | "fixing"
  | "validating"
  | "creating_prs"
  | "completed"
  | "failed";

export interface Vulnerability {
  id: string;
  scanId: string;
  category: VulnerabilityCategory;
  severity: Severity;
  cvssScore: number | null;
  cweId: string | null;
  cveId: string | null;
  title: string;
  description: string;
  filePath: string | null;
  lineStart: number | null;
  lineEnd: number | null;
  codeSnippet: string | null;
  scanner: string;
  isAutoFixable: boolean;
  status: VulnerabilityStatus;
}

export type VulnerabilityCategory =
  | "dependency"
  | "secret"
  | "sql_injection"
  | "xss"
  | "deserialization"
  | "crypto"
  | "csrf"
  | "auth_misconfig"
  | "path_traversal"
  | "malware"
  | "license"
  | "config_misconfig"
  | "security_header"
  | "logging_sensitive";

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export type VulnerabilityStatus =
  | "open"
  | "fix_generated"
  | "fix_validated"
  | "pr_created"
  | "pr_merged"
  | "dismissed";

export interface Fix {
  id: string;
  vulnerabilityId: string;
  status: FixStatus;
  diffContent: string | null;
  confidenceScore: number | null;
  aiModel: string;
  buildOutput: string | null;
  testOutput: string | null;
  retryCount: number;
  prUrl: string | null;
  prNumber: number | null;
  branchName: string | null;
}

export type FixStatus =
  | "generating"
  | "generated"
  | "build_passed"
  | "build_failed"
  | "pr_created"
  | "pr_merged"
  | "failed";

export interface SupportedLanguage {
  id: number;
  language: string;
  framework: string;
  displayName: string;
  projectFilePattern: string;
  buildCommand: string;
  testCommand: string | null;
  packageManager: string;
  dockerImage: string;
  isEnabled: boolean;
  sortOrder: number;
}
```

---

## 8. Scanner Engine

### Scanner Registry Pattern

Each scanner is a plugin. The orchestrator loads the applicable scanners based on the language/framework selection.

```python
# app/scanners/__init__.py

from app.scanners.dependency_scanner import DependencyScanner
from app.scanners.secrets_scanner import SecretsScanner
from app.scanners.sast_scanner import SASTScanner
from app.scanners.malware_scanner import MalwareScanner
from app.scanners.config_scanner import ConfigScanner
from app.scanners.license_scanner import LicenseScanner

SCANNER_REGISTRY = [
    DependencyScanner,
    SecretsScanner,
    SASTScanner,
    MalwareScanner,
    ConfigScanner,
    LicenseScanner,
]

def get_applicable_scanners(repo_path: str, language: str, framework: str):
    """Return scanner instances that apply to this language/framework."""
    scanners = []
    for scanner_class in SCANNER_REGISTRY:
        scanner = scanner_class(repo_path, language, framework)
        if scanner.is_applicable():
            scanners.append(scanner)
    return scanners
```

### Semgrep Custom Rules (C# Example)

```yaml
# app/scanners/rules/csharp/semgrep-rules.yaml
rules:
  - id: csharp-sql-injection-string-concat
    patterns:
      - pattern: |
          new SqlCommand($CMD, ...)
      - metavariable-regex:
          metavariable: $CMD
          regex: '.*\+.*'
    message: "SQL injection risk: SqlCommand with string concatenation"
    severity: ERROR
    languages: [csharp]
    metadata:
      category: sql_injection
      cwe: "CWE-89"
      auto_fixable: true

  - id: csharp-sql-injection-fromrawsql
    pattern: |
      .FromSqlRaw($QUERY, ...)
    message: "SQL injection risk: use FromSqlInterpolated instead of FromSqlRaw"
    severity: WARNING
    languages: [csharp]
    metadata:
      category: sql_injection
      cwe: "CWE-89"
      auto_fixable: true

  - id: csharp-xss-html-raw
    pattern: |
      @Html.Raw(...)
    message: "XSS risk: Html.Raw renders unencoded HTML"
    severity: WARNING
    languages: [csharp]
    metadata:
      category: xss
      cwe: "CWE-79"
      auto_fixable: true

  - id: csharp-insecure-deserialization-binary
    pattern: |
      new BinaryFormatter()
    message: "Insecure deserialization: BinaryFormatter is vulnerable to RCE"
    severity: ERROR
    languages: [csharp]
    metadata:
      category: deserialization
      cwe: "CWE-502"
      auto_fixable: true

  - id: csharp-weak-crypto-md5
    pattern: |
      MD5.Create()
    message: "Weak cryptography: MD5 is not collision-resistant"
    severity: WARNING
    languages: [csharp]
    metadata:
      category: crypto
      cwe: "CWE-328"
      auto_fixable: true

  - id: csharp-weak-crypto-sha1
    pattern: |
      SHA1.Create()
    message: "Weak cryptography: SHA1 is deprecated for security use"
    severity: WARNING
    languages: [csharp]
    metadata:
      category: crypto
      cwe: "CWE-328"
      auto_fixable: true

  - id: csharp-hardcoded-connection-string
    pattern-regex: '(Server|Data Source|Initial Catalog|Password)=.+'
    message: "Potential hardcoded connection string — extract to configuration"
    severity: WARNING
    languages: [csharp]
    metadata:
      category: secret
      cwe: "CWE-798"
      auto_fixable: true
```

---

## 9. AI Fix Engine

### Fix Generation Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                     AI FIX ENGINE FLOW                            │
│                                                                  │
│  Vulnerability + File Content + Context                          │
│       │                                                          │
│       ▼                                                          │
│  ┌─────────────────────────────────┐                             │
│  │ Check Fix Template Library      │◄── Pre-built fixes for     │
│  │ (common patterns, no AI needed) │    common patterns          │
│  └────────────┬────────────────────┘                             │
│               │                                                  │
│         Template found?                                          │
│        ╱            ╲                                            │
│      YES             NO                                          │
│       │               │                                          │
│       ▼               ▼                                          │
│  Apply Template   ┌──────────────────┐                           │
│  (fast, free)     │ Call GPT-5.4     │                           │
│       │           │ Thinking API     │                           │
│       │           └────────┬─────────┘                           │
│       │                    │                                     │
│       │              Success?                                    │
│       │             ╱        ╲                                   │
│       │           YES         NO                                 │
│       │            │           │                                  │
│       │            │    ┌──────▼──────────┐                      │
│       │            │    │ Call Claude      │                      │
│       │            │    │ Opus 4.6 API    │                      │
│       │            │    │ (backup)        │                      │
│       │            │    └────────┬────────┘                      │
│       │            │             │                                │
│       ▼            ▼             ▼                                │
│  ┌──────────────────────────────────────┐                        │
│  │         UNIFIED DIFF OUTPUT          │                        │
│  │  + Explanation + Confidence Score    │                        │
│  └──────────────────┬───────────────────┘                        │
│                     │                                            │
│                     ▼                                            │
│  ┌──────────────────────────────────────┐                        │
│  │      BUILD VALIDATION (Docker)       │                        │
│  │  git apply → dotnet build → test     │                        │
│  └──────────────────┬───────────────────┘                        │
│                     │                                            │
│               Pass?                                              │
│              ╱      ╲                                            │
│            YES       NO                                          │
│             │         │                                          │
│             │    ┌────▼─────────────────┐                        │
│             │    │ Retry with error     │                        │
│             │    │ context (max 3x)     │                        │
│             │    └────┬────────────────┘                         │
│             │         │                                          │
│             ▼         ▼                                          │
│       ✅ Validated   ❌ Failed                                   │
│       (ready for PR)  (flag for manual review)                   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Fix Template Examples (No AI Needed)

```python
# app/services/fix_templates.py

FIX_TEMPLATES = {
    "csharp": {
        "dependency_version_bump": {
            "pattern": r'<PackageReference Include="(\w+)" Version="([\d.]+)"',
            "fix": lambda match, new_version: match.group(0).replace(
                f'Version="{match.group(2)}"', f'Version="{new_version}"'
            ),
        },
        "md5_to_sha256": {
            "pattern": r"MD5\.Create\(\)",
            "replacement": "SHA256.Create()",
            "additional_using": "using System.Security.Cryptography;",
        },
        "sha1_to_sha256": {
            "pattern": r"SHA1\.Create\(\)",
            "replacement": "SHA256.Create()",
        },
        "binary_formatter_removal": {
            "pattern": r"new BinaryFormatter\(\)",
            "replacement": "new System.Text.Json.JsonSerializer()",
            "note": "Review: BinaryFormatter replaced with JsonSerializer. Adjust serialization logic.",
        },
        "validate_antiforgery": {
            "pattern": r"\[HttpPost\]\s*(?!\[ValidateAntiForgeryToken\])",
            "replacement": "[HttpPost]\n    [ValidateAntiForgeryToken]",
        },
    }
}
```

---

## 10. GitHub Integration

### PR Body Template

```markdown
## 🔒 Sealr Security Fix

### Vulnerability
- **Category:** {category}
- **Severity:** {severity_badge}
- **CVSS Score:** {cvss_score}
- **CWE:** [{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_number}.html)
- **CVE:** {cve_id or "N/A"}

### Description
{vulnerability_description}

### What Changed
{fix_explanation}

### Files Modified
{file_list}

### Validation Results
- ✅ Build: **Passed**
- ✅ Tests: **Passed** ({test_count} tests)
- 🤖 AI Model: {ai_model}
- 📊 Confidence: {confidence_score}%

### Before / After

<details>
<summary>View diff</summary>

```diff
{diff_content}
```

</details>

---
*This PR was automatically generated by [Sealr](https://sealr.dev). Review the changes carefully before merging.*
```

---

## 11. Build Validation Sandbox

### Docker Images per Language

| Language | Docker Image | Build Command | Test Command |
|----------|-------------|---------------|-------------|
| C# / .NET Core 8 | `mcr.microsoft.com/dotnet/sdk:8.0` | `dotnet restore && dotnet build` | `dotnet test` |
| C# / .NET Core 9 | `mcr.microsoft.com/dotnet/sdk:9.0` | `dotnet restore && dotnet build` | `dotnet test` |
| Node.js / TypeScript | `node:20-alpine` | `npm ci && npm run build` | `npm test` |
| Python / Django | `python:3.12-slim` | `pip install -r requirements.txt` | `python manage.py test` |
| Python / FastAPI | `python:3.12-slim` | `pip install -r requirements.txt` | `pytest` |
| Java / Spring Boot | `maven:3.9-eclipse-temurin-21` | `mvn compile` | `mvn test` |
| Go | `golang:1.22-alpine` | `go build ./...` | `go test ./...` |

### Sandbox Security Rules

```
1. Network disabled (network_disabled=True)
2. Memory limited to 2GB
3. CPU limited to 2 cores
4. Timeout: 5 minutes max
5. Read-only source mount + writable work dir
6. No privileged mode
7. Ephemeral — container destroyed after validation
8. No volume mounts to host filesystem
```

---

## 12. Project Structure (Full Monorepo)

```
sealr/
├── frontend/                      # Next.js 16 app
│   ├── app/
│   ├── components/
│   ├── lib/
│   ├── stores/
│   ├── hooks/
│   ├── types/
│   ├── public/
│   ├── next.config.ts
│   ├── tailwind.config.ts
│   ├── package.json
│   └── Dockerfile
│
├── backend/                       # Python FastAPI
│   ├── app/
│   │   ├── api/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── scanners/
│   │   │   ├── rules/
│   │   │   │   ├── csharp/
│   │   │   │   ├── typescript/
│   │   │   │   └── python/
│   │   │   └── ...
│   │   ├── workers/
│   │   ├── websocket/
│   │   └── utils/
│   ├── alembic/
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
│
├── docker/
│   ├── docker-compose.yml          # Full local dev stack
│   ├── docker-compose.prod.yml
│   ├── nginx/
│   │   └── nginx.conf
│   └── yara-rules/
│       └── malware.yar
│
├── docs/
│   ├── architecture.md
│   ├── api-reference.md
│   └── scanner-rules.md
│
├── scripts/
│   ├── setup-dev.sh
│   ├── seed-languages.sql
│   └── run-tests.sh
│
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── deploy-staging.yml
│       └── deploy-prod.yml
│
├── .env.example
├── README.md
└── Makefile
```

---

## 13. Step-by-Step Development Guide

### Phase 1: Foundation (Weeks 1–4)

#### Week 1: Project Setup + Database

```bash
# 1. Create monorepo
mkdir sealr && cd sealr
git init

# 2. Frontend
npx create-next-app@latest frontend --typescript --tailwind --app --turbopack
cd frontend
npx shadcn@latest init
npx shadcn@latest add button card input select badge table tabs dialog toast dropdown-menu
npm install zustand @tanstack/react-query @tanstack/react-query-devtools
npm install react-hook-form @hookform/resolvers zod
npm install @monaco-editor/react recharts socket.io-client lucide-react
npm install axios
cd ..

# 3. Backend
mkdir -p backend/app/{api,models,schemas,services,scanners,workers,websocket,utils}
cd backend
python -m venv venv
source venv/bin/activate
pip install fastapi uvicorn[standard] sqlalchemy[asyncio] alembic
pip install pyodbc aioodbc  # SQL Server
pip install celery redis
pip install python-socketio
pip install httpx gitpython python-dotenv pydantic-settings
pip install openai anthropic
pip install cryptography  # for token encryption

# 4. Database
# Start SQL Server in Docker
docker run -e "ACCEPT_EULA=Y" -e "SA_PASSWORD=YourStrong!Pass" \
  -p 1433:1433 --name sealr-sqlserver \
  -d mcr.microsoft.com/mssql/server:2022-latest

# Apply migration
sqlcmd -S localhost -U sa -P 'YourStrong!Pass' -d master \
  -Q "CREATE DATABASE sealr"
sqlcmd -S localhost -U sa -P 'YourStrong!Pass' -d sealr \
  -i migrations/001_initial_schema.sql
```

**Deliverables:**
- [ ] Next.js 16 frontend scaffold with shadcn/ui
- [ ] FastAPI backend scaffold with SQLAlchemy models
- [ ] SQL Server running with initial schema
- [ ] Docker Compose for local dev (SQL Server + Redis)
- [ ] Basic health check endpoints
- [ ] Environment config (.env)

#### Week 2: Auth + GitHub Integration

**Tasks:**
- [ ] Build login page — user enters GitHub PAT
- [ ] Token encryption at rest (AES-256-GCM via `cryptography` lib)
- [ ] GitHub token validation endpoint (`GET /user` with token)
- [ ] Repo info fetching (owner, name, default branch, language)
- [ ] Repo cloning service (shallow clone to temp dir)
- [ ] Zustand auth store + token persistence (encrypted localStorage)

#### Week 3: Language Selector + Scan Form

**Tasks:**
- [ ] `GET /api/languages` endpoint — returns supported languages from DB
- [ ] Language/framework selector component (dropdown with "Auto-Detect" option)
- [ ] Scan form: repo URL + token + language + branch
- [ ] `POST /api/scans` endpoint — validates input, creates scan record
- [ ] Project discovery service — detect .csproj/.sln files (for .NET)
- [ ] Scan status model + basic status tracking

#### Week 4: First Scanner (Dependency)

**Tasks:**
- [ ] BaseScanner abstract class
- [ ] DependencyScanner for .NET (`dotnet list package --vulnerable`)
- [ ] OSV API integration for broader CVE coverage
- [ ] Celery task for scan execution
- [ ] Redis setup as Celery broker
- [ ] WebSocket manager for real-time progress
- [ ] Basic scan progress UI

### Phase 2: Core Scanning (Weeks 5–8)

#### Week 5: Secrets Scanner
- [ ] Gitleaks integration (subprocess wrapper)
- [ ] Custom regex patterns for .NET-specific secrets (connection strings)
- [ ] Git history scanning (configurable depth)
- [ ] Results normalized to VulnerabilityResult format

#### Week 6: SAST Scanner
- [ ] Semgrep installation + C# ruleset
- [ ] Custom Semgrep rules for .NET-specific vulnerabilities
- [ ] Results parsing and normalization
- [ ] Severity mapping from Semgrep → CVSS

#### Week 7: Malware + Config Scanners
- [ ] ClamAV integration (Docker container with updated signatures)
- [ ] YARA rules for crypto miners, reverse shells, backdoors
- [ ] Configuration scanner for appsettings.json, Program.cs
- [ ] License scanner (licensee/NuGet license metadata)

#### Week 8: Vulnerability Dashboard
- [ ] Vulnerability explorer UI — filterable, sortable table
- [ ] Severity badges, category filters
- [ ] Code snippet viewer with syntax highlighting
- [ ] Scan summary cards (total vulns by severity)
- [ ] Parallel scanner execution (all scanners run concurrently)

### Phase 3: AI Fix Engine (Weeks 9–12)

#### Week 9: Fix Template System
- [ ] Fix templates for common patterns (no AI needed)
- [ ] Template matching engine
- [ ] Dependency version bump automation
- [ ] Simple regex-based fixes (MD5→SHA256, etc.)

#### Week 10: GPT-5.4 Integration
- [ ] OpenAI API client (GPT-5.4 Thinking)
- [ ] Prompt engineering with few-shot examples per vulnerability type
- [ ] Response parsing (diff extraction, confidence scoring)
- [ ] Anthropic API client (Claude backup)
- [ ] Automatic fallback logic

#### Week 11: Build Validation
- [ ] Docker sandbox setup (Docker-in-Docker)
- [ ] Build validation pipeline (apply diff → build → test)
- [ ] Error feedback loop (failed build → retry with error context)
- [ ] Container security hardening (no network, resource limits)

#### Week 12: Diff Viewer + Fix Preview
- [ ] Monaco-based side-by-side diff viewer
- [ ] Fix detail view with explanation + confidence
- [ ] "Apply Fix" / "Reject Fix" actions
- [ ] Fix retry trigger (manual)

### Phase 4: PR Automation (Weeks 13–16)

#### Week 13: PR Creation
- [ ] Branch creation via GitHub API
- [ ] File update via GitHub Contents API
- [ ] PR creation with rich body template
- [ ] Auto-labeling (security, severity, sealr)

#### Week 14: PR Lifecycle
- [ ] GitHub webhook receiver for PR events
- [ ] PR status tracking (open → merged → closed)
- [ ] PR tracker UI
- [ ] Batch fix mode (group related fixes per PR)

#### Week 15: Scheduling + Notifications
- [ ] Cron-based scheduled scans (Celery Beat)
- [ ] Email notifications (SendGrid/SES)
- [ ] Slack webhook integration
- [ ] Scan config UI (per-repo settings)

#### Week 16: Integration Testing
- [ ] End-to-end test: scan → detect → fix → validate → PR
- [ ] Test with real .NET repos (public test repos)
- [ ] Performance testing (large repos)
- [ ] Error handling and edge cases

### Phase 5: Polish + Production (Weeks 17–20)

#### Week 17: Dashboard Analytics
- [ ] Vulnerability trend charts (Recharts)
- [ ] Fix success rate metrics
- [ ] Scan history with filtering
- [ ] Export reports (PDF/CSV)

#### Week 18: Security Hardening
- [ ] Rate limiting (per-user, per-IP)
- [ ] Input sanitization audit
- [ ] Token rotation reminders
- [ ] Audit logging for all actions

#### Week 19: Performance
- [ ] Incremental scanning (only changed files)
- [ ] Result caching (Redis)
- [ ] Database query optimization (indexes, query plans)
- [ ] Frontend code splitting and lazy loading

#### Week 20: Deployment
- [ ] Production Docker Compose / Kubernetes config
- [ ] CI/CD pipelines (GitHub Actions)
- [ ] SSL/TLS setup
- [ ] Monitoring (Sentry + Prometheus + Grafana)
- [ ] Documentation and README

---

## 14. Environment Setup

### `docker-compose.yml` (Local Development)

```yaml
version: "3.8"

services:
  sqlserver:
    image: mcr.microsoft.com/mssql/server:2022-latest
    environment:
      ACCEPT_EULA: "Y"
      SA_PASSWORD: "Sealr@Dev123"
      MSSQL_PID: "Developer"
    ports:
      - "1433:1433"
    volumes:
      - sqlserver-data:/var/opt/mssql

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  minio:
    image: minio/minio
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: sealr
      MINIO_ROOT_PASSWORD: sealr123
    ports:
      - "9000:9000"
      - "9001:9001"
    volumes:
      - minio-data:/data

  backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      SQL_SERVER_HOST: sqlserver
      SQL_SERVER_PASSWORD: "Sealr@Dev123"
      REDIS_URL: redis://redis:6379/0
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}
    depends_on:
      - sqlserver
      - redis
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # For build validation

  celery-worker:
    build: ./backend
    command: celery -A app.workers.celery_app worker --loglevel=info --concurrency=4
    environment:
      SQL_SERVER_HOST: sqlserver
      SQL_SERVER_PASSWORD: "Sealr@Dev123"
      REDIS_URL: redis://redis:6379/0
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}
    depends_on:
      - sqlserver
      - redis
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    environment:
      NEXT_PUBLIC_API_URL: http://localhost:8000
      NEXT_PUBLIC_WS_URL: ws://localhost:8000

volumes:
  sqlserver-data:
  minio-data:
```

### `.env.example`

```env
# SQL Server
SQL_SERVER_HOST=localhost
SQL_SERVER_PORT=1433
SQL_SERVER_DB=sealr
SQL_SERVER_USER=sa
SQL_SERVER_PASSWORD=Sealr@Dev123

# Redis
REDIS_URL=redis://localhost:6379/0

# AI Models
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-5.4
OPENAI_THINKING_MODEL=gpt-5.4-thinking
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-opus-4-6

# Security
ENCRYPTION_KEY=your-32-byte-encryption-key-here
JWT_SECRET=your-jwt-secret-here

# Frontend
FRONTEND_URL=http://localhost:3000

# S3/MinIO
S3_ENDPOINT=http://localhost:9000
S3_ACCESS_KEY=sealr
S3_SECRET_KEY=sealr123
S3_BUCKET=sealr-scans
```

---

## 15. API Endpoints Reference

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/api/auth/validate-token` | Validate GitHub PAT, return user info | No |
| `GET` | `/api/languages` | List supported languages/frameworks | No |
| `POST` | `/api/scans` | Create and start a new scan | Token |
| `GET` | `/api/scans` | List user's scans (paginated) | Token |
| `GET` | `/api/scans/:id` | Get scan status and summary | Token |
| `DELETE` | `/api/scans/:id` | Cancel a running scan | Token |
| `GET` | `/api/scans/:id/vulnerabilities` | List vulnerabilities (filterable) | Token |
| `GET` | `/api/scans/:id/fixes` | List fixes with PR status | Token |
| `POST` | `/api/scans/:id/fix-all` | Generate fixes for all fixable vulns | Token |
| `GET` | `/api/vulnerabilities/:id` | Vulnerability detail with code context | Token |
| `POST` | `/api/vulnerabilities/:id/fix` | Generate fix for single vulnerability | Token |
| `POST` | `/api/vulnerabilities/:id/dismiss` | Dismiss a vulnerability | Token |
| `GET` | `/api/fixes/:id` | Fix detail with diff content | Token |
| `POST` | `/api/fixes/:id/create-pr` | Open a GitHub PR for this fix | Token |
| `POST` | `/api/fixes/:id/retry` | Retry fix generation | Token |
| `GET` | `/api/repositories` | List user's scanned repositories | Token |
| `GET` | `/api/dashboard/stats` | Aggregate stats for dashboard | Token |
| `POST` | `/api/webhooks/github` | GitHub webhook receiver | HMAC |

---

## 16. WebSocket Events

| Event | Direction | Payload | Description |
|-------|-----------|---------|-------------|
| `scan.started` | Server→Client | `{scanId, status}` | Scan execution began |
| `scan.progress` | Server→Client | `{scanId, scanner, progress, message}` | Per-scanner progress update |
| `scan.vulnerability.found` | Server→Client | `{scanId, vulnerability}` | New vulnerability discovered |
| `scan.fixing` | Server→Client | `{scanId, vulnerabilityId, status}` | Fix generation started |
| `scan.fix.generated` | Server→Client | `{scanId, fix}` | Fix generated successfully |
| `scan.fix.validated` | Server→Client | `{scanId, fixId, buildPassed}` | Build validation result |
| `scan.pr.created` | Server→Client | `{scanId, fixId, prUrl}` | PR opened on GitHub |
| `scan.completed` | Server→Client | `{scanId, summary}` | Scan fully completed |
| `scan.failed` | Server→Client | `{scanId, error}` | Scan failed with error |

---

## 17. Configuration & Environment Variables

See `.env.example` in Section 14 above for the complete list.

Key configuration notes:
- `ENCRYPTION_KEY` must be 32 bytes (base64-encoded) for AES-256-GCM encryption of GitHub tokens
- `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` are both required — GPT-5.4 is primary, Claude is backup
- Docker socket mount is required for the build validation sandbox
- SQL Server connection uses ODBC Driver 18 with TrustServerCertificate for local dev

---

## 18. Deployment Guide

### Option A: Docker Compose (Small Scale)

```bash
# Production deployment
docker compose -f docker-compose.prod.yml up -d

# With proper SQL Server, Redis, and Nginx
# SSL via Let's Encrypt + Nginx
```

### Option B: Cloud Deployment

| Component | AWS | Azure |
|-----------|-----|-------|
| Frontend | Vercel / CloudFront + S3 | Azure Static Web Apps |
| Backend | ECS Fargate / EC2 | Azure Container Apps |
| Database | RDS SQL Server | Azure SQL Database |
| Cache | ElastiCache Redis | Azure Cache for Redis |
| Storage | S3 | Azure Blob Storage |
| Queue | SQS + Redis | Azure Service Bus |
| Containers | ECR + ECS | ACR + ACA |
| CI/CD | GitHub Actions | GitHub Actions |

### Option C: Kubernetes (Scale)

```yaml
# k8s/deployment-backend.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sealr-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sealr-api
  template:
    metadata:
      labels:
        app: sealr-api
    spec:
      containers:
        - name: api
          image: sealr/backend:latest
          ports:
            - containerPort: 8000
          envFrom:
            - secretRef:
                name: sealr-secrets
```

---

## 19. Testing Strategy

### Backend Tests

```
tests/
├── unit/
│   ├── test_dependency_scanner.py   # Mock subprocess, test parsing
│   ├── test_secrets_scanner.py
│   ├── test_sast_scanner.py
│   ├── test_ai_fix_service.py       # Mock OpenAI/Anthropic APIs
│   ├── test_build_validator.py      # Mock Docker
│   └── test_github_service.py       # Mock GitHub API
│
├── integration/
│   ├── test_scan_pipeline.py        # Full scan flow with test repos
│   ├── test_fix_generation.py       # AI fix with real API (gated)
│   └── test_database.py             # SQL Server CRUD operations
│
└── e2e/
    └── test_full_workflow.py         # Scan → Detect → Fix → PR
```

### Frontend Tests

```
__tests__/
├── components/
│   ├── scan-form.test.tsx
│   ├── language-selector.test.tsx
│   ├── vuln-table.test.tsx
│   └── diff-viewer.test.tsx
│
├── hooks/
│   └── use-scan.test.tsx
│
└── e2e/
    └── cypress/ or playwright/
        ├── scan-workflow.spec.ts
        └── vulnerability-explorer.spec.ts
```

### Test Repos (for integration testing)

Create dedicated test repositories with known vulnerabilities:
- `sealr-test-dotnet` — C# project with planted SQLi, XSS, hardcoded secrets, vulnerable NuGet packages
- `sealr-test-node` — Node.js project (for Phase 2)
- `sealr-test-python` — Python project (for Phase 3)

---

## 20. Expansion Roadmap

### Phase 2: Node.js / TypeScript Support

**Effort:** ~4 weeks

- [ ] npm audit integration for dependency scanning
- [ ] Semgrep JS/TS rulesets (prototype pollution, XSS, ReDoS)
- [ ] ESLint security plugin integration
- [ ] Node.js build validator (Docker + node:20-alpine)
- [ ] Fix templates for common JS vulnerabilities
- [ ] Enable `typescript` / `javascript` in SupportedLanguages table

### Phase 3: Python Support

**Effort:** ~3 weeks

- [ ] pip-audit / Safety integration
- [ ] Semgrep Python rulesets (command injection, pickle, SSRF)
- [ ] Bandit integration for additional Python SAST
- [ ] Python build validator (Docker + python:3.12-slim)
- [ ] Fix templates for Django/FastAPI vulnerabilities

### Phase 4: Java / Spring Boot Support

**Effort:** ~4 weeks

- [ ] Maven/Gradle dependency scanning
- [ ] Semgrep Java rulesets
- [ ] SpotBugs integration
- [ ] Java build validator (Docker + maven:3.9-eclipse-temurin-21)

### Phase 5: Go Support

**Effort:** ~2 weeks

- [ ] govulncheck integration
- [ ] Semgrep Go rulesets
- [ ] Go build validator (Docker + golang:1.22-alpine)

### Future Enhancements

- [ ] GitHub App support (install once, scan all repos)
- [ ] GitLab + Bitbucket support
- [ ] CI/CD integration (scan on every push)
- [ ] SBOM generation (CycloneDX/SPDX)
- [ ] Compliance reporting (SOC2, PCI-DSS, HIPAA)
- [ ] AI learning from fix acceptance/rejection
- [ ] Custom scanner rule editor in UI
- [ ] Team/organization features with RBAC

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/your-org/sealr.git
cd sealr

# Start infrastructure
docker compose up -d sqlserver redis minio

# Backend
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8000

# Celery worker (new terminal)
celery -A app.workers.celery_app worker --loglevel=info

# Frontend (new terminal)
cd frontend
npm install
npm run dev

# Open http://localhost:3000
```

---

*Built with Sealr — because vulnerability reports shouldn't end at a PDF.*
