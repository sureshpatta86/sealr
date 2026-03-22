# 🛡️ Sealr

### GitHub Vulnerability Scanner & Auto-Fix Platform

> Seal every crack in your code.

```
  ╔══════════════╗     ╔══════════════╗     ╔══════════════╗     ╔══════════════╗
  ║   🔍 SCAN    ║ ──▶ ║  🤖 AI FIX   ║ ──▶ ║  🏗️ VALIDATE ║ ──▶ ║   📬 PR      ║
  ║  6 scanners  ║     ║  GPT-5.4 +   ║     ║  Docker      ║     ║  Auto-open   ║
  ║  in parallel ║     ║  Claude      ║     ║  sandbox     ║     ║  on GitHub   ║
  ╚══════════════╝     ╚══════════════╝     ╚══════════════╝     ╚══════════════╝
```

---

## ✨ Features

- **15 vulnerability categories** — dependencies, secrets, SQL injection, XSS, malware, and more
- **AI-powered fixes** — GPT-5.4 Thinking (primary) + Claude Opus 4.6 (backup)
- **Build validation** — every fix is compiled and tested in Docker before PR
- **Multi-language** — C#/.NET Core first, Node.js/Python/Java/Go planned
- **Language selector** — choose language/framework in UI for correct scanner rules
- **Real-time progress** — WebSocket-based live updates during scanning
- **Automated PRs** — rich PR descriptions with before/after code and validation results

---

## 🏗️ Tech Stack

| Layer | Technology |
|:------|:-----------|
| Frontend | **Next.js 16** + TypeScript + Tailwind + shadcn/ui |
| Backend | **Python 3.12** + FastAPI + SQLAlchemy |
| Database | **SQL Server 2022** |
| AI Engine | **LangGraph** + GPT-5.4 Thinking + Claude Opus 4.6 |
| Task Queue | **Celery** + Redis |
| Scanners | **Semgrep** + Gitleaks + ClamAV + YARA |
| Build Sandbox | **Docker**-in-Docker |

---

## 🚀 Quick Start

```bash
# 1. Clone
git clone https://github.com/your-org/sealr.git && cd sealr

# 2. Setup
make setup        # Install deps + create .env

# 3. Configure
nano .env         # Add your OpenAI + Anthropic API keys

# 4. Infrastructure
make infra        # Start SQL Server + Redis + MinIO

# 5. Database
make db-setup     # Create schema + seed languages

# 6. Run
make dev          # Start backend + frontend + worker

# 7. Open
open http://localhost:3000
```

---

## 📁 Project Structure

```
sealr/
├── 📂 frontend/               Next.js 16 (App Router + Turbopack)
│   ├── app/                   Pages and layouts
│   ├── components/            UI components (scan form, vuln table, diff viewer)
│   ├── hooks/                 React Query + WebSocket hooks
│   ├── stores/                Zustand state management
│   └── types/                 TypeScript interfaces
│
├── 📂 backend/                Python FastAPI
│   ├── app/
│   │   ├── api/               REST endpoints (scans, vulns, fixes, languages)
│   │   ├── models/            SQLAlchemy ORM models
│   │   ├── schemas/           Pydantic request/response schemas
│   │   ├── services/          Business logic (GitHub, AI fix engine, build validator)
│   │   ├── scanners/          Scanner plugins + Semgrep/YARA rules
│   │   ├── workers/           Celery task definitions
│   │   └── websocket/         Socket.IO real-time events
│   └── tests/                 Unit + integration + e2e tests
│
├── 📂 docker/                 Docker Compose + Nginx + YARA rules
├── 📂 scripts/                SQL migrations + setup scripts
├── 📂 docs/                   Documentation (you are here)
└── 📂 .github/                CI/CD workflows
```

---

## 📚 Documentation

| Document | Description |
|:---------|:------------|
| [`01_TECH_SPEC.md`](docs/01_TECH_SPEC.md) | Full technical specification with architecture diagrams |
| [`02_DEVELOPMENT_GUIDE.md`](docs/02_DEVELOPMENT_GUIDE.md) | Step-by-step build guide (20-week roadmap) |
| [`03_ARCHITECTURE.md`](docs/03_ARCHITECTURE.md) | Deep-dive architecture with data flow diagrams |
| [`04_API_REFERENCE.md`](docs/04_API_REFERENCE.md) | Complete REST API + WebSocket documentation |
| [`05_SCANNER_RULES.md`](docs/05_SCANNER_RULES.md) | Scanner configuration and custom rule authoring |
| [`06_DATABASE_SCHEMA.md`](docs/06_DATABASE_SCHEMA.md) | SQL Server schema, migrations, and query patterns |

---

## 🗺️ Roadmap

| Phase | Timeline | Status |
|:------|:---------|:-------|
| C# / .NET Core | Weeks 1-8 | 🟢 Phase 1 |
| AI Fix Engine + LangGraph | Weeks 9-12 | 🟡 Phase 2 |
| PR Automation | Weeks 13-16 | ⚪ Phase 3 |
| Node.js / TypeScript | Weeks 17-20 | ⚪ Phase 4 |
| Python / Django + FastAPI | Weeks 21-24 | ⚪ Phase 5 |

---

## 📄 License

Private — All rights reserved.
