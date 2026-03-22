# Sealr

**Seal every crack in your code.**

Sealr is an AI-powered GitHub vulnerability scanner that automatically detects security issues, generates fixes, validates them in Docker sandboxes, and opens pull requests — all in a single pipeline.

## How It Works

```
Clone Repo → Scan (6 scanners) → AI Fix (GPT-5.4 / Claude) → Validate (Docker) → Open PR
```

1. **Scan** — Runs 6 parallel scanners (Semgrep, Gitleaks, ClamAV, YARA, dependency audit, config analysis) covering 15+ vulnerability categories
2. **Fix** — AI generates targeted fixes using GPT-5.4 Thinking (primary) with Claude Opus 4.6 fallback
3. **Validate** — Each fix is built and tested in an isolated Docker sandbox to ensure it doesn't break anything
4. **PR** — Verified fixes are committed to a branch and a pull request is created with rich diffs

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 16, React 19, TypeScript, Tailwind CSS v4, shadcn/ui |
| Backend | Python 3.12, FastAPI, SQLAlchemy, Celery |
| Database | SQL Server 2022 |
| AI Engine | LangGraph, GPT-5.4 Thinking, Claude Opus 4.6 |
| Scanners | Semgrep, Gitleaks, ClamAV, YARA |
| Infra | Docker Compose (SQL Server, Redis, MinIO) |
| Real-time | Socket.IO (WebSocket) |

## Vulnerability Categories

Dependencies, secrets, SAST (static analysis), malware, configuration, license compliance, cryptography, injection, XSS, deserialization, authentication, CSRF, path traversal, SSRF, and more.

## Quick Start

### Prerequisites

- Python 3.12+
- Node.js 20+
- Docker Desktop
- OpenAI API key
- GitHub Personal Access Token (`repo`, `read:org` scopes)

### Setup

```bash
# 1. Clone
git clone https://github.com/sureshpatta86/sealr.git
cd sealr

# 2. Configure environment
cp .env.example .env
# Edit .env with your API keys and tokens

# 3. Start infrastructure (SQL Server, Redis, MinIO)
make infra-up

# 4. Setup database
make db-setup

# 5. Install dependencies
make setup

# 6. Run all services
make dev
```

The app will be available at **http://localhost:3000**.

### Individual Services

```bash
make dev-backend   # FastAPI on :8000
make dev-frontend  # Next.js on :3000
make dev-worker    # Celery worker
```

## Project Structure

```
sealr/
├── frontend/              # Next.js 16 app
│   ├── app/               # App Router (pages & layouts)
│   ├── components/        # UI components (layout, dashboard, scan, vulnerability, fix)
│   ├── hooks/             # React Query & WebSocket hooks
│   ├── stores/            # Zustand state management
│   ├── types/             # TypeScript interfaces
│   └── lib/               # API client & utilities
├── backend/               # Python FastAPI
│   └── app/
│       ├── api/           # REST endpoints
│       ├── models/        # SQLAlchemy ORM models
│       ├── schemas/       # Pydantic schemas
│       ├── services/      # AI fix engine, GitHub integration
│       ├── scanners/      # Scanner plugins & rules
│       ├── workers/       # Celery task definitions
│       └── websocket/     # Socket.IO event handlers
├── docker/                # Docker Compose & Nginx config
├── docs/                  # Technical documentation
├── scripts/               # Database setup scripts
└── k8s/                   # Kubernetes manifests (optional)
```

## Configuration

Key environment variables (see `.env.example` for full list):

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key for GPT-5.4 |
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude (fallback) |
| `GITHUB_TOKEN` | GitHub PAT for repo access |
| `SQL_SERVER_HOST` | SQL Server connection host |
| `REDIS_URL` | Redis connection URL |
| `ENCRYPTION_KEY` | Key for encrypting stored tokens |

## Make Targets

```bash
make setup          # Install all dependencies
make infra-up       # Start Docker services
make infra-down     # Stop Docker services
make db-setup       # Initialize database schema
make dev            # Run all services
make test           # Run all tests
make lint           # Run linters (Ruff + ESLint)
make clean          # Remove containers & dependencies
```

## Documentation

Detailed docs are in the `docs/` directory:

- [Technical Specification](docs/01_TECH_SPEC.md)
- [Development Guide](docs/02_DEVELOPMENT_GUIDE.md)
- [Architecture](docs/03_ARCHITECTURE.md)
- [API Reference](docs/04_API_REFERENCE.md)
- [Scanner Rules](docs/05_SCANNER_RULES.md)
- [Database Schema](docs/06_DATABASE_SCHEMA.md)

## Language Support

All core scanners (dependencies, secrets, SAST, malware, config, license) are language-agnostic. SAST rules are available for the following languages with more being added:

| Language | SAST Rules | Dependency Scanning | AI Auto-Fix |
|----------|-----------|-------------------|-------------|
| C# / .NET Core | Yes | Yes | Yes |
| TypeScript / Node.js | Yes | Yes | Yes |
| Python | Yes | Yes | Yes |
| Java / Spring | Planned | Yes | Yes |
| Go | Planned | Yes | Yes |

## License

MIT
