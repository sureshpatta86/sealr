# 🏗️ Sealr — Architecture Document

> Deep dive into every architectural component, data flow, and design decision.

---

## 1. System Overview

Sealr is composed of **6 major subsystems** that work together:

```mermaid
graph TB
    subgraph User["👤 User Interface"]
        direction LR
        A1["Next.js 16<br/>Dashboard"]
    end

    subgraph Orchestration["🎯 Orchestration Layer"]
        direction LR
        B1["FastAPI<br/>REST + WebSocket"]
        B2["Celery<br/>Task Queue"]
    end

    subgraph Scanning["🔍 Scanning Engine"]
        direction LR
        C1["Dependency"]
        C2["Secrets"]
        C3["SAST"]
        C4["Malware"]
        C5["Config"]
        C6["License"]
    end

    subgraph Intelligence["🤖 AI Intelligence"]
        direction LR
        D1["LangGraph<br/>State Machine"]
        D2["GPT-5.4<br/>Thinking"]
        D3["Claude<br/>Opus 4.6"]
        D4["Fix<br/>Templates"]
    end

    subgraph Validation["✅ Validation"]
        direction LR
        E1["Docker<br/>Sandbox"]
    end

    subgraph Integration["🔗 Integration"]
        direction LR
        F1["GitHub<br/>API"]
    end

    User --> Orchestration
    Orchestration --> Scanning
    Scanning --> Intelligence
    Intelligence --> Validation
    Validation --> Integration

    style User fill:#1e3a5f,stroke:#2563eb,color:#e2e8f0
    style Orchestration fill:#1e3a5f,stroke:#0891b2,color:#e2e8f0
    style Scanning fill:#4c1d95,stroke:#7c3aed,color:#e2e8f0
    style Intelligence fill:#7f1d1d,stroke:#dc2626,color:#e2e8f0
    style Validation fill:#14532d,stroke:#22c55e,color:#e2e8f0
    style Integration fill:#422006,stroke:#f59e0b,color:#e2e8f0
```

---

## 2. Request Lifecycle

Every scan follows this exact path through the system:

```mermaid
flowchart TD
    A["🌐 User submits scan<br/>POST /api/scans"] --> B["FastAPI validates<br/>input + token"]
    B --> C["Create Scan record<br/>in SQL Server"]
    C --> D["Dispatch to<br/>Celery queue"]
    D --> E["Worker picks up job"]

    E --> F["Clone repo<br/>via GitHub API"]
    F --> G{"Language<br/>auto-detect?"}
    G -->|Yes| H["Scan for project files<br/>.csproj, package.json, etc."]
    G -->|No| I["Use selected language"]
    H --> I

    I --> J["Load applicable<br/>scanner plugins"]
    J --> K["Run 6 scanners<br/>in parallel"]

    K --> K1["Dependency<br/>Scanner"]
    K --> K2["Secrets<br/>Scanner"]
    K --> K3["SAST<br/>Scanner"]
    K --> K4["Malware<br/>Scanner"]
    K --> K5["Config<br/>Scanner"]
    K --> K6["License<br/>Scanner"]

    K1 & K2 & K3 & K4 & K5 & K6 --> L["Aggregate +<br/>deduplicate results"]
    L --> M["Save vulnerabilities<br/>to SQL Server"]
    M --> N["For each auto-fixable vuln"]

    N --> O["LangGraph<br/>Fix Engine"]
    O --> P["Template<br/>or AI fix"]
    P --> Q["Docker<br/>build validation"]
    Q --> R{"Build<br/>passes?"}
    R -->|Yes| S["Create<br/>GitHub PR"]
    R -->|No, retry| O
    R -->|No, exhausted| T["Flag for<br/>human review"]

    S --> U["Update DB +<br/>emit WebSocket events"]
    T --> U
    U --> V["✅ Scan complete"]

    style A fill:#059669,color:#fff
    style K fill:#7c3aed,color:#fff
    style O fill:#dc2626,color:#fff
    style Q fill:#0891b2,color:#fff
    style S fill:#059669,color:#fff
    style V fill:#059669,color:#fff
```

---

## 3. Scanner Architecture

### 3.1 Plugin Pattern

Each scanner implements the `BaseScanner` interface. The orchestrator loads applicable scanners based on the language/framework:

```mermaid
classDiagram
    class BaseScanner {
        <<abstract>>
        +repo_path: str
        +language: str
        +framework: str
        +scan()* list~VulnerabilityResult~
        +is_applicable()* bool
    }

    class DependencyScanner {
        +scan() list~VulnerabilityResult~
        +is_applicable() bool
        -_scan_dotnet()
        -_scan_npm()
        -_scan_pip()
        -_check_osv_api()
    }

    class SecretsScanner {
        +scan() list~VulnerabilityResult~
        +is_applicable() bool
        -_run_gitleaks()
    }

    class SASTScanner {
        +scan() list~VulnerabilityResult~
        +is_applicable() bool
        -_run_semgrep()
        -_load_rules()
    }

    class MalwareScanner {
        +scan() list~VulnerabilityResult~
        +is_applicable() bool
        -_run_clamav()
        -_run_yara()
    }

    class ConfigScanner {
        +scan() list~VulnerabilityResult~
        +is_applicable() bool
        -_scan_dotnet_config()
    }

    class LicenseScanner {
        +scan() list~VulnerabilityResult~
        +is_applicable() bool
    }

    BaseScanner <|-- DependencyScanner
    BaseScanner <|-- SecretsScanner
    BaseScanner <|-- SASTScanner
    BaseScanner <|-- MalwareScanner
    BaseScanner <|-- ConfigScanner
    BaseScanner <|-- LicenseScanner
```

### 3.2 Scanner Data Flow

```mermaid
graph LR
    subgraph Input["📂 Repository"]
        A1[".csproj files"]
        A2["Source code"]
        A3["Config files"]
        A4["Git history"]
        A5["Binary files"]
    end

    subgraph Tools["🔧 External Tools"]
        B1["dotnet CLI"]
        B2["Gitleaks"]
        B3["Semgrep"]
        B4["ClamAV"]
        B5["YARA"]
    end

    subgraph Output["📊 Results"]
        C1["VulnerabilityResult[]"]
    end

    A1 --> B1
    A2 --> B3
    A3 --> B3
    A4 --> B2
    A5 --> B4
    A5 --> B5
    B1 & B2 & B3 & B4 & B5 --> C1

    style Tools fill:#4c1d95,color:#e2e8f0
```

---

## 4. AI Fix Engine Architecture

### 4.1 LangGraph State Machine (Detailed)

```mermaid
stateDiagram-v2
    [*] --> CheckTemplates: vulnerability + file_content

    state CheckTemplates {
        [*] --> MatchTemplate
        MatchTemplate --> TemplateFound: Pattern matches
        MatchTemplate --> NoTemplate: No match
    }

    CheckTemplates --> ApplyBuild: TemplateFound
    CheckTemplates --> CallGPT: NoTemplate

    state CallGPT {
        [*] --> BuildPrompt
        BuildPrompt --> SendToGPT54
        SendToGPT54 --> ParseResponse
        ParseResponse --> ExtractDiff
    }

    CallGPT --> ApplyBuild: diff_content != null
    CallGPT --> CallClaude: exception or empty

    state CallClaude {
        [*] --> ReusePrompt
        ReusePrompt --> SendToClaude
        SendToClaude --> ParseClaudeResponse
    }

    CallClaude --> ApplyBuild: diff_content != null
    CallClaude --> FlagReview: both failed

    state ApplyBuild {
        [*] --> GitApply
        GitApply --> DotnetBuild
        DotnetBuild --> DotnetTest
        DotnetTest --> CheckResult
    }

    ApplyBuild --> CreatePR: build_passed == true
    ApplyBuild --> RetryDecision: build_passed == false

    state RetryDecision {
        [*] --> CheckCount
        CheckCount --> CanRetry: retry_count < 3
        CheckCount --> Exhausted: retry_count >= 3
    }

    RetryDecision --> CallGPT: CanRetry (with error context)
    RetryDecision --> FlagReview: Exhausted

    CreatePR --> [*]
    FlagReview --> [*]
```

### 4.2 Prompt Engineering Strategy

```mermaid
graph TD
    subgraph PromptLayers["Prompt Construction"]
        S["System Prompt<br/>Security expert persona<br/>+ output format rules"]
        V["Vulnerability Context<br/>Category, severity, CWE,<br/>file path, line numbers"]
        F["File Content<br/>Full affected file<br/>+ surrounding files"]
        P["Project Context<br/>Framework version,<br/>dependencies, has tests"]
        E["Error Context<br/>(retry only)<br/>Previous build error"]
    end

    S --> PROMPT["Final Prompt"]
    V --> PROMPT
    F --> PROMPT
    P --> PROMPT
    E -.->|retry only| PROMPT

    PROMPT --> LLM["GPT-5.4 / Claude"]
    LLM --> OUT["Structured Output"]

    subgraph ParsedOutput["Parsed Output"]
        D["Unified Diff<br/>(git apply compatible)"]
        EX["Explanation<br/>(what changed & why)"]
        CS["Confidence Score<br/>(0.0 - 1.0)"]
    end

    OUT --> D & EX & CS

    style S fill:#7c3aed,color:#fff
    style LLM fill:#dc2626,color:#fff
```

### 4.3 Cost Optimization Flow

```mermaid
pie title Fix Generation Cost Distribution (Projected)
    "Fix Templates (free)" : 40
    "GPT-5.4 Thinking" : 45
    "Claude Opus 4.6 (fallback)" : 10
    "Manual Review (no AI)" : 5
```

---

## 5. Data Flow Diagrams

### 5.1 Scan Data Flow

```mermaid
flowchart LR
    subgraph Input
        U["User Input<br/>URL + Token + Language"]
    end

    subgraph Processing
        V["Validate"]
        CL["Clone"]
        SC["Scan"]
        AG["Aggregate"]
    end

    subgraph AI
        FX["Fix Engine"]
        BV["Build Validate"]
    end

    subgraph Output
        PR["GitHub PR"]
        DB["SQL Server"]
        WS["WebSocket Events"]
    end

    U --> V --> CL --> SC --> AG --> FX --> BV --> PR
    V --> DB
    SC --> DB
    AG --> DB
    FX --> DB
    BV --> DB
    SC --> WS
    FX --> WS
    BV --> WS

    style Input fill:#059669,color:#fff
    style AI fill:#7c3aed,color:#fff
    style Output fill:#0891b2,color:#fff
```

### 5.2 Real-Time Event Flow

```mermaid
sequenceDiagram
    participant C as Celery Worker
    participant S as Socket.IO Server
    participant F as Frontend

    F->>S: join_scan(scan_id)

    C->>S: emit("scan.started")
    S->>F: scan.started

    loop For each scanner
        C->>S: emit("scan.progress", {scanner, %})
        S->>F: scan.progress
    end

    loop For each vulnerability found
        C->>S: emit("scan.vulnerability.found", {vuln})
        S->>F: scan.vulnerability.found
        Note over F: UI adds row to table
    end

    loop For each fix
        C->>S: emit("scan.fix.generated", {fix})
        S->>F: scan.fix.generated
        C->>S: emit("scan.fix.validated", {fix, passed})
        S->>F: scan.fix.validated
    end

    C->>S: emit("scan.completed", {summary})
    S->>F: scan.completed
    Note over F: UI shows final results
```

---

## 6. Security Architecture

```mermaid
graph TB
    subgraph UserLayer["User Layer"]
        TOKEN["GitHub PAT<br/>(user provides)"]
    end

    subgraph TransitSecurity["In Transit"]
        TLS["TLS 1.3<br/>(HTTPS + WSS)"]
    end

    subgraph AppSecurity["Application Layer"]
        ENC["AES-256-GCM<br/>Token Encryption"]
        RL["Rate Limiting<br/>per user/IP"]
        VAL["Input Validation<br/>Pydantic + Zod"]
        AUDIT["Audit Logging"]
    end

    subgraph DataSecurity["Data Layer"]
        DBENC["SQL Server TDE<br/>(Transparent Data Encryption)"]
        EPHEMERAL["Ephemeral Repo Storage<br/>(destroyed after scan)"]
        NOCODE["No Source Code<br/>Persistence<br/>(only diffs + metadata)"]
    end

    subgraph SandboxSecurity["Sandbox Security"]
        NONET["No Network Access"]
        MEMLIM["2GB Memory Limit"]
        CPULIM["2 CPU Core Limit"]
        TIMEOUT["5 Min Timeout"]
        NOPRIVILEGED["No Privileged Mode"]
    end

    TOKEN --> TLS --> ENC
    ENC --> DBENC
    TLS --> RL --> VAL
    VAL --> AUDIT

    style TransitSecurity fill:#059669,color:#fff
    style AppSecurity fill:#0891b2,color:#fff
    style SandboxSecurity fill:#dc2626,color:#fff
```

---

## 7. Deployment Architecture

### 7.1 Local Development

```mermaid
graph TB
    subgraph Dev["Local Machine"]
        FE["Next.js :3000"]
        BE["FastAPI :8000"]
        WK["Celery Worker"]
    end

    subgraph Docker["Docker Containers"]
        SQL["SQL Server :1433"]
        RED["Redis :6379"]
        MIN["MinIO :9000"]
    end

    FE --> BE
    BE --> SQL & RED
    WK --> SQL & RED
    BE -.-> WK

    style Dev fill:#1e3a5f,color:#e2e8f0
    style Docker fill:#14532d,color:#e2e8f0
```

### 7.2 Production (AWS Example)

```mermaid
graph TB
    subgraph Internet
        USER["Users"]
    end

    subgraph AWS["AWS Cloud"]
        subgraph Edge
            CF["CloudFront CDN"]
        end

        subgraph Compute
            ECS1["ECS Fargate<br/>FastAPI (x3)"]
            ECS2["ECS Fargate<br/>Celery Workers (x5)"]
        end

        subgraph Data
            RDS["RDS SQL Server<br/>Multi-AZ"]
            EC["ElastiCache<br/>Redis"]
            S3["S3 Bucket<br/>Scan Artifacts"]
        end

        subgraph Monitoring
            CW["CloudWatch"]
            SENTRY["Sentry"]
        end
    end

    USER --> CF --> ECS1
    ECS1 --> RDS & EC
    ECS2 --> RDS & EC & S3
    ECS1 & ECS2 --> CW & SENTRY

    style Edge fill:#f59e0b,color:#000
    style Compute fill:#0891b2,color:#fff
    style Data fill:#059669,color:#fff
    style Monitoring fill:#7c3aed,color:#fff
```

---

## 8. Technology Decision Log

| # | Decision | Options Considered | Chosen | Why |
|:--|:---------|:-------------------|:-------|:----|
| 1 | Frontend framework | React+Vite, Next.js 16, Remix | **Next.js 16** | SSR, RSC, Turbopack, App Router |
| 2 | Backend framework | Django, Flask, FastAPI | **FastAPI** | Async-first, auto OpenAPI docs, Pydantic |
| 3 | Database | PostgreSQL, SQL Server, MySQL | **SQL Server** | Project requirement, enterprise features |
| 4 | AI orchestration | Raw SDK, LangChain, LangGraph | **LangGraph** | State machine for retry loops, checkpointing |
| 5 | Primary LLM | GPT-5.4, Claude Opus, Gemini | **GPT-5.4 Thinking** | Best code generation benchmarks (Mar 2026) |
| 6 | Task queue | Celery, Dramatiq, Huey | **Celery** | Most mature Python task queue, Redis broker |
| 7 | SAST engine | Semgrep, CodeQL, SonarQube | **Semgrep** | Free, fast, custom rule authoring |
| 8 | Secrets scanner | Gitleaks, TruffleHog, detect-secrets | **Gitleaks** | Fast, comprehensive, JSON output |
| 9 | Malware scanner | ClamAV, VirusTotal | **ClamAV + YARA** | Self-hosted, no API limits, custom rules |
| 10 | Container runtime | Docker, Podman | **Docker** | Widest support, Docker-in-Docker for builds |

---

*Sealr Architecture Document — March 2026*
