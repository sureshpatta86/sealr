-- Sealr Initial Schema
-- Target: SQL Server 2022
-- Run against: sealr database

-- ======== USERS ========
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Users')
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

-- ======== REPOSITORIES ========
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Repositories')
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

-- ======== SCANS ========
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Scans')
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

-- ======== VULNERABILITIES ========
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Vulnerabilities')
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

-- ======== FIXES ========
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Fixes')
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

-- ======== SCAN EVENTS ========
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'ScanEvents')
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

-- ======== SUPPORTED LANGUAGES ========
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'SupportedLanguages')
BEGIN
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
    INSERT INTO SupportedLanguages (Language, Framework, DisplayName, ProjectFilePattern, BuildCommand, TestCommand, PackageManager, DockerImage, IsEnabled, SortOrder) VALUES
        ('csharp', '.NET Core', 'C# / .NET Core', '*.csproj;*.sln', 'dotnet build --no-restore', 'dotnet test --no-build', 'nuget', 'mcr.microsoft.com/dotnet/sdk:8.0', 1, 1),
        ('csharp', '.NET Framework', 'C# / .NET Framework', '*.csproj;*.sln', 'msbuild /restore', 'dotnet test', 'nuget', 'mcr.microsoft.com/dotnet/framework/sdk:4.8', 0, 2),
        ('typescript', 'Next.js', 'TypeScript / Next.js', 'package.json;next.config.*', 'npm run build', 'npm test', 'npm', 'node:20-alpine', 0, 3),
        ('typescript', 'Express', 'TypeScript / Express', 'package.json;tsconfig.json', 'npm run build', 'npm test', 'npm', 'node:20-alpine', 0, 4),
        ('javascript', 'Node.js', 'JavaScript / Node.js', 'package.json', 'npm run build', 'npm test', 'npm', 'node:20-alpine', 0, 5),
        ('python', 'Django', 'Python / Django', 'manage.py;requirements.txt', 'python -m py_compile', 'python manage.py test', 'pip', 'python:3.12-slim', 0, 6),
        ('python', 'FastAPI', 'Python / FastAPI', 'requirements.txt;pyproject.toml', 'python -m py_compile', 'pytest', 'pip', 'python:3.12-slim', 0, 7),
        ('java', 'Spring Boot', 'Java / Spring Boot', 'pom.xml;build.gradle', 'mvn compile', 'mvn test', 'maven', 'maven:3.9-eclipse-temurin-21', 0, 8),
        ('go', 'Go Standard', 'Go', 'go.mod', 'go build ./...', 'go test ./...', 'go modules', 'golang:1.22-alpine', 0, 9);
END;

-- ======== SCAN CONFIGS ========
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'ScanConfigs')
CREATE TABLE ScanConfigs (
    Id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    UserId UNIQUEIDENTIFIER NOT NULL REFERENCES Users(Id),
    RepositoryId UNIQUEIDENTIFIER NULL REFERENCES Repositories(Id),
    EnabledScanners NVARCHAR(MAX) NOT NULL DEFAULT '["dependency","secrets","sast","malware","config","license"]',
    AutoCreatePR BIT NOT NULL DEFAULT 1,
    ScheduleCron NVARCHAR(100) NULL,
    ExcludedPaths NVARCHAR(MAX) NULL,
    SeverityThreshold NVARCHAR(20) NOT NULL DEFAULT 'low',
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);

PRINT 'Sealr schema created successfully!';
GO
