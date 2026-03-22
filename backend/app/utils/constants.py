from enum import StrEnum


class ScanStatus(StrEnum):
    QUEUED = "queued"
    CLONING = "cloning"
    SCANNING = "scanning"
    FIXING = "fixing"
    VALIDATING = "validating"
    CREATING_PRS = "creating_prs"
    COMPLETED = "completed"
    FAILED = "failed"


class VulnerabilityStatus(StrEnum):
    OPEN = "open"
    FIX_GENERATED = "fix_generated"
    FIX_VALIDATED = "fix_validated"
    PR_CREATED = "pr_created"
    PR_MERGED = "pr_merged"
    DISMISSED = "dismissed"


class FixStatus(StrEnum):
    GENERATING = "generating"
    GENERATED = "generated"
    BUILD_PASSED = "build_passed"
    BUILD_FAILED = "build_failed"
    PR_CREATED = "pr_created"
    PR_MERGED = "pr_merged"
    FAILED = "failed"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class VulnerabilityCategory(StrEnum):
    DEPENDENCY = "dependency"
    SECRET = "secret"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    DESERIALIZATION = "deserialization"
    CRYPTO = "crypto"
    CSRF = "csrf"
    AUTH_MISCONFIG = "auth_misconfig"
    PATH_TRAVERSAL = "path_traversal"
    MALWARE = "malware"
    LICENSE = "license"
    CONFIG_MISCONFIG = "config_misconfig"
    SECURITY_HEADER = "security_header"
    LOGGING_SENSITIVE = "logging_sensitive"
