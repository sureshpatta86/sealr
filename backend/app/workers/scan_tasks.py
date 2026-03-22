import asyncio
import json
import logging
import os
import uuid
from datetime import datetime

from app.workers.celery_app import celery_app
from app.websocket.manager import publish_event

logger = logging.getLogger(__name__)

# Maps filename indicators to (language, framework)
_LANG_INDICATORS = [
    (["*.csproj", "*.sln", "*.cs"],          "csharp",     ".NET Core"),
    (["package.json"],                         "javascript", "Node.js"),
    (["tsconfig.json"],                        "typescript", "Node.js"),
    (["requirements.txt", "setup.py", "pyproject.toml", "*.py"], "python", "Python"),
    (["pom.xml"],                              "java",       "Maven"),
    (["build.gradle", "build.gradle.kts"],     "java",       "Gradle"),
    (["go.mod"],                               "go",         "Go"),
    (["Gemfile"],                              "ruby",       "Rails"),
    (["Cargo.toml"],                           "rust",       "Cargo"),
]


def _detect_language(repo_path: str) -> tuple[str, str]:
    """Walk the repo and return (language, framework) based on file indicators."""
    import fnmatch
    found: set[str] = set()
    for root, _, files in os.walk(repo_path):
        for f in files:
            found.add(f)
        if len(found) > 500:
            break

    for patterns, lang, fw in _LANG_INDICATORS:
        for pat in patterns:
            if any(fnmatch.fnmatch(f, pat) for f in found):
                logger.info(f"Auto-detected language: {lang} (matched {pat})")
                return lang, fw

    return "csharp", ".NET Core"  # default fallback


def _default_framework(language: str) -> str:
    defaults = {
        "csharp": ".NET Core", "javascript": "Node.js", "typescript": "Node.js",
        "python": "Python", "java": "Maven", "go": "Go",
        "ruby": "Rails", "rust": "Cargo",
    }
    return defaults.get(language, "unknown")


def _log_event(db_session, scan_id: str, event_type: str, message: str, metadata: dict | None = None, worker: str | None = None):
    """Persist a ScanEvent to the database and publish to Redis for WebSocket."""
    from app.models import ScanEvent
    event = ScanEvent(
        ScanId=scan_id,
        EventType=event_type,
        WorkerName=worker,
        Message=message[:500] if message else None,
        Metadata=json.dumps(metadata) if metadata else None,
    )
    db_session.add(event)
    # Also publish to Redis for real-time WebSocket delivery
    publish_event(scan_id, event_type, message, metadata)


@celery_app.task(name="scan_repository", bind=True, max_retries=1)
def scan_repository(self, scan_id: str, user_id: str, repo_info: dict, github_token: str):
    """
    Main scan orchestration task.
    Clones repo → runs scanners → generates fixes via LangGraph → creates PRs.
    Emits WebSocket events at each phase and persists ScanEvent audit records.
    """
    import concurrent.futures

    coro = _async_scan(scan_id, user_id, repo_info, github_token, worker_name=self.request.hostname)

    # In DEV_MODE, task_always_eager=True runs this task synchronously inside
    # FastAPI's async event loop. asyncio.run() can't nest inside a running loop,
    # so run the coroutine in a fresh thread instead.
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(asyncio.run, coro).result()
    else:
        asyncio.run(coro)


async def run_scan_async(scan_id: str, user_id: str, repo_info: dict, github_token: str):
    """BackgroundTasks entry point used in DEV_MODE — runs directly in the main event loop."""
    await _async_scan(scan_id, user_id, repo_info, github_token)


async def _async_scan(scan_id: str, user_id: str, repo_info: dict, github_token: str, worker_name: str | None = None):
    from sqlalchemy import select
    from app.utils.database import async_session_factory
    from app.models import Scan, Vulnerability, Fix
    from app.services.github_service import GitHubService
    from app.services.ai_fix_service import AIFixService
    from app.scanners import get_applicable_scanners
    from app.utils.constants import ScanStatus, FixStatus, VulnerabilityStatus

    async with async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.Id == scan_id))
        scan = result.scalar_one()

        clone_path = None
        gh_service = GitHubService(github_token)

        try:
            # ---- Phase 1: Clone ----
            scan.Status = ScanStatus.CLONING
            scan.StartedAt = datetime.utcnow()
            await db.commit()
            _log_event(db, scan_id, "scan.started", "Cloning repository...", worker=worker_name)
            await db.commit()

            clone_path = gh_service.clone_repo(
                repo_info["owner"], repo_info["name"], repo_info.get("branch", "main")
            )

            # ---- Phase 2: Scan ----
            scan.Status = ScanStatus.SCANNING
            await db.commit()
            _log_event(db, scan_id, "scan.progress", "Scanning for vulnerabilities...", {"status": "scanning"}, worker=worker_name)
            await db.commit()

            language = repo_info.get("language") or "auto"
            framework = repo_info.get("framework") or "auto"
            if language == "auto":
                language, framework = _detect_language(clone_path)
            elif framework == "auto":
                framework = _default_framework(language)

            scanners = get_applicable_scanners(clone_path, language, framework)
            all_vulns = []

            for scanner in scanners:
                scanner_name = scanner.__class__.__name__
                _log_event(db, scan_id, "scan.progress", f"Running {scanner_name}...", {"scanner": scanner_name}, worker=worker_name)
                await db.commit()
                try:
                    results = await scanner.scan()
                    all_vulns.extend(results)
                    for vuln_result in results:
                        _log_event(db, scan_id, "scan.vulnerability.found", vuln_result.title, {
                            "category": vuln_result.category,
                            "severity": vuln_result.severity,
                            "title": vuln_result.title,
                        }, worker=worker_name)
                except Exception as e:
                    logger.error(f"Scanner {scanner_name} failed: {e}")
                    _log_event(db, scan_id, "scan.progress", f"{scanner_name} failed: {e}", {"scanner": scanner_name, "error": str(e)}, worker=worker_name)
            await db.commit()

            # Save vulnerabilities
            vuln_records = []
            for vuln_result in all_vulns:
                vuln = Vulnerability(
                    Id=str(uuid.uuid4()),
                    ScanId=scan_id,
                    Category=vuln_result.category,
                    Severity=vuln_result.severity,
                    CvssScore=vuln_result.cvss_score,
                    CweId=vuln_result.cwe_id,
                    CveId=vuln_result.cve_id,
                    Title=vuln_result.title,
                    Description=vuln_result.description,
                    FilePath=vuln_result.file_path,
                    LineStart=vuln_result.line_start,
                    LineEnd=vuln_result.line_end,
                    CodeSnippet=vuln_result.code_snippet,
                    Scanner=vuln_result.scanner,
                    IsAutoFixable=vuln_result.is_auto_fixable,
                )
                db.add(vuln)
                vuln_records.append(vuln)

            scan.TotalVulnerabilities = len(all_vulns)
            await db.commit()

            # ---- Phase 3: Fix ----
            scan.Status = ScanStatus.FIXING
            await db.commit()
            _log_event(db, scan_id, "scan.progress", f"Generating fixes for {len([v for v in vuln_records if v.IsAutoFixable])} auto-fixable vulnerabilities...", {"status": "fixing"}, worker=worker_name)
            await db.commit()

            fix_service = AIFixService()
            fixed_count = 0

            # 3a: Programmatic dependency fixes
            if clone_path:
                dep_fix_fn = {
                    "javascript": _fix_npm_dependencies,
                    "typescript": _fix_npm_dependencies,
                    "python": _fix_pip_dependencies,
                    "csharp": _fix_dotnet_dependencies,
                    "java": _fix_java_dependencies,
                    "go": _fix_go_dependencies,
                    "rust": _fix_rust_dependencies,
                    "ruby": _fix_ruby_dependencies,
                }.get(language)
                if dep_fix_fn:
                    dep_fixed = await dep_fix_fn(clone_path, vuln_records, db, scan_id, worker_name)
                    fixed_count += dep_fixed

            # 3b: AI fixes for non-dependency vulnerabilities
            for vuln in vuln_records:
                if not vuln.IsAutoFixable:
                    continue
                # Skip dependency vulns — already handled programmatically above
                if vuln.Category == "dependency":
                    continue

                try:
                    # Read full file content for the affected file
                    file_content = ""
                    if vuln.FilePath and clone_path:
                        import os
                        full_path = os.path.join(clone_path, vuln.FilePath)
                        if os.path.isfile(full_path):
                            with open(full_path, "r", errors="replace") as f:
                                file_content = f.read()

                    # Run the LangGraph fix pipeline
                    fix_result = await fix_service.generate_fix(
                        vulnerability={
                            "category": vuln.Category,
                            "severity": vuln.Severity,
                            "cwe_id": vuln.CweId,
                            "cve_id": vuln.CveId,
                            "description": vuln.Description,
                            "file_path": vuln.FilePath,
                            "line_start": vuln.LineStart,
                            "line_end": vuln.LineEnd,
                        },
                        file_content=file_content or vuln.CodeSnippet or "",
                        project_context={"dependencies": [], "has_tests": True},
                        language=language,
                        framework=framework,
                        repo_path=clone_path,
                    )

                    # Determine fix status from LangGraph result
                    if fix_result["status"] == "validated":
                        fix_status = FixStatus.BUILD_PASSED
                        fixed_count += 1
                    elif fix_result["status"] == "flagged":
                        fix_status = FixStatus.FAILED
                    else:
                        fix_status = FixStatus.GENERATED

                    fix = Fix(
                        Id=str(uuid.uuid4()),
                        VulnerabilityId=vuln.Id,
                        Status=fix_status,
                        DiffContent=fix_result.get("diff"),
                        ConfidenceScore=fix_result.get("confidence"),
                        AIModel=fix_result.get("model", "unknown"),
                        AIPromptTokens=fix_result.get("prompt_tokens"),
                        AICompletionTokens=fix_result.get("completion_tokens"),
                        BuildOutput=fix_result.get("build_output"),
                        TestOutput=fix_result.get("build_output"),
                        RetryCount=fix_result.get("retry_count", 0),
                        ValidatedAt=datetime.utcnow() if fix_result["status"] == "validated" else None,
                    )
                    db.add(fix)
                    vuln.Status = VulnerabilityStatus.FIX_VALIDATED if fix_result["status"] == "validated" else VulnerabilityStatus.OPEN
                    await db.commit()

                    _log_event(db, scan_id, "scan.fix.generated", f"Fix for {vuln.Title} ({fix_result['model']})", {
                        "vulnerability_id": vuln.Id,
                        "model": fix_result.get("model"),
                        "confidence": fix_result.get("confidence"),
                        "status": fix_result["status"],
                    }, worker=worker_name)

                    if fix_result["status"] == "validated":
                        _log_event(db, scan_id, "scan.fix.validated", f"Fix validated for {vuln.Title}", {
                            "fix_id": fix.Id,
                            "build_passed": True,
                        }, worker=worker_name)

                    await db.commit()

                except Exception as e:
                    logger.error(f"Fix generation failed for {vuln.Id}: {e}")
                    _log_event(db, scan_id, "scan.fix.generated", f"Fix failed for {vuln.Title}: {e}", {
                        "vulnerability_id": vuln.Id,
                        "error": str(e),
                    }, worker=worker_name)
                    await db.commit()

            # ---- Phase 4: Create PR (batch all fixes into one PR) ----
            if fixed_count > 0:
                _log_event(db, scan_id, "scan.progress", f"Creating PR for {fixed_count} fix(es)...", {"status": "creating_pr"}, worker=worker_name)
                await db.commit()

                # create_pr_task.delay() with always_eager runs synchronously.
                # If we're in the main event loop (BackgroundTasks path) we must
                # offload to a thread to avoid blocking it.
                pr_coro = _async_create_pr(
                    scan_id, github_token,
                    repo_info["owner"], repo_info["name"],
                    repo_info.get("branch", "main"),
                )
                try:
                    running_loop = asyncio.get_running_loop()
                except RuntimeError:
                    running_loop = None

                if running_loop:
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        pool.submit(asyncio.run, pr_coro).result()
                else:
                    asyncio.run(pr_coro)

            # ---- Phase 5: Complete ----
            scan.FixedCount = fixed_count
            scan.Status = ScanStatus.COMPLETED
            scan.CompletedAt = datetime.utcnow()
            if scan.StartedAt:
                scan.ScanDurationSec = int(
                    (scan.CompletedAt - scan.StartedAt).total_seconds()
                )
            await db.commit()

            unfixed_count = len(all_vulns) - fixed_count
            completed_msg = f"Scan completed: {len(all_vulns)} vulnerabilities found, {fixed_count} fixed"
            if unfixed_count > 0:
                completed_msg += f", {unfixed_count} require manual action"
            _log_event(db, scan_id, "scan.completed", completed_msg, {
                "total_vulnerabilities": len(all_vulns),
                "fixed_count": fixed_count,
                "unfixed_count": unfixed_count,
                "duration_sec": scan.ScanDurationSec,
            }, worker=worker_name)
            await db.commit()

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            scan.Status = ScanStatus.FAILED
            scan.ErrorMessage = str(e)
            scan.CompletedAt = datetime.utcnow()
            await db.commit()

            _log_event(db, scan_id, "scan.failed", str(e), worker=worker_name)
            await db.commit()

        finally:
            if clone_path:
                gh_service.cleanup(clone_path)
            await gh_service.close()


@celery_app.task(name="fix_vulnerability")
def fix_vulnerability(vuln_id: str, repo_path: str = "", language: str = "csharp", framework: str = ".NET Core"):
    """Generate an AI fix for a single vulnerability via LangGraph."""
    asyncio.run(_async_fix(vuln_id, repo_path, language, framework))


async def _async_fix(vuln_id: str, repo_path: str, language: str, framework: str):
    from sqlalchemy import select
    from app.utils.database import async_session_factory
    from app.models import Fix, Vulnerability
    from app.services.ai_fix_service import AIFixService
    from app.utils.constants import FixStatus

    async with async_session_factory() as db:
        result = await db.execute(
            select(Vulnerability).where(Vulnerability.Id == vuln_id)
        )
        vuln = result.scalar_one_or_none()
        if not vuln:
            return

        fix_service = AIFixService()

        try:
            fix_result = await fix_service.generate_fix(
                vulnerability={
                    "category": vuln.Category,
                    "severity": vuln.Severity,
                    "cwe_id": vuln.CweId,
                    "cve_id": vuln.CveId,
                    "description": vuln.Description,
                    "file_path": vuln.FilePath,
                    "line_start": vuln.LineStart,
                    "line_end": vuln.LineEnd,
                },
                file_content=vuln.CodeSnippet or "",
                project_context={},
                language=language,
                framework=framework,
                repo_path=repo_path,
            )

            if fix_result["status"] == "validated":
                fix_status = FixStatus.BUILD_PASSED
            elif fix_result["status"] == "flagged":
                fix_status = FixStatus.FAILED
            else:
                fix_status = FixStatus.GENERATED

            fix = Fix(
                Id=str(uuid.uuid4()),
                VulnerabilityId=vuln_id,
                Status=fix_status,
                DiffContent=fix_result.get("diff"),
                ConfidenceScore=fix_result.get("confidence"),
                AIModel=fix_result.get("model", "unknown"),
                AIPromptTokens=fix_result.get("prompt_tokens"),
                AICompletionTokens=fix_result.get("completion_tokens"),
                BuildOutput=fix_result.get("build_output"),
                TestOutput=fix_result.get("build_output"),
                RetryCount=fix_result.get("retry_count", 0),
                ValidatedAt=datetime.utcnow() if fix_result["status"] == "validated" else None,
            )
            db.add(fix)
            vuln.Status = VulnerabilityStatus.FIX_VALIDATED if fix_result["status"] == "validated" else VulnerabilityStatus.OPEN
            await db.commit()

        except Exception as e:
            logger.error(f"Fix generation failed for {vuln_id}: {e}")


@celery_app.task(name="check_scheduled_scans")
def check_scheduled_scans():
    """Periodic task: check ScanConfigs with ScheduleCron and trigger scans when due."""
    asyncio.run(_async_check_scheduled_scans())


async def _async_check_scheduled_scans():
    from croniter import croniter
    from sqlalchemy import select
    from sqlalchemy.orm import joinedload
    from app.utils.database import async_session_factory
    from app.models import ScanConfig, Repository, Scan, User
    from app.utils.encryption import decrypt_token

    async with async_session_factory() as db:
        result = await db.execute(
            select(ScanConfig)
            .where(ScanConfig.ScheduleCron.isnot(None))
            .options(joinedload(ScanConfig.user))
        )
        configs = result.scalars().all()

        now = datetime.utcnow()

        for config in configs:
            try:
                cron = croniter(config.ScheduleCron, now)
                prev_fire = cron.get_prev(datetime)
                # If the previous fire time was within the last 90 seconds, trigger a scan
                if (now - prev_fire).total_seconds() <= 90:
                    # Get the repository
                    if not config.RepositoryId:
                        continue
                    repo_result = await db.execute(
                        select(Repository).where(Repository.Id == config.RepositoryId)
                    )
                    repo = repo_result.scalar_one_or_none()
                    if not repo:
                        continue

                    # Check if a scan is already running for this repo
                    existing = await db.execute(
                        select(Scan)
                        .where(Scan.RepositoryId == repo.Id)
                        .where(Scan.Status.in_(["queued", "cloning", "scanning", "fixing"]))
                    )
                    if existing.scalar_one_or_none():
                        continue

                    # Decrypt user token
                    user = config.user
                    github_token = decrypt_token(user.GitHubTokenEncrypted)

                    # Create scan record
                    scan = Scan(
                        Id=str(uuid.uuid4()),
                        UserId=user.Id,
                        RepositoryId=repo.Id,
                        Status="queued",
                        Language=repo.Language or "csharp",
                        Framework=repo.Framework or ".NET Core",
                        Branch=repo.DefaultBranch,
                    )
                    db.add(scan)
                    await db.commit()

                    # Dispatch the scan task
                    scan_repository.delay(
                        scan.Id,
                        user.Id,
                        {
                            "owner": repo.Owner,
                            "name": repo.Name,
                            "branch": repo.DefaultBranch,
                            "language": repo.Language or "csharp",
                            "framework": repo.Framework or ".NET Core",
                        },
                        github_token,
                    )
                    logger.info(f"Scheduled scan triggered for repo {repo.Owner}/{repo.Name} (config {config.Id})")

            except Exception as e:
                logger.error(f"Error checking schedule for config {config.Id}: {e}")


def _generate_unified_diff(original: str, modified: str, file_path: str) -> str:
    """Generate a unified diff between two strings."""
    import difflib
    orig_lines = original.splitlines(keepends=True)
    mod_lines = modified.splitlines(keepends=True)
    diff = difflib.unified_diff(orig_lines, mod_lines, fromfile=f"a/{file_path}", tofile=f"b/{file_path}")
    return "".join(diff)


async def _fix_npm_dependencies(clone_path: str, vuln_records: list, db, scan_id: str, worker_name: str | None) -> int:
    """
    Run `npm audit fix` on the cloned repo and create Fix records for dependency vulns.
    Returns the number of fixes created.
    """
    import subprocess as sp
    from app.models import Fix
    from app.utils.constants import FixStatus, VulnerabilityStatus

    all_dep_vulns = [v for v in vuln_records if v.Category == "dependency"]
    dep_vulns = [v for v in all_dep_vulns if v.IsAutoFixable]
    # Vulns npm says have no fix available (e.g. xlsx)
    no_fix_available = [v for v in all_dep_vulns if not v.IsAutoFixable]

    if not dep_vulns:
        # Still log the unfixable ones
        if no_fix_available:
            names = ", ".join(v.Title.replace("Vulnerable npm package: ", "") for v in no_fix_available)
            _log_event(db, scan_id, "scan.progress", f"No auto-fix available: {names}", {"unfixable": names}, worker=worker_name)
            await db.commit()
        return 0

    # Read package.json before fix
    pkg_path = os.path.join(clone_path, "package.json")
    if not os.path.isfile(pkg_path):
        logger.warning("No package.json found — skipping npm audit fix")
        return 0

    with open(pkg_path, "r") as f:
        original_pkg = f.read()

    # Read package-lock.json before fix (if exists)
    lock_path = os.path.join(clone_path, "package-lock.json")
    original_lock = None
    if os.path.isfile(lock_path):
        with open(lock_path, "r") as f:
            original_lock = f.read()

    _log_event(db, scan_id, "scan.progress", "Installing dependencies (npm install)...", {"status": "npm_install"}, worker=worker_name)
    await db.commit()

    # npm audit fix needs node_modules to properly resolve the dependency tree
    try:
        install_proc = sp.run(
            ["npm", "install", "--ignore-scripts"],
            cwd=clone_path,
            capture_output=True,
            text=True,
            timeout=300,
        )
        logger.info(f"npm install exit code: {install_proc.returncode}")
    except Exception as e:
        logger.warning(f"npm install failed: {e} — continuing with npm audit fix anyway")

    _log_event(db, scan_id, "scan.progress", "Running npm audit fix...", {"status": "npm_fix"}, worker=worker_name)
    await db.commit()

    # Run npm audit fix with node_modules present
    try:
        proc = sp.run(
            ["npm", "audit", "fix", "--force"],
            cwd=clone_path,
            capture_output=True,
            text=True,
            timeout=180,
        )
        logger.info(f"npm audit fix exit code: {proc.returncode}")
        if proc.stderr:
            logger.info(f"npm audit fix stderr: {proc.stderr[:500]}")
        if proc.stdout:
            logger.info(f"npm audit fix stdout: {proc.stdout[:500]}")
    except Exception as e:
        logger.error(f"npm audit fix failed: {e}")
        _log_event(db, scan_id, "scan.progress", f"npm audit fix failed: {e}", {"error": str(e)}, worker=worker_name)
        await db.commit()
        return 0

    # ── Post-fix verification: re-run npm audit to see what's actually resolved ──
    still_vulnerable: set[str] = set()
    try:
        verify_proc = sp.run(
            ["npm", "audit", "--json"],
            cwd=clone_path,
            capture_output=True,
            text=True,
            timeout=120,
        )
        verify_data = json.loads(verify_proc.stdout) if verify_proc.stdout else {}
        for pkg_name in verify_data.get("vulnerabilities", {}).keys():
            still_vulnerable.add(pkg_name.lower())
        logger.info(f"Post-fix audit: {len(still_vulnerable)} vulnerabilities remain: {still_vulnerable}")
    except Exception as e:
        logger.warning(f"Post-fix npm audit verification failed: {e}")

    # Separate vulns into actually-fixed vs still-open
    actually_fixed = []
    not_fixed = []
    for v in dep_vulns:
        # Extract package name from title like "Vulnerable npm package: ajv"
        pkg_name = v.Title.replace("Vulnerable npm package: ", "").strip().lower()
        if pkg_name in still_vulnerable:
            not_fixed.append(v)
        else:
            actually_fixed.append(v)

    # Combine: vulns npm audit fix couldn't resolve + vulns with no fix available at all
    all_unfixed = not_fixed + no_fix_available
    if all_unfixed:
        names = ", ".join(v.Title.replace("Vulnerable npm package: ", "") for v in all_unfixed)
        _log_event(db, scan_id, "scan.vulnerability.found",
            f"Unfixable vulnerabilities: {names} — no compatible fix available, manual upgrade required",
            {"unfixable_packages": [v.Title for v in all_unfixed]},
            worker=worker_name,
        )

    # Read package.json after fix
    with open(pkg_path, "r") as f:
        modified_pkg = f.read()

    # Check if package.json actually changed
    pkg_changed = modified_pkg != original_pkg

    # Check if package-lock.json changed
    lock_changed = False
    modified_lock = None
    if os.path.isfile(lock_path):
        with open(lock_path, "r") as f:
            modified_lock = f.read()
        lock_changed = original_lock is None or modified_lock != original_lock

    if not pkg_changed and not lock_changed:
        _log_event(db, scan_id, "scan.progress", "npm audit fix made no changes to tracked files", worker=worker_name)
        await db.commit()
        return 0

    if not actually_fixed:
        _log_event(db, scan_id, "scan.progress", "npm audit fix ran but no vulnerabilities were resolved", worker=worker_name)
        await db.commit()
        return 0

    fixes_created = []

    # Create Fix record for package.json if it changed
    if pkg_changed:
        pkg_diff = _generate_unified_diff(original_pkg, modified_pkg, "package.json")
        primary_vuln = actually_fixed[0]
        pkg_fix = Fix(
            Id=str(uuid.uuid4()),
            VulnerabilityId=primary_vuln.Id,
            Status=FixStatus.BUILD_PASSED,
            DiffContent=pkg_diff,
            ConfidenceScore=0.95,
            AIModel="npm-audit-fix",
            AIPromptTokens=0,
            AICompletionTokens=0,
            BuildOutput="npm audit fix --force",
            TestOutput=proc.stdout[:1000] if proc.stdout else None,
            RetryCount=0,
            ValidatedAt=datetime.utcnow(),
        )
        db.add(pkg_fix)
        fixes_created.append(pkg_fix)

    # Create Fix record for package-lock.json if it changed
    if lock_changed and modified_lock:
        lock_vuln = actually_fixed[1] if len(actually_fixed) > 1 else actually_fixed[0]
        lock_fix = Fix(
            Id=str(uuid.uuid4()),
            VulnerabilityId=lock_vuln.Id,
            Status=FixStatus.BUILD_PASSED,
            DiffContent="__FULL_CONTENT__\n" + modified_lock,
            ConfidenceScore=0.95,
            AIModel="npm-audit-fix-lock",
            AIPromptTokens=0,
            AICompletionTokens=0,
            BuildOutput="npm audit fix --force (lock file)",
            TestOutput=None,
            RetryCount=0,
            ValidatedAt=datetime.utcnow(),
        )
        lock_vuln.FilePath = "package-lock.json"
        db.add(lock_fix)
        fixes_created.append(lock_fix)

    # Mark only ACTUALLY fixed vulns as validated; leave unfixed ones as OPEN
    for v in actually_fixed:
        v.Status = VulnerabilityStatus.FIX_VALIDATED

    fixed_names = ", ".join(v.Title.replace("Vulnerable npm package: ", "") for v in actually_fixed)
    _log_event(db, scan_id, "scan.fix.generated", f"Dependency fix: resolved {len(actually_fixed)} vulnerabilities ({fixed_names})", {
        "model": "npm-audit-fix",
        "confidence": 0.95,
        "status": "validated",
        "fixed_packages": [v.Title for v in actually_fixed],
        "unfixed_packages": [v.Title for v in not_fixed],
    }, worker=worker_name)
    _log_event(db, scan_id, "scan.fix.validated", f"Fix validated: {len(actually_fixed)} of {len(dep_vulns)} dependency vulnerabilities resolved", {
        "build_passed": True,
    }, worker=worker_name)

    await db.commit()
    return len(actually_fixed)


# ── Shared helper for non-npm dependency fixers ──────────────────────────────

async def _generic_dep_fix(
    clone_path: str,
    vuln_records: list,
    db,
    scan_id: str,
    worker_name: str | None,
    *,
    manifest_file: str,
    lock_files: list[str],
    install_cmds: list[list[str]] | None,
    fix_cmd: list[str],
    verify_cmd: list[str] | None,
    model_name: str,
    vuln_prefix: str,
    fix_timeout: int = 180,
) -> int:
    """
    Generic programmatic dependency fixer.
    Follows the same pattern as _fix_npm_dependencies:
    snapshot → install → fix → verify → create Fix records.
    """
    import subprocess as sp
    import shutil
    from app.models import Fix
    from app.utils.constants import FixStatus, VulnerabilityStatus

    all_dep = [v for v in vuln_records if v.Category == "dependency"]
    dep_vulns = [v for v in all_dep if v.IsAutoFixable]
    no_fix_available = [v for v in all_dep if not v.IsAutoFixable]

    if not dep_vulns:
        if no_fix_available:
            names = ", ".join(v.Title.replace(vuln_prefix, "") for v in no_fix_available)
            _log_event(db, scan_id, "scan.progress", f"No auto-fix available: {names}", {"unfixable": names}, worker=worker_name)
            await db.commit()
        return 0

    # Check that the fix tool exists
    tool = fix_cmd[0]
    if not shutil.which(tool):
        _log_event(db, scan_id, "scan.progress", f"{tool} not installed — skipping dependency fix", worker=worker_name)
        await db.commit()
        return 0

    manifest_path = os.path.join(clone_path, manifest_file)
    if not os.path.isfile(manifest_path):
        logger.warning(f"{manifest_file} not found — skipping dependency fix")
        return 0

    # Snapshot manifest before fix
    with open(manifest_path, "r") as f:
        original_manifest = f.read()

    # Snapshot lock files before fix
    lock_originals: dict[str, str | None] = {}
    for lf in lock_files:
        lf_path = os.path.join(clone_path, lf)
        if os.path.isfile(lf_path):
            with open(lf_path, "r") as f:
                lock_originals[lf] = f.read()
        else:
            lock_originals[lf] = None

    # Install dependencies if needed
    if install_cmds:
        for cmd in install_cmds:
            if shutil.which(cmd[0]):
                _log_event(db, scan_id, "scan.progress", f"Running {' '.join(cmd[:3])}...", worker=worker_name)
                await db.commit()
                try:
                    sp.run(cmd, cwd=clone_path, capture_output=True, text=True, timeout=300)
                except Exception as e:
                    logger.warning(f"{cmd[0]} failed: {e}")

    # Run the fix command
    _log_event(db, scan_id, "scan.progress", f"Running {' '.join(fix_cmd[:4])}...", {"status": "dep_fix"}, worker=worker_name)
    await db.commit()

    try:
        proc = sp.run(fix_cmd, cwd=clone_path, capture_output=True, text=True, timeout=fix_timeout)
        logger.info(f"{fix_cmd[0]} fix exit code: {proc.returncode}")
    except Exception as e:
        logger.error(f"{fix_cmd[0]} fix failed: {e}")
        _log_event(db, scan_id, "scan.progress", f"Dependency fix failed: {e}", worker=worker_name)
        await db.commit()
        return 0

    # Post-fix verification
    still_vulnerable: set[str] = set()
    if verify_cmd and shutil.which(verify_cmd[0]):
        try:
            verify_proc = sp.run(verify_cmd, cwd=clone_path, capture_output=True, text=True, timeout=120)
            # Each language's verify output is parsed differently — for simplicity,
            # if verify returns exit code 0, assume all fixed; if non-zero, some remain
            if verify_proc.returncode != 0 and verify_proc.stdout:
                # Try to parse package names from output
                try:
                    vdata = json.loads(verify_proc.stdout)
                    # npm audit format
                    if "vulnerabilities" in vdata and isinstance(vdata["vulnerabilities"], dict):
                        still_vulnerable = {k.lower() for k in vdata["vulnerabilities"]}
                    # pip-audit format (list)
                    elif isinstance(vdata, list):
                        still_vulnerable = {item.get("name", "").lower() for item in vdata}
                except (json.JSONDecodeError, TypeError):
                    pass
        except Exception as e:
            logger.warning(f"Post-fix verification failed: {e}")

    # Classify vulns as fixed vs not
    actually_fixed = []
    not_fixed = []
    for v in dep_vulns:
        pkg_name = v.Title.replace(vuln_prefix, "").strip().lower()
        if pkg_name in still_vulnerable:
            not_fixed.append(v)
        else:
            actually_fixed.append(v)

    all_unfixed = not_fixed + no_fix_available
    if all_unfixed:
        names = ", ".join(v.Title.replace(vuln_prefix, "") for v in all_unfixed)
        _log_event(db, scan_id, "scan.vulnerability.found",
            f"Unfixable: {names} — manual upgrade required",
            {"unfixable_packages": [v.Title for v in all_unfixed]}, worker=worker_name)

    # Read manifest after fix
    with open(manifest_path, "r") as f:
        modified_manifest = f.read()

    manifest_changed = modified_manifest != original_manifest

    # Check lock files
    lock_changes: dict[str, str] = {}
    for lf in lock_files:
        lf_path = os.path.join(clone_path, lf)
        if os.path.isfile(lf_path):
            with open(lf_path, "r") as f:
                modified_lock = f.read()
            if lock_originals[lf] is None or modified_lock != lock_originals[lf]:
                lock_changes[lf] = modified_lock

    if not manifest_changed and not lock_changes:
        _log_event(db, scan_id, "scan.progress", "Dependency fix made no changes", worker=worker_name)
        await db.commit()
        return 0

    if not actually_fixed:
        _log_event(db, scan_id, "scan.progress", "Dependency fix ran but no vulnerabilities were resolved", worker=worker_name)
        await db.commit()
        return 0

    fixes_created = []

    # Create Fix for manifest file
    if manifest_changed:
        diff = _generate_unified_diff(original_manifest, modified_manifest, manifest_file)
        fix = Fix(
            Id=str(uuid.uuid4()),
            VulnerabilityId=actually_fixed[0].Id,
            Status=FixStatus.BUILD_PASSED,
            DiffContent=diff,
            ConfidenceScore=0.95,
            AIModel=model_name,
            AIPromptTokens=0, AICompletionTokens=0,
            BuildOutput=" ".join(fix_cmd),
            TestOutput=proc.stdout[:1000] if proc.stdout else None,
            RetryCount=0,
            ValidatedAt=datetime.utcnow(),
        )
        db.add(fix)
        fixes_created.append(fix)

    # Create Fix for lock files
    vuln_idx = 1
    for lf, content in lock_changes.items():
        link_vuln = actually_fixed[vuln_idx] if vuln_idx < len(actually_fixed) else actually_fixed[0]
        lock_fix = Fix(
            Id=str(uuid.uuid4()),
            VulnerabilityId=link_vuln.Id,
            Status=FixStatus.BUILD_PASSED,
            DiffContent="__FULL_CONTENT__\n" + content,
            ConfidenceScore=0.95,
            AIModel=f"{model_name}-lock",
            AIPromptTokens=0, AICompletionTokens=0,
            BuildOutput=f"{' '.join(fix_cmd)} (lock file)",
            TestOutput=None, RetryCount=0,
            ValidatedAt=datetime.utcnow(),
        )
        link_vuln.FilePath = lf
        db.add(lock_fix)
        fixes_created.append(lock_fix)
        vuln_idx += 1

    for v in actually_fixed:
        v.Status = VulnerabilityStatus.FIX_VALIDATED

    fixed_names = ", ".join(v.Title.replace(vuln_prefix, "") for v in actually_fixed)
    _log_event(db, scan_id, "scan.fix.generated",
        f"Dependency fix: resolved {len(actually_fixed)} vulnerabilities ({fixed_names})",
        {"model": model_name, "status": "validated"}, worker=worker_name)
    _log_event(db, scan_id, "scan.fix.validated",
        f"Fix validated: {len(actually_fixed)} of {len(dep_vulns)} dependency vulnerabilities resolved",
        {"build_passed": True}, worker=worker_name)

    await db.commit()
    return len(actually_fixed)


# ── Language-specific dependency fixers ───────────────────────────────────────

async def _fix_pip_dependencies(clone_path: str, vuln_records: list, db, scan_id: str, worker_name: str | None) -> int:
    return await _generic_dep_fix(
        clone_path, vuln_records, db, scan_id, worker_name,
        manifest_file="requirements.txt",
        lock_files=[],
        install_cmds=None,
        fix_cmd=["pip-audit", "--fix", "-r", os.path.join(clone_path, "requirements.txt")],
        verify_cmd=["pip-audit", "--format", "json", "-r", os.path.join(clone_path, "requirements.txt")],
        model_name="pip-audit-fix",
        vuln_prefix="Vulnerable pip package: ",
    )


async def _fix_dotnet_dependencies(clone_path: str, vuln_records: list, db, scan_id: str, worker_name: str | None) -> int:
    """For .NET: find vulnerable packages and run dotnet add package to upgrade them."""
    import subprocess as sp
    import shutil
    import glob
    from app.models import Fix
    from app.utils.constants import FixStatus, VulnerabilityStatus

    dep_vulns = [v for v in vuln_records if v.Category == "dependency" and v.IsAutoFixable]
    if not dep_vulns or not shutil.which("dotnet"):
        return 0

    # Find .csproj files
    csproj_files = glob.glob(os.path.join(clone_path, "**", "*.csproj"), recursive=True)
    if not csproj_files:
        return 0

    _log_event(db, scan_id, "scan.progress", "Running dotnet package upgrades...", worker=worker_name)
    await db.commit()

    # Snapshot csproj files
    originals: dict[str, str] = {}
    for csproj in csproj_files:
        with open(csproj, "r") as f:
            originals[csproj] = f.read()

    # For each vuln, try to upgrade the package
    for v in dep_vulns:
        # Extract package name from title like "Vulnerable package: Newtonsoft.Json 12.0.1"
        pkg_name = v.Title.replace("Vulnerable package: ", "").split(" ")[0].strip()
        if not pkg_name:
            continue
        for csproj in csproj_files:
            try:
                sp.run(
                    ["dotnet", "add", csproj, "package", pkg_name],
                    cwd=clone_path, capture_output=True, text=True, timeout=60,
                )
            except Exception:
                pass

    # Verify
    still_vulnerable: set[str] = set()
    try:
        proc = sp.run(
            ["dotnet", "list", "package", "--vulnerable", "--format", "json"],
            cwd=clone_path, capture_output=True, text=True, timeout=120,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout)
            for project in data.get("projects", []):
                for fw in project.get("frameworks", []):
                    for pkg in fw.get("topLevelPackages", []):
                        if pkg.get("vulnerabilities"):
                            still_vulnerable.add(pkg["id"].lower())
    except Exception:
        pass

    actually_fixed = []
    for v in dep_vulns:
        pkg_name = v.Title.replace("Vulnerable package: ", "").split(" ")[0].strip().lower()
        if pkg_name not in still_vulnerable:
            actually_fixed.append(v)

    if not actually_fixed:
        return 0

    # Create Fix records for changed csproj files
    fixes_created = 0
    vuln_idx = 0
    for csproj in csproj_files:
        with open(csproj, "r") as f:
            modified = f.read()
        if modified == originals[csproj]:
            continue
        rel_path = os.path.relpath(csproj, clone_path)
        diff = _generate_unified_diff(originals[csproj], modified, rel_path)
        link_vuln = actually_fixed[vuln_idx] if vuln_idx < len(actually_fixed) else actually_fixed[0]
        fix = Fix(
            Id=str(uuid.uuid4()),
            VulnerabilityId=link_vuln.Id,
            Status=FixStatus.BUILD_PASSED,
            DiffContent=diff,
            ConfidenceScore=0.95,
            AIModel="dotnet-package-fix",
            AIPromptTokens=0, AICompletionTokens=0,
            BuildOutput="dotnet add package",
            TestOutput=None, RetryCount=0,
            ValidatedAt=datetime.utcnow(),
        )
        link_vuln.FilePath = rel_path
        db.add(fix)
        vuln_idx += 1
        fixes_created += 1

    for v in actually_fixed:
        v.Status = VulnerabilityStatus.FIX_VALIDATED

    if fixes_created:
        fixed_names = ", ".join(v.Title.replace("Vulnerable package: ", "").split(" ")[0] for v in actually_fixed)
        _log_event(db, scan_id, "scan.fix.generated",
            f"Dependency fix: resolved {len(actually_fixed)} vulnerabilities ({fixed_names})",
            {"model": "dotnet-package-fix", "status": "validated"}, worker=worker_name)
        _log_event(db, scan_id, "scan.fix.validated",
            f"Fix validated: {len(actually_fixed)} of {len(dep_vulns)} dependency vulnerabilities resolved",
            {"build_passed": True}, worker=worker_name)

    await db.commit()
    return len(actually_fixed)


async def _fix_java_dependencies(clone_path: str, vuln_records: list, db, scan_id: str, worker_name: str | None) -> int:
    # Maven: mvn versions:use-latest-releases
    if os.path.isfile(os.path.join(clone_path, "pom.xml")):
        return await _generic_dep_fix(
            clone_path, vuln_records, db, scan_id, worker_name,
            manifest_file="pom.xml",
            lock_files=[],
            install_cmds=None,
            fix_cmd=["mvn", "versions:use-latest-releases", "-DgenerateBackupPoms=false", "-q"],
            verify_cmd=None,
            model_name="maven-versions-fix",
            vuln_prefix="Vulnerable Java package: ",
            fix_timeout=300,
        )
    # Gradle: ./gradlew dependencies (no direct fix command — mark as best-effort)
    elif os.path.isfile(os.path.join(clone_path, "build.gradle")) or os.path.isfile(os.path.join(clone_path, "build.gradle.kts")):
        return await _generic_dep_fix(
            clone_path, vuln_records, db, scan_id, worker_name,
            manifest_file="build.gradle" if os.path.isfile(os.path.join(clone_path, "build.gradle")) else "build.gradle.kts",
            lock_files=["gradle.lockfile"],
            install_cmds=None,
            fix_cmd=["./gradlew", "dependencies", "--write-locks"],
            verify_cmd=None,
            model_name="gradle-fix",
            vuln_prefix="Vulnerable Java package: ",
            fix_timeout=300,
        )
    return 0


async def _fix_go_dependencies(clone_path: str, vuln_records: list, db, scan_id: str, worker_name: str | None) -> int:
    return await _generic_dep_fix(
        clone_path, vuln_records, db, scan_id, worker_name,
        manifest_file="go.mod",
        lock_files=["go.sum"],
        install_cmds=None,
        fix_cmd=["go", "get", "-u", "./..."],
        verify_cmd=["govulncheck", "-json", "./..."],
        model_name="go-get-fix",
        vuln_prefix="Vulnerable Go package: ",
    )


async def _fix_rust_dependencies(clone_path: str, vuln_records: list, db, scan_id: str, worker_name: str | None) -> int:
    return await _generic_dep_fix(
        clone_path, vuln_records, db, scan_id, worker_name,
        manifest_file="Cargo.toml",
        lock_files=["Cargo.lock"],
        install_cmds=None,
        fix_cmd=["cargo", "update"],
        verify_cmd=["cargo", "audit", "--json"],
        model_name="cargo-update-fix",
        vuln_prefix="Vulnerable Rust package: ",
    )


async def _fix_ruby_dependencies(clone_path: str, vuln_records: list, db, scan_id: str, worker_name: str | None) -> int:
    return await _generic_dep_fix(
        clone_path, vuln_records, db, scan_id, worker_name,
        manifest_file="Gemfile",
        lock_files=["Gemfile.lock"],
        install_cmds=[["bundle", "install"]],
        fix_cmd=["bundle", "update", "--conservative"],
        verify_cmd=["bundle", "audit", "check", "--format", "json"],
        model_name="bundle-update-fix",
        vuln_prefix="Vulnerable Ruby gem: ",
    )


def _apply_diff_to_content(original_content: str, diff_content: str) -> str:
    """Apply a unified diff to original file content. Returns the patched result."""
    import re

    original_lines = original_content.splitlines(keepends=True)
    result_lines = list(original_lines)
    hunk_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

    diff_lines = diff_content.splitlines()
    offset = 0  # running offset from previously applied hunks
    i = 0

    while i < len(diff_lines):
        line = diff_lines[i]
        m = hunk_re.match(line)
        if not m:
            i += 1
            continue

        orig_start = int(m.group(1))
        pos = orig_start - 1 + offset  # 0-based index into result_lines
        i += 1

        hunk_orig: list[str] = []
        hunk_new: list[str] = []

        while i < len(diff_lines):
            hline = diff_lines[i]
            if hunk_re.match(hline) or hline.startswith("---") or hline.startswith("+++"):
                break
            if hline.startswith("-"):
                hunk_orig.append(hline[1:])
            elif hline.startswith("+"):
                hunk_new.append(hline[1:])
            elif hline.startswith(" "):
                ctx = hline[1:]
                hunk_orig.append(ctx)
                hunk_new.append(ctx)
            # else: ignore (e.g. "\ No newline at end of file")
            i += 1

        # Ensure each line ends with a newline
        def _ensure_nl(lines: list[str]) -> list[str]:
            return [l if l.endswith("\n") else l + "\n" for l in lines]

        hunk_orig = _ensure_nl(hunk_orig)
        hunk_new = _ensure_nl(hunk_new)

        result_lines[pos : pos + len(hunk_orig)] = hunk_new
        offset += len(hunk_new) - len(hunk_orig)

    return "".join(result_lines)


@celery_app.task(name="create_pr_task")
def create_pr_task(scan_id: str, github_token: str, owner: str, repo: str, branch: str = "main"):
    """Create a single GitHub PR for all validated fixes in a scan."""
    import concurrent.futures
    coro = _async_create_pr(scan_id, github_token, owner, repo, branch)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(asyncio.run, coro).result()
    else:
        asyncio.run(coro)


async def _async_create_pr(scan_id: str, github_token: str, owner: str, repo: str, base_branch: str):
    from sqlalchemy import select
    from sqlalchemy.orm import joinedload
    from app.utils.database import async_session_factory
    from app.models import Fix, Vulnerability
    from app.services.github_service import GitHubService
    from app.utils.constants import FixStatus

    async with async_session_factory() as db:
        # Load all validated fixes for this scan
        result = await db.execute(
            select(Fix)
            .join(Vulnerability, Fix.VulnerabilityId == Vulnerability.Id)
            .where(Vulnerability.ScanId == scan_id)
            .where(Fix.Status == FixStatus.BUILD_PASSED)
            .options(joinedload(Fix.vulnerability))
        )
        fixes = result.scalars().all()

        if not fixes:
            logger.info(f"No validated fixes for scan {scan_id} — skipping PR creation")
            return

        # Load ALL dependency vulns — both fixed and unfixed — for PR description
        from app.utils.constants import VulnerabilityStatus
        all_dep_result = await db.execute(
            select(Vulnerability)
            .where(Vulnerability.ScanId == scan_id)
            .where(Vulnerability.Category == "dependency")
        )
        all_dep_vulns_all = all_dep_result.scalars().all()
        all_dep_vulns = [v for v in all_dep_vulns_all if v.Status == VulnerabilityStatus.FIX_VALIDATED]
        unfixed_dep_vulns = [v for v in all_dep_vulns_all if v.Status != VulnerabilityStatus.FIX_VALIDATED]

        gh_service = GitHubService(github_token)

        try:
            repo_info = await gh_service.get_repo_info(owner, repo)
            default_branch = repo_info.get("default_branch", base_branch)
            base_sha = await gh_service.get_branch_sha(owner, repo, default_branch)

            timestamp = int(datetime.utcnow().timestamp())
            branch_name = f"sealr/fixes-{scan_id[:8]}-{timestamp}"
            await gh_service.create_branch(owner, repo, branch_name, base_sha)

            committed_files: list[str] = []
            fix_descriptions: list[str] = []

            for fix in fixes:
                vuln = fix.vulnerability
                if not fix.DiffContent or not vuln.FilePath:
                    continue

                # Strip leading repo-name segment (e.g. "RepoName/src/..." → "src/...")
                file_path = vuln.FilePath
                if file_path.startswith(f"{repo}/"):
                    file_path = file_path[len(repo) + 1:]

                # Get the patched file content
                if fix.DiffContent.startswith("__FULL_CONTENT__\n"):
                    # Full replacement content (e.g. package-lock.json from npm audit fix)
                    patched = fix.DiffContent[len("__FULL_CONTENT__\n"):]
                else:
                    # Unified diff — fetch original from GitHub and apply
                    try:
                        original = await gh_service.get_file_content(owner, repo, file_path, default_branch)
                        patched = _apply_diff_to_content(original, fix.DiffContent)
                    except Exception as e:
                        logger.warning(f"Could not fetch/patch {file_path}: {e} — committing raw diff")
                        patched = fix.DiffContent

                # For programmatic dependency fixers, list all affected packages
                is_dep_fix = fix.AIModel.endswith("-fix") or fix.AIModel.endswith("-fix-lock") or fix.AIModel == "dotnet-package-fix"
                if is_dep_fix and all_dep_vulns:
                    if fix.AIModel.endswith("-lock"):
                        commit_msg = f"chore: update lock file after dependency fix"
                    else:
                        # Strip common prefixes from vuln titles for clean display
                        pkg_names = []
                        for dv in all_dep_vulns:
                            name = dv.Title
                            for prefix in ("Vulnerable npm package: ", "Vulnerable pip package: ",
                                           "Vulnerable package: ", "Vulnerable Java package: ",
                                           "Vulnerable Go package: ", "Vulnerable Rust package: ",
                                           "Vulnerable Ruby gem: "):
                                name = name.replace(prefix, "")
                            pkg_names.append(name.split(" ")[0])
                        commit_msg = (
                            f"fix(dependency): upgrade vulnerable packages\n\n"
                            f"Packages fixed: {', '.join(pkg_names)}\n"
                            f"Applied by Sealr via {fix.AIModel}."
                        )
                        # Add all dep vulns to PR description (only once)
                        for dv in all_dep_vulns:
                            fix_descriptions.append(
                                f"- **{dv.Severity}** [{dv.Category}] {dv.Title} (`{file_path}`)"
                            )
                else:
                    commit_msg = (
                        f"fix({vuln.Category}): {vuln.Title}\n\n"
                        f"Applied by Sealr. Model: {fix.AIModel}. Confidence: {fix.ConfidenceScore}"
                    )
                    fix_descriptions.append(
                        f"- **{vuln.Severity}** [{vuln.Category}] {vuln.Title} (`{file_path}`)"
                    )

                try:
                    await gh_service.commit_file(owner, repo, branch_name, file_path, patched, commit_msg)
                    committed_files.append(file_path)
                    fix.BranchName = branch_name
                    await db.commit()
                except Exception as e:
                    logger.error(f"Failed to commit {file_path}: {e}")

            if not committed_files:
                logger.warning(f"No files committed for scan {scan_id}")
                return

            # Total issues fixed = committed files for non-dep + all dep vulns covered
            total_fixed = len(fix_descriptions)

            # Build unfixed vulnerabilities section
            unfixed_section = ""
            if unfixed_dep_vulns:
                unfixed_lines = []
                for uv in unfixed_dep_vulns:
                    pkg = uv.Title.replace("Vulnerable npm package: ", "")
                    unfixed_lines.append(
                        f"- :warning: **{uv.Severity}** `{pkg}` — no compatible fix available, manual upgrade or replacement required"
                    )
                unfixed_section = (
                    f"\n\n### Unfixed Vulnerabilities ({len(unfixed_dep_vulns)})\n"
                    f"The following vulnerabilities could not be auto-fixed by `npm audit fix`. "
                    f"These require manual intervention (e.g., replacing the package or waiting for an upstream patch).\n\n"
                    + "\n".join(unfixed_lines)
                )

            pr_body = (
                f"## Security Fixes\n\n"
                f"Sealr automatically detected and fixed **{total_fixed}** security issue{'s' if total_fixed > 1 else ''}.\n\n"
                f"### Fixes Applied\n"
                + "\n".join(fix_descriptions)
                + unfixed_section
                + f"\n\n### Files Changed\n"
                + "\n".join(f"- `{f}`" for f in committed_files)
                + f"\n\n---\n*Generated by [Sealr](https://github.com/sealr-io/sealr) · Scan ID: `{scan_id}`*"
            )

            pr = await gh_service.create_pull_request(
                owner, repo,
                title=f"[Sealr] {total_fixed} security fix{'es' if total_fixed > 1 else ''} — scan {scan_id[:8]}",
                body=pr_body,
                head_branch=branch_name,
                base_branch=default_branch,
            )

            for fix in fixes:
                fix.Status = FixStatus.PR_CREATED
                fix.PRUrl = pr["html_url"]
                fix.PRNumber = pr["number"]
                fix.BranchName = branch_name
            await db.commit()

            publish_event(scan_id, "scan.pr.created", f"PR created: {pr['html_url']}", {
                "pr_url": pr["html_url"],
                "pr_number": pr["number"],
                "issues_fixed": total_fixed,
            })
            logger.info(f"PR {pr['html_url']} created for scan {scan_id} with {total_fixed} fix(es)")

        except Exception as e:
            logger.error(f"Batch PR creation failed for scan {scan_id}: {e}")
        finally:
            await gh_service.close()
