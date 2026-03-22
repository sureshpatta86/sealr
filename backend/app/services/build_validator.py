import logging
import shutil
import tempfile
from pathlib import Path

import docker

logger = logging.getLogger(__name__)


class BuildValidator:
    """Validates fixes by building and testing in an isolated Docker sandbox."""

    def __init__(self):
        self.docker_client = docker.from_env()

    async def validate_fix(
        self,
        repo_path: str,
        diff_content: str,
        language_config: dict,
    ) -> dict:
        """Apply diff, build, and test in an isolated container."""
        work_dir = tempfile.mkdtemp(prefix="sealr-build-")

        try:
            # Copy repo to work directory
            shutil.copytree(repo_path, work_dir, dirs_exist_ok=True)

            # Write patch file
            patch_path = Path(work_dir) / "sealr-fix.patch"
            patch_path.write_text(diff_content)

            # Build command
            build_cmd = language_config.get("build_command", "echo 'no build'")
            test_cmd = language_config.get("test_command", "")

            script = f"cd /app && git apply sealr-fix.patch && {build_cmd}"
            if test_cmd:
                script += f" && {test_cmd}"

            # Run in Docker with security constraints
            container = self.docker_client.containers.run(
                image=language_config["docker_image"],
                command=["sh", "-c", script],
                volumes={work_dir: {"bind": "/app", "mode": "rw"}},
                working_dir="/app",
                detach=True,
                network_disabled=True,
                mem_limit="2g",
                cpu_period=100000,
                cpu_quota=200000,  # 2 CPU cores
                remove=False,
            )

            # Wait with 5 minute timeout
            result = container.wait(timeout=300)
            logs = container.logs().decode("utf-8")
            exit_code = result["StatusCode"]
            container.remove()

            return {
                "success": exit_code == 0,
                "build_output": logs,
                "test_output": logs,
                "exit_code": exit_code,
            }

        except docker.errors.ContainerError as e:
            logger.error(f"Container error: {e}")
            return {
                "success": False,
                "build_output": str(e),
                "test_output": "",
                "exit_code": 1,
            }
        except Exception as e:
            logger.error(f"Build validation error: {e}")
            return {
                "success": False,
                "build_output": str(e),
                "test_output": "",
                "exit_code": 1,
            }
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)
