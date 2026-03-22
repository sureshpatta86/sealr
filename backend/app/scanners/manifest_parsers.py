"""
Parsers for dependency manifest files.

Each parser takes a file path and returns a list of (package_name, version) tuples.
Parsers use only stdlib modules (re, logging) — no external XML/TOML libraries required.
On any failure, parsers log a warning and return an empty list.
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)


def _read_file(path: str) -> str:
    """Read a file's text content, returning empty string on failure."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return ""


# ---------------------------------------------------------------------------
# Maven pom.xml
# ---------------------------------------------------------------------------

def parse_pom_xml(path: str) -> list[tuple[str, str]]:
    """Parse Maven pom.xml for <dependency> elements.

    Returns ("groupId:artifactId", "version") tuples.
    Dependency entries without an explicit <version> are skipped.
    """
    content = _read_file(path)
    if not content:
        return []

    results: list[tuple[str, str]] = []
    try:
        # Strip XML namespace prefixes so tags match simply.
        cleaned = re.sub(r"<(/?)[\w.-]+:", r"<\1", content)

        dep_pattern = re.compile(
            r"<dependency>(.*?)</dependency>", re.DOTALL
        )
        tag_pattern = re.compile(r"<(\w+)>\s*(.*?)\s*</\1>")

        for dep_match in dep_pattern.finditer(cleaned):
            block = dep_match.group(1)
            tags: dict[str, str] = {}
            for tag_match in tag_pattern.finditer(block):
                tags[tag_match.group(1)] = tag_match.group(2)

            group_id = tags.get("groupId", "")
            artifact_id = tags.get("artifactId", "")
            version = tags.get("version", "")

            if group_id and artifact_id and version:
                results.append((f"{group_id}:{artifact_id}", version))
    except Exception as exc:
        logger.warning("Error parsing pom.xml at %s: %s", path, exc)
        return []

    return results


# ---------------------------------------------------------------------------
# Gradle build.gradle
# ---------------------------------------------------------------------------

_GRADLE_CONFIG_KEYWORDS = (
    "implementation",
    "api",
    "compile",
    "compileOnly",
    "runtimeOnly",
    "testImplementation",
    "testCompile",
    "testRuntimeOnly",
    "classpath",
    "annotationProcessor",
)

# Matches:  implementation 'group:artifact:version'
#           implementation "group:artifact:version"
#           implementation("group:artifact:version")
_GRADLE_PATTERN = re.compile(
    r"(?:" + "|".join(_GRADLE_CONFIG_KEYWORDS) + r")"
    r"""\s*\(?\s*['"]([^'"]+):([^'"]+):([^'"]+)['"]\s*\)?""",
)


def parse_build_gradle(path: str) -> list[tuple[str, str]]:
    """Parse Gradle build.gradle for dependency declarations.

    Returns ("group:artifact", "version") tuples.
    """
    content = _read_file(path)
    if not content:
        return []

    results: list[tuple[str, str]] = []
    try:
        for match in _GRADLE_PATTERN.finditer(content):
            group, artifact, version = match.group(1), match.group(2), match.group(3)
            results.append((f"{group}:{artifact}", version))
    except Exception as exc:
        logger.warning("Error parsing build.gradle at %s: %s", path, exc)
        return []

    return results


# ---------------------------------------------------------------------------
# Go go.mod
# ---------------------------------------------------------------------------

def parse_go_mod(path: str) -> list[tuple[str, str]]:
    """Parse go.mod require block entries.

    Returns (module_path, version) tuples.
    Handles both single-line `require mod v1.2.3` and block syntax.
    """
    content = _read_file(path)
    if not content:
        return []

    results: list[tuple[str, str]] = []
    try:
        # Block require:  require ( ... )
        block_pattern = re.compile(r"require\s*\((.*?)\)", re.DOTALL)
        # Single-line require: require mod v1.2.3
        single_pattern = re.compile(r"^require\s+(\S+)\s+(\S+)", re.MULTILINE)
        # Entry inside a block
        entry_pattern = re.compile(r"^\s*(\S+)\s+(\S+)", re.MULTILINE)

        for block_match in block_pattern.finditer(content):
            block = block_match.group(1)
            for entry in entry_pattern.finditer(block):
                module = entry.group(1)
                version = entry.group(2)
                # Skip comments
                if module.startswith("//"):
                    continue
                results.append((module, version))

        for single_match in single_pattern.finditer(content):
            module = single_match.group(1)
            version = single_match.group(2)
            # Avoid duplicates from block-require lines already captured
            if module != "(" and (module, version) not in results:
                results.append((module, version))
    except Exception as exc:
        logger.warning("Error parsing go.mod at %s: %s", path, exc)
        return []

    return results


# ---------------------------------------------------------------------------
# Rust Cargo.lock
# ---------------------------------------------------------------------------

def parse_cargo_lock(path: str) -> list[tuple[str, str]]:
    """Parse Cargo.lock [[package]] blocks.

    Returns (package_name, version) tuples.
    """
    content = _read_file(path)
    if not content:
        return []

    results: list[tuple[str, str]] = []
    try:
        # Split on [[package]] headers
        blocks = re.split(r"^\[\[package\]\]\s*$", content, flags=re.MULTILINE)
        name_pattern = re.compile(r'^name\s*=\s*"([^"]+)"', re.MULTILINE)
        version_pattern = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)

        for block in blocks:
            name_match = name_pattern.search(block)
            version_match = version_pattern.search(block)
            if name_match and version_match:
                results.append((name_match.group(1), version_match.group(1)))
    except Exception as exc:
        logger.warning("Error parsing Cargo.lock at %s: %s", path, exc)
        return []

    return results


# ---------------------------------------------------------------------------
# Ruby Gemfile.lock
# ---------------------------------------------------------------------------

def parse_gemfile_lock(path: str) -> list[tuple[str, str]]:
    """Parse Gemfile.lock GEM specs section.

    Returns (gem_name, version) tuples from the ``specs:`` block under ``GEM``.
    """
    content = _read_file(path)
    if not content:
        return []

    results: list[tuple[str, str]] = []
    try:
        # The GEM section looks like:
        #   GEM
        #     remote: https://rubygems.org/
        #     specs:
        #       rails (7.0.4)
        #         actioncable (= 7.0.4)
        #       ...
        #
        # Top-level gems are indented 4 spaces; their sub-deps 6+.
        gem_section = re.search(
            r"^GEM\s*\n(.*?)(?=^\S|\Z)", content, re.MULTILINE | re.DOTALL
        )
        if gem_section:
            in_specs = False
            for line in gem_section.group(1).splitlines():
                stripped = line.strip()
                if stripped == "specs:":
                    in_specs = True
                    continue
                if not in_specs:
                    continue
                # Top-level gem lines are indented exactly 4 spaces
                if line.startswith("    ") and not line.startswith("      "):
                    match = re.match(r"^\s+(\S+)\s+\((\S+)\)", line)
                    if match:
                        results.append((match.group(1), match.group(2)))
    except Exception as exc:
        logger.warning("Error parsing Gemfile.lock at %s: %s", path, exc)
        return []

    return results


# ---------------------------------------------------------------------------
# Python requirements.txt
# ---------------------------------------------------------------------------

def parse_requirements_txt(path: str) -> list[tuple[str, str]]:
    """Parse Python requirements.txt.

    Handles ``package==version``, ``package>=version``, and similar specifiers.
    Lines with extras (e.g. ``package[extra]==1.0``) are supported.
    Comments, blank lines, and ``-r``/``-e``/``--`` option lines are skipped.
    """
    content = _read_file(path)
    if not content:
        return []

    results: list[tuple[str, str]] = []
    # Matches: package==1.0, package>=1.0, package~=1.0, package[extra]==1.0
    pin_pattern = re.compile(
        r"^([A-Za-z0-9_][A-Za-z0-9._-]*(?:\[[^\]]+\])?)\s*(==|>=|<=|~=|!=|>|<)\s*([^\s;#,]+)",
    )

    try:
        for raw_line in content.splitlines():
            line = raw_line.strip()
            # Skip blanks, comments, options
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = pin_pattern.match(line)
            if match:
                package = match.group(1)
                version = match.group(3)
                results.append((package, version))
    except Exception as exc:
        logger.warning("Error parsing requirements.txt at %s: %s", path, exc)
        return []

    return results
