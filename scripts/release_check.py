#!/usr/bin/env python3
"""Focused release hygiene checks; not a complete security or secret audit."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
IGNORED = {".git", ".venv", "work", "build", "dist", "__pycache__", ".runtime"}
TEXT_SUFFIXES = {".py", ".md", ".toml", ".json", ".yml", ".yaml", ".in"}
REQUIRED = {
    "LICENSE", "README.md", "THIRD_PARTY_NOTICES.md", "SECURITY.md",
    "CONTRIBUTING.md", "CHANGELOG.md", "MANIFEST.in", "pyproject.toml",
    "security/moby-seccomp.json", "security/LICENSE.moby", "security/NOTICE.moby",
    "security/README.md", "docs/RELEASE.md", ".github/workflows/ci.yml",
}
PROFILE_SHA256 = "9c1025c88ccaa517b648da571961838744ea2137f176bfe6a48b21294cae9c76"
SUSPECT = {
    "provider key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}"),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "personal absolute path": re.compile(r"(?:/Users/|/home/(?!(?:runner|worker)/))[A-Za-z0-9][^\s\"'<>]*"),
}
MARKDOWN_LINK = re.compile(r"!?\[[^\]\n]*\]\(([^\s)]+)(?:\s+\"[^\"]*\")?\)")


def candidate_files() -> list[Path]:
    # Work before the initial commit, in a checkout, and in an extracted sdist.
    if (ROOT / ".git").exists():
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=ROOT, check=True, stdout=subprocess.PIPE,
        )
        return sorted({ROOT / name for name in result.stdout.decode().split("\0") if name})
    return sorted(path for path in ROOT.rglob("*") if path.is_file()
                  and not any(part in IGNORED or part.endswith(".egg-info")
                              for part in path.relative_to(ROOT).parts))


def main() -> int:
    failures = []
    files = candidate_files()
    for name in sorted(REQUIRED):
        if not (ROOT / name).is_file():
            failures.append(f"Missing required file: {name}")
    profile = ROOT / "security/moby-seccomp.json"
    if profile.exists() and hashlib.sha256(profile.read_bytes()).hexdigest() != PROFILE_SHA256:
        failures.append("Vendored Moby profile differs from the recorded unmodified upstream copy")
    checked = 0
    for path in files:
        relative = path.relative_to(ROOT)
        if (any(part in {".venv", ".runtime", "__pycache__"} for part in relative.parts)
                or path.name in {"auth.json", "credentials.json", ".env"}
                or path.suffix in {".db", ".sqlite", ".sqlite3", ".log"}):
            failures.append(f"Private/generated file is in release candidates: {relative}")
        if not path.is_file() or (path.suffix not in TEXT_SUFFIXES
                                  and path.name not in {"LICENSE", "Dockerfile"}):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeError:
            failures.append(f"Invalid UTF-8 text file: {relative}")
            continue
        checked += 1
        for number, line in enumerate(content.splitlines(), 1):
            for label, pattern in SUSPECT.items():
                if pattern.search(line):
                    # Never echo a matched credential into CI logs.
                    failures.append(f"Possible {label}: {relative}:{number}")
        if path.suffix != ".md":
            continue
        for match in MARKDOWN_LINK.finditer(content):
            target = match.group(1).strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            destination = (path.parent / unquote(parsed.path)).resolve()
            if not destination.is_relative_to(ROOT):
                failures.append(f"Local documentation link escapes checkout: {relative}")
            elif not destination.exists():
                failures.append(f"Broken local documentation link in {relative}: {target}")
    if failures:
        print("Release checks failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Release checks passed: {checked} text files; local links, required notices, profile hash, focused secret/path scan.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
