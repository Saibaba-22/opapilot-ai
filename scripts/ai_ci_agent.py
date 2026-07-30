#!/usr/bin/env python3
"""AI CI/CD remediation assistant for GitHub Actions, pytest, Docker, and deploy YAML.

Modes:

1. analyze   - summarize a failed GitHub Actions run and produce an RCA artifact.
2. remediate - after human approval, apply a constrained remediation with a
   validation/retry loop and produce a pull-request-ready worktree.

Safety design:
- The agent only edits allow-listed files.
- It never merges to main.
- It never deploys production.
- It validates before a PR is created.
- It returns manual actions when a failure is outside repository code control
  such as expired secrets, broken EC2 access, or cloud/network configuration.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import textwrap
import time
import urllib.request
from typing import Iterable

ROOT_DEFAULT = pathlib.Path.cwd()
MAX_LOG_CHARS = 60_000
MAX_FILE_CHARS = 18_000
MAX_PROMPT_CHARS = 95_000
PROJECT_PORT = "5000"
DEFAULT_MAX_ATTEMPTS = 3


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


ALLOWED_REMEDIATION_PATHS = (
    ".github/workflows/deploy.yml",
    ".github/workflows/ai-agent-rca.yml",
    ".github/workflows/ai-agent-remediate.yml",
    ".github/workflows/ai-agent-guardian.yml",
    "Dockerfile",
    ".dockerignore",
    ".gitignore",
    "requirements.txt",
    "requirements-dev.txt",
    "app.py",
    "tests/test_app.py",
    "tests/test_training_failure.py",
    "README.md",
    "docs/AI_AGENT_RUNBOOK.md",
    "scripts/ai_ci_agent.py",
)

CONTEXT_PATTERNS = (
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    "Dockerfile",
    ".dockerignore",
    ".gitignore",
    "requirements.txt",
    "requirements-dev.txt",
    "app.py",
    "tests/*.py",
    "README.md",
    "docs/*.md",
)

SECRET_PATTERNS = [
    # Mask concrete key/token/password assignments, but v3.1 protects GitHub
    # expression references like ${{ secrets.DOCKERHUB_TOKEN }} before this runs.
    (re.compile(r"(?i)(api[_-]?key|token|password|secret|private[_-]?key)(\s*[:=]\s*)([^\s'\"]+)"), r"\1\2***MASKED***"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "***MASKED_PRIVATE_KEY***"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "***MASKED_AWS_ACCESS_KEY***"),
    (re.compile(r"(?i)gh[pousr]_[A-Za-z0-9_]{20,}"), "***MASKED_GITHUB_TOKEN***"),
]

GITHUB_EXPRESSION_PATTERN = re.compile(r"\$\{\{\s*(?:secrets|vars)\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}")
MASKED_PLACEHOLDER_MARKERS = (
    "***MASKED***",
    "***MASKED_PRIVATE_KEY***",
    "***MASKED_AWS_ACCESS_KEY***",
    "***MASKED_GITHUB_TOKEN***",
)
MASKED_SCAN_EXCLUDED_PATHS = {"scripts/ai_ci_agent.py", "README.md", "docs/AI_AGENT_RUNBOOK.md"}

MANUAL_ONLY_HINTS = (
    "docker login", "unauthorized", "denied: requested access", "authentication required",
    "permission denied (publickey)", "host key verification failed", "connection timed out",
    "no space left on device", "quota", "rate limit", "secret", "secrets.",
)


def sanitize(text: str) -> str:
    """Best-effort masking before sending data to an LLM or artifact.

    v3.1 protection: GitHub expressions such as `${{ secrets.NAME }}` and
    `${{ vars.NAME }}` are references, not secret values. They must remain
    syntactically intact in AI prompts, otherwise the AI may write
    `***MASKED*** secrets.NAME }}` back into workflow files.
    """
    protected: list[tuple[str, str]] = []

    def protect(match: re.Match[str]) -> str:
        token = f"__GITHUB_EXPR_{len(protected)}__"
        protected.append((token, match.group(0)))
        # Quote the placeholder so key/password sanitizers do not treat it as a
        # concrete secret value. The quotes are removed when the token is restored.
        return f'"{token}"'

    text = GITHUB_EXPRESSION_PATTERN.sub(protect, text)
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    for token, original in protected:
        text = text.replace(f'"{token}"', original)
        text = text.replace(token, original)
    return text


def read_raw_text(path: pathlib.Path, limit: int | None = None) -> str:
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    if limit and len(data) > limit:
        return data[:limit] + f"\n\n...[truncated to {limit} characters]...\n"
    return data


def read_text(path: pathlib.Path, limit: int | None = None) -> str:
    data = sanitize(read_raw_text(path))
    if limit and len(data) > limit:
        return data[:limit] + f"\n\n...[truncated to {limit} characters]...\n"
    return data


def contains_masked_placeholder(text: str) -> bool:
    return any(marker in text for marker in MASKED_PLACEHOLDER_MARKERS)


def scan_masked_placeholders(repo_root: pathlib.Path) -> list[str]:
    findings: list[str] = []
    for rel in ALLOWED_REMEDIATION_PATHS:
        if rel in MASKED_SCAN_EXCLUDED_PATHS:
            continue
        path = repo_root / rel
        if path.exists() and contains_masked_placeholder(read_raw_text(path)):
            findings.append(rel)
    return findings


def collect_logs(logs_dir: pathlib.Path | None, logs_file: pathlib.Path | None) -> str:
    chunks: list[str] = []
    if logs_file and logs_file.exists():
        chunks.append(f"## {logs_file}\n" + read_text(logs_file, MAX_LOG_CHARS))
    if logs_dir and logs_dir.exists():
        for file in sorted(logs_dir.rglob("*")):
            if file.is_file():
                rel = file.relative_to(logs_dir)
                content = read_text(file, 20_000)
                chunks.append(f"\n\n## log file: {rel}\n{content}")
    text = "\n".join(chunks).strip()
    if len(text) > MAX_LOG_CHARS:
        text = text[-MAX_LOG_CHARS:]
        text = "...[older log content truncated; keeping final failure context]...\n" + text
    return text or "No logs were available to the agent."


def collect_repo_context(repo_root: pathlib.Path) -> str:
    sections: list[str] = []
    seen: set[pathlib.Path] = set()
    for pattern in CONTEXT_PATTERNS:
        for path in sorted(repo_root.glob(pattern)):
            if not path.is_file() or path in seen:
                continue
            seen.add(path)
            rel = path.relative_to(repo_root)
            sections.append(f"\n\n### File: {rel}\n```\n{read_text(path, MAX_FILE_CHARS)}\n```")
    return "".join(sections).strip() or "No repository context files found."


def truncate_prompt(*parts: str) -> str:
    prompt = "\n\n".join(parts)
    if len(prompt) <= MAX_PROMPT_CHARS:
        return prompt
    return prompt[:35_000] + "\n\n...[middle prompt truncated]...\n\n" + prompt[-55_000:]


def call_gemini(prompt: str, system_instruction: str) -> str | None:
    api_key = os.environ.get("AI_AGENT_API_KEY") or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None
    try:
        import google.generativeai as genai  # type: ignore
    except Exception as exc:  # pragma: no cover - depends on runner install
        return f"AI model unavailable because google-generativeai could not be imported: {exc}"

    model_name = os.environ.get("AI_AGENT_MODEL") or "gemini-1.5-flash"
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name, system_instruction=system_instruction)
        response = model.generate_content(prompt)
        return (getattr(response, "text", None) or "").strip()
    except Exception as exc:  # pragma: no cover - external API
        return f"AI model call failed: {exc}"


def fallback_analysis(run_id: str, logs: str, context: str) -> str:
    lower = logs.lower()
    likely: list[str] = []
    if "docker/login-action" in lower or "login to docker" in lower or "log in to docker" in lower or "unauthorized" in lower:
        likely.append(
            "Docker Hub authentication failed. Check DOCKERHUB_USERNAME and DOCKERHUB_TOKEN secrets, "
            "token permissions, and Docker Hub rate/auth restrictions."
        )
    if "pytest" in lower or "assertionerror" in lower:
        likely.append("Pytest failure. Review the failing test name, assertion, and related app/test code.")
    if "docker build" in lower or "buildx" in lower:
        likely.append("Docker build/buildx failure. Review Dockerfile, requirements install output, and image build context.")
    if "curl" in lower and "/health" in lower:
        likely.append("Health check failed. Check app route, app/container port 5000, Docker port mapping, and deployment script.")
    if "permission denied" in lower and ("ssh" in lower or "ec2" in lower):
        likely.append("EC2 SSH deployment failed. Check EC2_SSH_KEY, username, host, and instance SSH access.")
    if not likely:
        likely.append("The exact failure needs the complete GitHub Actions logs. Review the failed step name and final 100 lines.")

    return f"""# AI Agent RCA Artifact

Generated: {now_utc()}
Run ID: {run_id}

## Executive summary

The AI provider was not available, so this is a deterministic fallback RCA. The failed run logs were still collected and inspected for common CI/CD, pytest, Docker, and deployment failure patterns.

## Most likely root cause

{chr(10).join(f'- {item}' for item in likely)}

## Recommended solution options

1. Fix missing or invalid GitHub Actions secrets if the failure is secret/infrastructure related.
2. Fix repository files if the failure is in `app.py`, tests, Dockerfile, requirements, or workflow YAML.
3. Keep validate and pytest as pre-deployment gates.
4. Use the human-approved remediation workflow to prepare a PR instead of pushing directly to `main`.

## Validation plan

- Run Python syntax checks.
- Run pytest.
- Build the Docker image.
- Start the container and call `/health` on port 5000.
- After merge, approve `docker-publish`, then approve `production`.

## Rollback plan

- Redeploy the previous Docker image tag from Docker Hub.
- If the new container is unhealthy, stop it and restart the last known-good image.

## Human approval

Comment `/ai-agent approve` on the generated RCA issue to allow the remediation workflow to create a pull request. Review and merge the PR manually.
"""


def build_analysis_prompt(run_id: str, repo: str, metadata: str, logs: str, context: str) -> str:
    return truncate_prompt(
        f"Repository: {repo}\nFailed workflow run ID: {run_id}\nCurrent UTC time: {now_utc()}",
        "Workflow metadata:\n```json\n" + metadata + "\n```",
        "Failed logs:\n```\n" + logs + "\n```",
        "Repository CI/CD, pytest, Docker, and app context:\n" + context,
        textwrap.dedent(
            """
            Create a production-ready RCA artifact in Markdown.
            Required sections:
            1. Executive summary
            2. Failure evidence with exact failed job/step if visible
            3. Root cause
            4. Contributing factors
            5. Solution options, including safest option and tradeoffs
            6. Recommended remediation plan with file-level changes
            7. Validation plan for GitHub Actions, pytest, Docker build, container health check, and deployment
            8. Rollback plan
            9. Human approval instructions

            Rules:
            - Do not invent secrets or claim actions that are not in the logs.
            - If logs are incomplete, say exactly what is missing.
            - Do not recommend bypassing human approvals.
            - Keep commands safe and explicit.
            """
        ).strip(),
    )


def analyze(args: argparse.Namespace) -> int:
    repo_root = pathlib.Path(args.repo_root).resolve()
    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    logs = collect_logs(pathlib.Path(args.logs_dir) if args.logs_dir else None, pathlib.Path(args.logs_file) if args.logs_file else None)
    context = collect_repo_context(repo_root)
    metadata = read_text(pathlib.Path(args.metadata_file), 15_000) if args.metadata_file else "{}"
    repo = os.environ.get("GITHUB_REPOSITORY", "unknown/repository")
    run_id = args.run_id or os.environ.get("RUN_ID", "unknown")

    system_instruction = (
        "You are a senior DevOps incident responder. Analyze GitHub Actions, pytest, Docker, "
        "app.py, YAML, and deployment failures. Produce RCA and remediation plans only; never suggest "
        "direct production changes without human approval."
    )
    prompt = build_analysis_prompt(run_id, repo, metadata, logs, context)
    ai_text = call_gemini(prompt, system_instruction)
    if not ai_text or ai_text.startswith("AI model unavailable") or ai_text.startswith("AI model call failed"):
        fallback = fallback_analysis(run_id, logs, context)
        if ai_text:
            fallback += f"\n\n## AI provider status\n\n{sanitize(ai_text)}\n"
        rca = fallback
    else:
        rca = ai_text

    header = f"# AI Agent RCA - GitHub Actions Failure\n\nRun ID: {run_id}\nRepository: {repo}\n\n"
    if not rca.lstrip().startswith("#"):
        rca = header + rca

    rca_path = output_dir / "ai-agent-rca.md"
    rca_path.write_text(sanitize(rca).rstrip() + "\n", encoding="utf-8")

    issue_body = f"""{rca_path.read_text(encoding='utf-8')}

---

## Approval gate

The AI agent has **not changed code** yet.

If you approve the agent to prepare a fix, comment exactly:

```text
/ai-agent approve
```

The remediation workflow will then:

1. create a new branch,
2. apply an allow-listed app/CI/CD/Docker/test remediation only,
3. run Python, pytest, Docker build, and container `/health` validation,
4. retry remediation up to the configured limit if validation fails,
5. open a pull request for human review if validation passes.

It will **not** merge the pull request and will **not** deploy production automatically.
"""
    (output_dir / "issue.md").write_text(issue_body, encoding="utf-8")
    (output_dir / "logs-sanitized.txt").write_text(logs, encoding="utf-8")
    return 0


def extract_json(text: str) -> dict:
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start >= 0 and end > start:
            return json.loads(cleaned[start : end + 1])
        raise


def validate_path(path: str) -> str:
    normalized = path.replace("\\", "/").strip().lstrip("/")
    if ".." in pathlib.PurePosixPath(normalized).parts:
        raise ValueError(f"Refusing path traversal: {path}")
    if normalized not in ALLOWED_REMEDIATION_PATHS:
        raise ValueError(
            f"Refusing to edit non-allow-listed path: {normalized}. "
            f"Allowed: {', '.join(ALLOWED_REMEDIATION_PATHS)}"
        )
    return normalized


def build_remediation_prompt(issue_body: str, logs: str, context: str, attempt: int, validation_feedback: str) -> str:
    return truncate_prompt(
        f"Remediation attempt: {attempt}",
        "Human-approved RCA issue body:\n" + issue_body,
        "Original sanitized failed-run logs:\n```\n" + logs + "\n```",
        "Validation feedback from previous remediation attempt, if any:\n```\n" + (validation_feedback or "No previous validation feedback.") + "\n```",
        "Current repository files after any prior remediation attempts:\n" + context,
        textwrap.dedent(
            f"""
            A repository maintainer approved remediation. Propose a minimal safe patch for this repo.

            Return STRICT JSON only, no Markdown fences, in this shape:
            {{
              "summary": "one paragraph summary",
              "risk": "low|medium|high plus explanation",
              "validation": ["validation command or check", "..."],
              "files": [
                {{"path": "relative/path", "action": "write|delete", "reason": "why this file changes", "content": "complete new file content when action is write"}}
              ]
            }}

            Constraints:
            - You may edit only these files: {', '.join(ALLOWED_REMEDIATION_PATHS)}.
            - Use action="write" when replacing/creating a file and include complete replacement content.
            - Use action="delete" only for allow-listed files clearly proven to be the root cause.
            - Never hard-code secrets.
            - Never remove human approval gates.
            - Never weaken pytest, Docker build, or /health validation.
            - Do not add dependencies unless necessary and justified.
            - Prefer the smallest patch that passes validation.
            - If the problem is only an external secret/infrastructure issue, return an empty files list and explain the manual fix.

            Project invariants:
            - Do not blindly assume a fixed port for every project.
            - Discover the app/container port from Dockerfile EXPOSE, Gunicorn bind, app.py app.run, PORT defaults, and existing valid health checks.
            - Docker/gunicorn should listen on the discovered app/container port.
            - Docker port mapping should be DISCOVERED_PORT:DISCOVERED_PORT unless there is explicit project evidence otherwise.
            - Health check URL should use the discovered app/container port and `/health`.
            - deploy.yml docker-publish must depend on both validate and pytest.
            - Production deployment must stay behind the production environment approval.
            - Docker publishing must stay behind the docker-publish environment approval.

            Known training/demo remediation:
            - If pytest fails because tests/test_training_failure.py contains "Training pytest failure for AI RCA demo" and assert False, delete tests/test_training_failure.py.
            """
        ).strip(),
    )


def fallback_remediation(output_dir: pathlib.Path) -> dict:
    plan = {
        "summary": "No AI model response was available. Deterministic remediations, if any, were attempted. Manual remediation may be required based on the RCA artifact.",
        "risk": "low - only deterministic allow-listed remediations can be applied without the AI provider",
        "validation": ["Review the RCA artifact", "Fix secrets/configuration manually if required", "Rerun the failed workflow"],
        "files": [],
    }
    (output_dir / "ai-provider-status.txt").write_text(
        "AI provider unavailable or not configured; deterministic remediation only.\n",
        encoding="utf-8",
    )
    return plan


def manual_only_failure(logs: str, issue_body: str) -> bool:
    text = f"{logs}\n{issue_body}".lower()
    return any(hint in text for hint in MANUAL_ONLY_HINTS)


def replace_if_changed(path: pathlib.Path, new_content: str, reason: str) -> list[tuple[str, str]]:
    old = read_raw_text(path) if path.exists() else ""
    if old != new_content:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(new_content.rstrip() + "\n", encoding="utf-8")
        rel = str(path).replace(str(ROOT_DEFAULT), "").lstrip("/")
        return [(rel, reason)]
    return []


def valid_port(value: str | int) -> bool:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return False
    return 1 <= port <= 65535


def choose_port(candidates: list[tuple[str, str, int]]) -> tuple[str, list[tuple[str, str, int]]]:
    """Choose the most likely application/container port from evidence.

    Each candidate is (source, port, weight). Stronger sources such as
    Gunicorn bind, Dockerfile EXPOSE, and app.py app.run are weighted higher
    than deploy.yml because deploy.yml is often the file being remediated.
    """
    scores: dict[str, int] = {}
    for _source, port, weight in candidates:
        if valid_port(port):
            scores[port] = scores.get(port, 0) + weight
    if not scores:
        return PROJECT_PORT, candidates
    # Highest score wins; if tied, prefer the existing project default when present,
    # otherwise choose the numerically highest stable app-like port.
    best_score = max(scores.values())
    tied = [port for port, score in scores.items() if score == best_score]
    if PROJECT_PORT in tied:
        return PROJECT_PORT, candidates
    return sorted(tied, key=lambda item: int(item))[-1], candidates


def infer_app_port(repo_root: pathlib.Path) -> tuple[str, list[tuple[str, str, int]]]:
    """Infer the app/container port from repository evidence.

    This makes v3.2 generic: it does not blindly assume 5000. It checks
    Dockerfile, app.py, and workflow context to discover the port the
    application actually uses, then deployment health checks and port mappings
    are aligned to that port.
    """
    candidates: list[tuple[str, str, int]] = []

    dockerfile = read_raw_text(repo_root / "Dockerfile")
    for match in re.finditer(r"(?im)^\s*EXPOSE\s+(\d{2,5})\b", dockerfile):
        candidates.append(("Dockerfile EXPOSE", match.group(1), 5))
    for match in re.finditer(r"(?:0\.0\.0\.0|127\.0\.0\.1|localhost):(\d{2,5})", dockerfile):
        candidates.append(("Dockerfile bind/health", match.group(1), 5))

    app_py = read_raw_text(repo_root / "app.py")
    for match in re.finditer(r"app\.run\([^\n)]*port\s*=\s*(\d{2,5})", app_py, re.S):
        candidates.append(("app.py app.run", match.group(1), 5))
    for match in re.finditer(r"PORT[^\n]{0,80}?(\d{2,5})", app_py):
        candidates.append(("app.py PORT default", match.group(1), 3))

    deploy_yml = read_raw_text(repo_root / ".github/workflows/deploy.yml")
    # Workflow ports are weaker evidence because deploy.yml is commonly the broken file.
    for match in re.finditer(r"(?:localhost|127\.0\.0\.1):(\d{2,5})/health", deploy_yml):
        candidates.append(("deploy.yml health check", match.group(1), 1))
    for match in re.finditer(r"(?:-p|--publish)\s+(\d{2,5}):(\d{2,5})", deploy_yml):
        host_port, container_port = match.groups()
        candidates.append(("deploy.yml docker container port", container_port, 2))
        candidates.append(("deploy.yml docker host port", host_port, 1))

    return choose_port(candidates)


def port_evidence_summary(candidates: list[tuple[str, str, int]]) -> str:
    if not candidates:
        return "No explicit port evidence found; using fallback project port."
    return "; ".join(f"{source}={port}(w={weight})" for source, port, weight in candidates)


def load_yaml_file(path: pathlib.Path) -> tuple[object | None, str | None]:
    try:
        import yaml  # type: ignore
    except Exception as exc:
        return None, f"PyYAML is required for workflow validation but is not installed: {exc}"

    try:
        return yaml.safe_load(read_raw_text(path)), None
    except Exception as exc:
        return None, str(exc)


def job_needs_include(job: dict, required: set[str]) -> bool:
    needs = job.get("needs")
    if isinstance(needs, str):
        actual = {needs}
    elif isinstance(needs, list):
        actual = {str(item) for item in needs}
    else:
        actual = set()
    return required.issubset(actual)


def workflow_environment_name(job: dict) -> str:
    env = job.get("environment")
    if isinstance(env, str):
        return env
    if isinstance(env, dict):
        return str(env.get("name", ""))
    return ""


def collect_project_health(repo_root: pathlib.Path) -> dict:
    """Run static project health checks for the OpsPilot AI project.

    The doctor is intentionally deterministic. It does not call the AI model.
    It is used by the v4 guardian workflow and by the remediation validation
    loop to catch broken YAML, corrupted secret expressions, missing gates,
    wrong health-check ports, and tracked runtime artifacts.
    """
    errors: list[str] = []
    warnings: list[str] = []
    info: list[str] = []

    required_files = [
        "app.py",
        "Dockerfile",
        "requirements.txt",
        "requirements-dev.txt",
        "tests/test_app.py",
        ".github/workflows/deploy.yml",
        ".github/workflows/ai-agent-rca.yml",
        ".github/workflows/ai-agent-remediate.yml",
        ".github/workflows/ai-agent-guardian.yml",
        "scripts/ai_ci_agent.py",
        ".gitignore",
        ".dockerignore",
    ]
    for rel in required_files:
        if not (repo_root / rel).exists():
            errors.append(f"Missing required file: {rel}")

    masked = scan_masked_placeholders(repo_root)
    for rel in masked:
        errors.append(f"Masked placeholder found in repository output file: {rel}")

    ok, git_ls = run_process(["git", "ls-files", "ai-agent-input", "ai-agent-output"], repo_root, timeout=60)
    if ok:
        tracked_lines = [
            line for line in git_ls.splitlines()
            if line.strip()
            and not line.startswith("$ ")
            and not line.startswith("(exit code:")
        ]
        if tracked_lines:
            tracked = "\n".join(tracked_lines)
            errors.append(f"AI runtime artifacts are tracked in Git and must be removed:\n{tracked}")

    gitignore = read_raw_text(repo_root / ".gitignore")
    for ignored in ["ai-agent-input/", "ai-agent-output/", ".pytest_cache/", ".env"]:
        if ignored not in gitignore:
            warnings.append(f".gitignore should include {ignored}")

    req = read_raw_text(repo_root / "requirements.txt").lower()
    for dep in ["flask", "google-generativeai", "gunicorn"]:
        if dep not in req:
            errors.append(f"requirements.txt missing expected runtime dependency: {dep}")

    req_dev = read_raw_text(repo_root / "requirements-dev.txt").lower()
    if "-r requirements.txt" not in req_dev:
        errors.append("requirements-dev.txt should include -r requirements.txt")
    if "pytest" not in req_dev:
        errors.append("requirements-dev.txt missing pytest")
    if "pyyaml" not in req_dev and "yaml" not in req_dev:
        warnings.append("requirements-dev.txt should include PyYAML for guardian workflow YAML validation")

    for py_file in ["app.py", "scripts/ai_ci_agent.py", "tests/test_app.py"]:
        if (repo_root / py_file).exists():
            ok, output = run_process([sys.executable, "-m", "py_compile", py_file], repo_root, timeout=120)
            if not ok:
                errors.append(f"Python compile failed for {py_file}:\n{output}")

    app_py = read_raw_text(repo_root / "app.py")
    if "Flask(__name__)" not in app_py:
        errors.append("app.py does not appear to create a Flask app with Flask(__name__)")
    if "/health" not in app_py:
        errors.append("app.py does not appear to define a /health endpoint")
    if "GEMINI_API_KEY" not in app_py:
        warnings.append("app.py should read GEMINI_API_KEY from environment")

    inferred_port, port_candidates = infer_app_port(repo_root)
    info.append(f"Discovered app/container port: {inferred_port}")
    info.append(f"Port evidence: {port_evidence_summary(port_candidates)}")

    strong = [(source, port) for source, port, weight in port_candidates if weight >= 5 and valid_port(port)]
    strong_ports = {port for _source, port in strong}
    if len(strong_ports) > 1:
        errors.append(f"Conflicting strong app port evidence: {strong}")

    dockerfile = read_raw_text(repo_root / "Dockerfile")
    if "HEALTHCHECK" not in dockerfile:
        warnings.append("Dockerfile should include a HEALTHCHECK")
    if "gunicorn" not in dockerfile.lower():
        warnings.append("Dockerfile should run the app with gunicorn for production")
    if f"EXPOSE {inferred_port}" not in dockerfile and "EXPOSE" in dockerfile:
        errors.append(f"Dockerfile EXPOSE does not match discovered app port {inferred_port}")
    wrong_docker_health_ports = [p for p in re.findall(r"(?:localhost|127\.0\.0\.1):(\d{2,5})/health", dockerfile) if p != inferred_port]
    if wrong_docker_health_ports:
        errors.append(f"Dockerfile health check ports do not match discovered port {inferred_port}: {wrong_docker_health_ports}")

    for workflow in sorted((repo_root / ".github/workflows").glob("*.yml")) + sorted((repo_root / ".github/workflows").glob("*.yaml")):
        data, err = load_yaml_file(workflow)
        rel = workflow.relative_to(repo_root)
        if err:
            errors.append(f"Workflow YAML syntax error in {rel}: {err}")
        elif not isinstance(data, dict):
            errors.append(f"Workflow {rel} is not a YAML mapping")

    deploy_path = repo_root / ".github/workflows/deploy.yml"
    deploy_data, deploy_err = load_yaml_file(deploy_path)
    deploy_text = read_raw_text(deploy_path)
    if deploy_err:
        errors.append(f"deploy.yml could not be parsed: {deploy_err}")
    elif isinstance(deploy_data, dict):
        jobs = deploy_data.get("jobs", {})
        if not isinstance(jobs, dict):
            errors.append("deploy.yml jobs section is missing or invalid")
            jobs = {}
        for job_name in ["validate", "pytest", "docker-publish", "deploy"]:
            if job_name not in jobs:
                errors.append(f"deploy.yml missing required job: {job_name}")
        docker_publish = jobs.get("docker-publish", {}) if isinstance(jobs.get("docker-publish", {}), dict) else {}
        if docker_publish and not job_needs_include(docker_publish, {"validate", "pytest"}):
            errors.append("docker-publish job must need both validate and pytest")
        if docker_publish and workflow_environment_name(docker_publish) != "docker-publish":
            errors.append("docker-publish job must use environment: docker-publish")
        deploy_job = jobs.get("deploy", {}) if isinstance(jobs.get("deploy", {}), dict) else {}
        if deploy_job and workflow_environment_name(deploy_job) != "production":
            errors.append("deploy job must use environment: production")

    wrong_health_ports = [p for p in re.findall(r"(?:localhost|127\.0\.0\.1):(\d{2,5})/health", deploy_text) if p != inferred_port]
    if wrong_health_ports:
        errors.append(f"deploy.yml health check ports do not match discovered app port {inferred_port}: {wrong_health_ports}")

    wrong_mappings: list[str] = []
    for host_port, container_port in re.findall(r"(?:-p|--publish)\s+(\d{2,5}):(\d{2,5})", deploy_text):
        if host_port != inferred_port or container_port != inferred_port:
            wrong_mappings.append(f"{host_port}:{container_port}")
    if wrong_mappings:
        errors.append(f"deploy.yml Docker port mappings do not match discovered app port {inferred_port}: {wrong_mappings}")

    if "***MASKED***" in deploy_text:
        errors.append("deploy.yml contains ***MASKED*** placeholder text")
    for expr in ["${{ secrets.DOCKERHUB_USERNAME }}", "${{ secrets.DOCKERHUB_TOKEN }}", "${{ secrets.EC2_HOST }}", "${{ secrets.EC2_SSH_KEY }}", "${{ secrets.GEMINI_API_KEY }}"]:
        if expr not in deploy_text:
            warnings.append(f"deploy.yml does not contain expected GitHub expression: {expr}")

    remediate_text = read_raw_text(repo_root / ".github/workflows/ai-agent-remediate.yml")
    if "secrets.AI_AGENT_GITHUB_TOKEN" not in remediate_text:
        errors.append("ai-agent-remediate.yml should use secrets.AI_AGENT_GITHUB_TOKEN for checkout/push/PR when workflow files may be changed")
    if "AI_AGENT_MAX_ATTEMPTS" not in remediate_text:
        warnings.append("ai-agent-remediate.yml should expose AI_AGENT_MAX_ATTEMPTS for retry configuration")

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "info": info,
        "inferred_port": inferred_port,
        "port_evidence": port_candidates,
    }


def write_project_health_artifact(report: dict, output_dir: pathlib.Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "project-health.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    lines = [
        "# OpsPilot AI Project Health Report",
        "",
        f"Generated: {now_utc()}",
        f"Status: {'PASS' if report.get('ok') else 'FAIL'}",
        f"Discovered app/container port: {report.get('inferred_port')}",
        "",
        "## Errors",
        "",
    ]
    errors = report.get("errors", [])
    if errors:
        lines.extend(f"- {item}" for item in errors)
    else:
        lines.append("- None")
    lines.extend(["", "## Warnings", ""])
    warnings = report.get("warnings", [])
    if warnings:
        lines.extend(f"- {item}" for item in warnings)
    else:
        lines.append("- None")
    lines.extend(["", "## Info", ""])
    info = report.get("info", [])
    if info:
        lines.extend(f"- {item}" for item in info)
    else:
        lines.append("- None")
    lines.extend([
        "",
        "## Human approval",
        "",
        "If this report was attached to an RCA/Guardian issue and you want the AI agent to prepare a fix, comment exactly:",
        "",
        "```text",
        "/ai-agent approve",
        "```",
    ])
    (output_dir / "project-health.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def doctor(args: argparse.Namespace) -> int:
    repo_root = pathlib.Path(args.repo_root).resolve()
    output_dir = pathlib.Path(args.output_dir).resolve()
    report = collect_project_health(repo_root)
    write_project_health_artifact(report, output_dir)
    print((output_dir / "project-health.md").read_text(encoding="utf-8"))
    return 0 if report.get("ok") else 1


def apply_safe_deterministic_remediations(repo_root: pathlib.Path, logs: str, issue_body: str, validation_feedback: str = "") -> list[tuple[str, str]]:
    """Apply narrowly-scoped deterministic fixes for known safe repository failures."""
    changed: list[tuple[str, str]] = []

    # 1. Remove the exact intentional pytest demo failure.
    training_test = repo_root / "tests/test_training_failure.py"
    training_content = read_raw_text(training_test)
    if (
        training_test.exists()
        and "Training pytest failure for AI RCA demo" in training_content
        and "assert False" in training_content
    ):
        training_test.unlink()
        changed.append((
            "tests/test_training_failure.py",
            "Removed the intentional training pytest failure so pytest can pass.",
        ))

    inferred_port, port_candidates = infer_app_port(repo_root)

    # 2. Restore dynamic app port in deploy.yml when a demo mistake changes
    # health checks or Docker port mappings to the wrong port.
    deploy_yml = repo_root / ".github/workflows/deploy.yml"
    if deploy_yml.exists():
        content = read_raw_text(deploy_yml)
        updated = content
        # v3.1 recovery: restore GitHub expressions if an older remediation wrote
        # sanitized placeholders back into deploy.yml.
        updated = updated.replace("password: ***MASKED*** secrets.DOCKERHUB_TOKEN }}", "password: ${{ secrets.DOCKERHUB_TOKEN }}")
        updated = updated.replace("DOCKERHUB_TOKEN: ***MASKED*** secrets.DOCKERHUB_TOKEN }}", "DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}")
        updated = updated.replace("GEMINI_API_KEY: ***MASKED*** secrets.GEMINI_API_KEY }}", "GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}")
        updated = updated.replace("-e GEMINI_API_KEY=***MASKED*** \\", "-e GEMINI_API_KEY=dummy-for-healthcheck \\")
        updated = re.sub(r"(localhost|127\.0\.0\.1):(\d{2,5})/health", rf"\1:{inferred_port}/health", updated)
        updated = re.sub(r"(?<=-p )\d{2,5}:\d{2,5}\b", f"{inferred_port}:{inferred_port}", updated)
        updated = re.sub(r"(?<=--publish )\d{2,5}:\d{2,5}\b", f"{inferred_port}:{inferred_port}", updated)
        if updated != content:
            deploy_yml.write_text(updated if updated.endswith("\n") else updated + "\n", encoding="utf-8")
            changed.append((
                ".github/workflows/deploy.yml",
                f"Aligned deployment health checks and Docker port mappings to discovered app port {inferred_port}. Evidence: {port_evidence_summary(port_candidates)}",
            ))

    # 3. Restore the discovered app port in Dockerfile when it is clearly inconsistent.
    dockerfile = repo_root / "Dockerfile"
    if dockerfile.exists():
        content = read_raw_text(dockerfile)
        updated = content
        updated = re.sub(r"(?im)^[ \t]*EXPOSE\s+\d{2,5}\b", f"EXPOSE {inferred_port}", updated)
        updated = re.sub(r"(0\.0\.0\.0|127\.0\.0\.1|localhost):\d{2,5}", rf"\1:{inferred_port}", updated)
        updated = re.sub(r"(localhost|127\.0\.0\.1):\d{2,5}/health", rf"\1:{inferred_port}/health", updated)
        if updated != content:
            dockerfile.write_text(updated if updated.endswith("\n") else updated + "\n", encoding="utf-8")
            changed.append((
                "Dockerfile",
                f"Aligned Dockerfile exposed/bound port to discovered app port {inferred_port}.",
            ))

    # 4. Restore app.run port in app.py if the development server port is inconsistent.
    app_py = repo_root / "app.py"
    if app_py.exists():
        content = read_raw_text(app_py)
        updated = content
        updated = re.sub(r"app\.run\(([^\n)]*?)port\s*=\s*\d{2,5}([^\n)]*?)\)", rf"app.run(\1port={inferred_port}\2)", updated, flags=re.S)
        if updated != content:
            app_py.write_text(updated if updated.endswith("\n") else updated + "\n", encoding="utf-8")
            changed.append((
                "app.py",
                f"Aligned Flask development server port to discovered app port {inferred_port}.",
            ))

    return changed


def apply_ai_plan(repo_root: pathlib.Path, plan: dict) -> list[tuple[str, str]]:
    changed: list[tuple[str, str]] = []
    for file_spec in plan.get("files", []):
        path = validate_path(str(file_spec.get("path", "")))
        action = str(file_spec.get("action", "write")).lower().strip()
        reason = str(file_spec.get("reason", "No reason provided"))
        target = repo_root / path

        if action == "delete":
            if target.exists():
                target.unlink()
                changed.append((path, reason))
            continue

        if action != "write":
            raise ValueError(f"Unsupported action for {path}: {action}")

        content = file_spec.get("content")
        if not isinstance(content, str):
            raise ValueError(f"File {path} has no string content")
        if path not in MASKED_SCAN_EXCLUDED_PATHS and contains_masked_placeholder(content):
            raise ValueError(
                f"Refusing to write masked placeholder into {path}. "
                "The AI response appears to contain sanitized secret placeholders; it must preserve GitHub expressions such as ${{ secrets.NAME }}."
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        existing = read_raw_text(target) if target.exists() else None
        if existing != content:
            target.write_text(content.rstrip() + "\n", encoding="utf-8")
            changed.append((path, reason))
    return changed


def run_process(args: list[str], cwd: pathlib.Path, timeout: int = 180) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            args,
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        output = result.stdout or ""
        return result.returncode == 0, f"$ {' '.join(args)}\n{output}\n(exit code: {result.returncode})"
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return False, f"$ {' '.join(args)}\nTIMEOUT after {timeout}s\n{output}"
    except Exception as exc:
        return False, f"$ {' '.join(args)}\nERROR: {exc}"


def docker_health_check(container_name: str, port: str, timeout_seconds: int = 30) -> tuple[bool, str]:
    deadline = time.time() + timeout_seconds
    last_error = ""
    url = f"http://127.0.0.1:{port}/health"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                body = response.read().decode("utf-8", errors="replace")
                if response.status == 200:
                    return True, f"Health check passed on {url}: HTTP {response.status} {body}"
        except Exception as exc:  # pragma: no cover - timing/network dependent
            last_error = str(exc)
            time.sleep(2)
    return False, f"Health check failed for {container_name} on {url}: {last_error}"


def run_validation_suite(repo_root: pathlib.Path, output_dir: pathlib.Path, attempt: int, skip_docker: bool = False) -> dict:
    logs: list[str] = [f"# Validation attempt {attempt} at {now_utc()}"]

    masked_findings = scan_masked_placeholders(repo_root)
    if masked_findings:
        text = "Masked placeholder guard failed. These files contain ***MASKED*** placeholders and will not be committed:\n" + "\n".join(masked_findings)
        logs.append("\n## Masked placeholder guard\n" + text)
        full_log = "\n".join(logs)
        (output_dir / f"validation-attempt-{attempt}.log").write_text(full_log, encoding="utf-8")
        return {"ok": False, "failed_at": "Masked placeholder guard", "log": full_log}

    health_report = collect_project_health(repo_root)
    write_project_health_artifact(health_report, output_dir / f"project-health-attempt-{attempt}")
    logs.append("\n## Project health doctor\n" + json.dumps(health_report, indent=2))
    if not health_report.get("ok"):
        full_log = "\n".join(logs)
        (output_dir / f"validation-attempt-{attempt}.log").write_text(full_log, encoding="utf-8")
        return {"ok": False, "failed_at": "Project health doctor", "log": full_log}

    checks = [
        ("Python compile", [sys.executable, "-m", "py_compile", "app.py", "scripts/ai_ci_agent.py"]),
        ("Pytest", ["pytest", "-q"]),
    ]
    for name, command in checks:
        ok, output = run_process(command, repo_root, timeout=180)
        logs.append(f"\n## {name}\n{output}")
        if not ok:
            text = "\n".join(logs)
            (output_dir / f"validation-attempt-{attempt}.log").write_text(text, encoding="utf-8")
            return {"ok": False, "failed_at": name, "log": text}

    if skip_docker or os.environ.get("AI_AGENT_SKIP_DOCKER_VALIDATION", "").lower() in {"1", "true", "yes"}:
        logs.append("\n## Docker validation\nSkipped by configuration.")
        text = "\n".join(logs)
        (output_dir / f"validation-attempt-{attempt}.log").write_text(text, encoding="utf-8")
        return {"ok": True, "failed_at": "", "log": text}

    if not shutil.which("docker"):
        logs.append("\n## Docker validation\nDocker executable was not found on the runner.")
        text = "\n".join(logs)
        (output_dir / f"validation-attempt-{attempt}.log").write_text(text, encoding="utf-8")
        return {"ok": False, "failed_at": "Docker available", "log": text}

    validation_port, port_candidates = infer_app_port(repo_root)
    logs.append(f"\n## Dynamic port discovery\nUsing app port {validation_port}. Evidence: {port_evidence_summary(port_candidates)}")

    image = f"local/devops-ai-assistant:ai-agent-validation-{os.environ.get('GITHUB_RUN_ID', 'local')}-{attempt}"
    container = f"ai-agent-validation-{os.environ.get('GITHUB_RUN_ID', 'local')}-{attempt}"

    run_process(["docker", "rm", "-f", container], repo_root, timeout=60)

    ok, output = run_process(["docker", "build", "-t", image, "."], repo_root, timeout=600)
    logs.append(f"\n## Docker build\n{output}")
    if not ok:
        text = "\n".join(logs)
        (output_dir / f"validation-attempt-{attempt}.log").write_text(text, encoding="utf-8")
        return {"ok": False, "failed_at": "Docker build", "log": text}

    ok, output = run_process([
        "docker", "run", "-d",
        "-p", f"{validation_port}:{validation_port}",
        "-e", "GEMINI_API_KEY=dummy-for-healthcheck",
        "--name", container,
        image,
    ], repo_root, timeout=120)
    logs.append(f"\n## Docker run\n{output}")
    if not ok:
        text = "\n".join(logs)
        (output_dir / f"validation-attempt-{attempt}.log").write_text(text, encoding="utf-8")
        return {"ok": False, "failed_at": "Docker run", "log": text}

    try:
        ok, health_output = docker_health_check(container, validation_port)
        logs.append(f"\n## Container /health smoke test\n{health_output}")
        docker_logs_ok, docker_logs = run_process(["docker", "logs", container], repo_root, timeout=60)
        logs.append(f"\n## Container logs\n{docker_logs}")
        if not ok:
            text = "\n".join(logs)
            (output_dir / f"validation-attempt-{attempt}.log").write_text(text, encoding="utf-8")
            return {"ok": False, "failed_at": "Container health", "log": text}
    finally:
        cleanup_ok, cleanup_output = run_process(["docker", "rm", "-f", container], repo_root, timeout=60)
        logs.append(f"\n## Docker cleanup\n{cleanup_output}")

    text = "\n".join(logs)
    (output_dir / f"validation-attempt-{attempt}.log").write_text(text, encoding="utf-8")
    return {"ok": True, "failed_at": "", "log": text}


def dedupe_changes(changes: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []
    for path, reason in changes:
        key = (path, reason)
        if key not in seen:
            seen.add(key)
            result.append((path, reason))
    return result


def write_remediation_artifacts(output_dir: pathlib.Path, plan: dict, changes: list[tuple[str, str]], attempts: list[dict], success: bool) -> None:
    plan_md = [
        "# AI Agent Remediation Plan",
        "",
        f"Generated: {now_utc()}",
        f"Status: {'success' if success else 'failed'}",
        "",
        "## Summary",
        "",
        str(plan.get("summary", "No summary provided.")),
        "",
        "## Risk",
        "",
        str(plan.get("risk", "Not specified.")),
        "",
        "## Changed files",
        "",
    ]
    if changes:
        for path, reason in dedupe_changes(changes):
            plan_md.append(f"- `{path}` — {reason}")
    else:
        plan_md.append("- No repository files were changed by the agent.")

    plan_md.extend(["", "## Validation attempts", ""])
    for attempt in attempts:
        status = "passed" if attempt.get("ok") else "failed"
        failed_at = attempt.get("failed_at") or "none"
        plan_md.append(f"- Attempt {attempt.get('attempt')}: {status}; failed_at={failed_at}")

    plan_md.extend(["", "## Validation requested by AI", ""])
    for item in plan.get("validation", []):
        plan_md.append(f"- {item}")

    if not success:
        plan_md.extend([
            "",
            "## Manual follow-up required",
            "",
            "The agent could not produce a validated fix within the configured retry limit. Review validation logs in this artifact and fix manually or approve a more specific remediation.",
        ])

    (output_dir / "remediation-plan.md").write_text("\n".join(plan_md).rstrip() + "\n", encoding="utf-8")
    (output_dir / "remediation-plan.json").write_text(json.dumps({"plan": plan, "changes": changes, "attempts": attempts, "success": success}, indent=2), encoding="utf-8")


def remediate(args: argparse.Namespace) -> int:
    repo_root = pathlib.Path(args.repo_root).resolve()
    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    issue_body = read_text(pathlib.Path(args.issue_body), 30_000) if args.issue_body else ""
    logs = collect_logs(pathlib.Path(args.logs_dir) if args.logs_dir else None, pathlib.Path(args.logs_file) if args.logs_file else None)

    max_attempts = max(1, int(args.max_attempts or os.environ.get("AI_AGENT_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS)))
    skip_docker = bool(args.skip_docker_validation)
    all_changes: list[tuple[str, str]] = []
    attempts: list[dict] = []
    latest_plan: dict = {
        "summary": "Deterministic and AI remediation v4.2 with validation retry loop.",
        "risk": "medium - modifies allow-listed CI/CD/app/test files only after human approval",
        "validation": ["python -m py_compile", "pytest -q", "docker build", "container /health smoke test"],
        "files": [],
    }
    validation_feedback = ""

    if manual_only_failure(logs, issue_body):
        (output_dir / "manual-only-detected.txt").write_text(
            "The logs contain hints of a secrets, credentials, permissions, quota, or infrastructure issue. The agent will still run deterministic/code remediation if applicable, but manual configuration may be required.\n",
            encoding="utf-8",
        )

    for attempt in range(1, max_attempts + 1):
        print(f"=== AI remediation v4 attempt {attempt}/{max_attempts} ===")

        deterministic_changes = apply_safe_deterministic_remediations(repo_root, logs, issue_body, validation_feedback)
        all_changes.extend(deterministic_changes)
        for path, reason in deterministic_changes:
            print(f"Deterministic remediation: {path}: {reason}")

        context = collect_repo_context(repo_root)
        system_instruction = (
            "You are a cautious DevOps code remediation agent. You only propose minimal, "
            "reviewable patches for GitHub Actions, Docker, pytest, app.py, and deployment automation after "
            "human approval. Return valid JSON only."
        )
        prompt = build_remediation_prompt(issue_body, logs, context, attempt, validation_feedback)
        ai_text = call_gemini(prompt, system_instruction)

        if not ai_text or ai_text.startswith("AI model unavailable") or ai_text.startswith("AI model call failed"):
            latest_plan = fallback_remediation(output_dir)
            if ai_text:
                with (output_dir / f"ai-provider-status-attempt-{attempt}.txt").open("w", encoding="utf-8") as f:
                    f.write(sanitize(ai_text) + "\n")
        else:
            try:
                latest_plan = extract_json(ai_text)
                (output_dir / f"ai-plan-attempt-{attempt}.json").write_text(json.dumps(latest_plan, indent=2), encoding="utf-8")
                ai_changes = apply_ai_plan(repo_root, latest_plan)
                all_changes.extend(ai_changes)
                for path, reason in ai_changes:
                    print(f"AI remediation: {path}: {reason}")
            except Exception as exc:
                (output_dir / f"raw-ai-response-attempt-{attempt}.txt").write_text(sanitize(ai_text), encoding="utf-8")
                validation_feedback = f"AI response was not valid/applicable JSON: {exc}"
                attempts.append({"attempt": attempt, "ok": False, "failed_at": "AI JSON/apply", "log": validation_feedback})
                continue

        # Re-run deterministic remediation after the AI plan in case the AI missed a known safe issue.
        post_ai_changes = apply_safe_deterministic_remediations(repo_root, logs, issue_body, validation_feedback)
        all_changes.extend(post_ai_changes)
        for path, reason in post_ai_changes:
            print(f"Post-AI deterministic remediation: {path}: {reason}")

        validation = run_validation_suite(repo_root, output_dir, attempt, skip_docker=skip_docker)
        validation["attempt"] = attempt
        attempts.append(validation)
        validation_feedback = validation.get("log", "")[-MAX_LOG_CHARS:]

        if validation.get("ok"):
            print(f"Validation passed on attempt {attempt}")
            write_remediation_artifacts(output_dir, latest_plan, all_changes, attempts, success=True)
            print(f"Changed {len(dedupe_changes(all_changes))} files")
            for path, reason in dedupe_changes(all_changes):
                print(f"- {path}: {reason}")
            return 0

        print(f"Validation failed on attempt {attempt}: {validation.get('failed_at')}")

    write_remediation_artifacts(output_dir, latest_plan, all_changes, attempts, success=False)
    print(f"AI remediation v4 failed after {max_attempts} attempts")
    return 1


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--repo-root", default=str(ROOT_DEFAULT))
    common.add_argument("--output-dir", default="ai-agent-output")
    common.add_argument("--logs-dir")
    common.add_argument("--logs-file")

    p_analyze = sub.add_parser("analyze", parents=[common])
    p_analyze.add_argument("--run-id", default=os.environ.get("RUN_ID", "unknown"))
    p_analyze.add_argument("--metadata-file")
    p_analyze.set_defaults(func=analyze)

    p_remediate = sub.add_parser("remediate", parents=[common])
    p_remediate.add_argument("--issue-body", required=True)
    p_remediate.add_argument("--max-attempts", type=int, default=None)
    p_remediate.add_argument("--skip-docker-validation", action="store_true")
    p_remediate.set_defaults(func=remediate)

    p_doctor = sub.add_parser("doctor", parents=[common])
    p_doctor.set_defaults(func=doctor)

    args = parser.parse_args(list(argv) if argv is not None else None)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
