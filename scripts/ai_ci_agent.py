#!/usr/bin/env python3
"""AI CI/CD remediation assistant for GitHub Actions and Docker.

This script has two modes:

1. analyze   - summarize a failed GitHub Actions run and produce an RCA artifact.
2. remediate - after human approval, propose and apply a minimal patch on a branch.

The script is intentionally constrained:
- It reads only repository files needed for CI/CD and Docker diagnosis.
- It writes only allow-listed files during remediation.
- It creates artifacts/PR content; it never merges to main or deploys production by itself.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import sys
import textwrap
from typing import Iterable

ROOT_DEFAULT = pathlib.Path.cwd()
MAX_LOG_CHARS = 60_000
MAX_FILE_CHARS = 18_000
MAX_PROMPT_CHARS = 95_000

def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


ALLOWED_REMEDIATION_PATHS = (
    ".github/workflows/deploy.yml",
    ".github/workflows/ai-agent-rca.yml",
    ".github/workflows/ai-agent-remediate.yml",
    "Dockerfile",
    ".dockerignore",
    ".gitignore",
    "requirements.txt",
    "requirements-dev.txt",
    "app.py",
    "tests/test_app.py",
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
    (re.compile(r"(?i)(api[_-]?key|token|password|secret|private[_-]?key)(\s*[:=]\s*)([^\s'\"]+)"), r"\1\2***MASKED***"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "***MASKED_PRIVATE_KEY***"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "***MASKED_AWS_ACCESS_KEY***"),
    (re.compile(r"(?i)gh[pousr]_[A-Za-z0-9_]{20,}"), "***MASKED_GITHUB_TOKEN***"),
]


def sanitize(text: str) -> str:
    """Best-effort masking before sending data to an LLM or artifact."""
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def read_text(path: pathlib.Path, limit: int | None = None) -> str:
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    data = sanitize(data)
    if limit and len(data) > limit:
        return data[:limit] + f"\n\n...[truncated to {limit} characters]...\n"
    return data


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
    # Preserve the end of logs because failures usually appear near the end.
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
    if "docker build" in lower or "buildx" in lower:
        likely.append("Docker build/buildx failure. Review Dockerfile, requirements install output, and image build context.")
    if "curl" in lower and "/health" in lower:
        likely.append("Post-deploy health check failed. Container may not have started, app may be unhealthy, or port/security-group may be wrong.")
    if "permission denied" in lower and ("ssh" in lower or "ec2" in lower):
        likely.append("EC2 SSH deployment failed. Check EC2_SSH_KEY, username, host, and instance SSH access.")
    if not likely:
        likely.append("The exact failure needs the complete GitHub Actions logs. Review the failed step name and final 100 lines.")

    return f"""# AI Agent RCA Artifact

Generated: {now_utc()}
Run ID: {run_id}

## Executive summary

The AI provider was not available, so this is a deterministic fallback RCA. The failed run logs were still collected and inspected for common CI/CD and Docker failure patterns.

## Most likely root cause

{chr(10).join(f'- {item}' for item in likely)}

## Recommended solution options

1. Fix missing or invalid GitHub Actions secrets and rerun the failed workflow.
2. Split CI/CD into validate, Docker publish, and deploy jobs so Docker publishing and production deployment can require human environment approval.
3. Add an AI RCA workflow that creates this artifact automatically on pipeline failure.
4. Add a human-approved remediation workflow that opens a pull request instead of pushing directly to `main`.

## Validation plan

- Run Python syntax/dependency checks.
- Run pytest before Docker publishing and deployment.
- Build the Docker image locally in GitHub Actions before publishing.
- Start the container in CI and call `/health`.
- After merge, approve the `docker-publish` environment, then approve the `production` environment.

## Rollback plan

- Redeploy the previous Docker image tag from Docker Hub.
- If the new container is unhealthy, stop it and restart the last known-good image.

## Human approval

Comment `/ai-agent approve` on the generated RCA issue to allow the remediation workflow to create a pull request. Review and merge the PR manually. Production deploy remains gated by GitHub Environment approvals.
"""


def build_analysis_prompt(run_id: str, repo: str, metadata: str, logs: str, context: str) -> str:
    return truncate_prompt(
        f"Repository: {repo}\nFailed workflow run ID: {run_id}\nCurrent UTC time: {now_utc()}",
        "Workflow metadata:\n```json\n" + metadata + "\n```",
        "Failed logs:\n```\n" + logs + "\n```",
        "Repository CI/CD and Docker context:\n" + context,
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
            7. Validation plan for GitHub Actions, Docker build, container health check, and deployment
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
        "You are a senior DevOps incident responder. Analyze GitHub Actions, Docker, "
        "and deployment failures. Produce RCA and remediation plans only; never suggest "
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
2. apply an allow-listed CI/CD/Docker remediation only,
3. run Python, pytest, and Docker validation,
4. open a pull request for human review.

It will **not** merge the pull request and will **not** deploy production automatically. Docker publishing and production deployment are gated by GitHub Environments.
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


def build_remediation_prompt(issue_body: str, logs: str, context: str) -> str:
    return truncate_prompt(
        "Human-approved RCA issue body:\n" + issue_body,
        "Available sanitized failed-run logs:\n```\n" + logs + "\n```",
        "Current repository files:\n" + context,
        textwrap.dedent(
            f"""
            A repository maintainer approved remediation. Propose a minimal safe patch.

            Return STRICT JSON only, no Markdown fences, in this shape:
            {{
              "summary": "one paragraph summary",
              "risk": "low|medium|high plus explanation",
              "validation": ["validation command or check", "..."],
              "files": [
                {{"path": "relative/path", "reason": "why this file changes", "content": "complete new file content"}}
              ]
            }}

            Constraints:
            - You may edit only these files: {', '.join(ALLOWED_REMEDIATION_PATHS)}.
            - Return complete replacement content for each changed file.
            - Prefer the smallest change that fixes the RCA.
            - Do not remove human approval gates.
            - Do not hard-code secrets.
            - Do not add dependencies unless necessary.
            - Preserve pytest, Docker build, and /health validation.
            - If no safe code change is possible (for example, only a missing secret), return an empty files list and explain the manual fix in summary.
            """
        ).strip(),
    )


def fallback_remediation(output_dir: pathlib.Path) -> dict:
    plan = {
        "summary": "No AI model response was available. No automatic code changes were applied. Manual remediation is required based on the RCA artifact.",
        "risk": "low - no repository files were changed",
        "validation": ["Review the RCA artifact", "Fix secrets/configuration manually", "Rerun the failed workflow"],
        "files": [],
    }
    (output_dir / "remediation-plan.md").write_text(
        "# AI Agent Remediation Plan\n\nNo automatic patch was produced because the AI provider was unavailable.\n",
        encoding="utf-8",
    )
    return plan


def remediate(args: argparse.Namespace) -> int:
    repo_root = pathlib.Path(args.repo_root).resolve()
    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    issue_body = read_text(pathlib.Path(args.issue_body), 30_000) if args.issue_body else ""
    logs = collect_logs(pathlib.Path(args.logs_dir) if args.logs_dir else None, pathlib.Path(args.logs_file) if args.logs_file else None)
    context = collect_repo_context(repo_root)

    system_instruction = (
        "You are a cautious DevOps code remediation agent. You only propose minimal, "
        "reviewable patches for GitHub Actions, Docker, and deployment automation after "
        "human approval. Return valid JSON only."
    )
    prompt = build_remediation_prompt(issue_body, logs, context)
    ai_text = call_gemini(prompt, system_instruction)

    if not ai_text or ai_text.startswith("AI model unavailable") or ai_text.startswith("AI model call failed"):
        plan = fallback_remediation(output_dir)
        if ai_text:
            with (output_dir / "ai-provider-status.txt").open("w", encoding="utf-8") as f:
                f.write(sanitize(ai_text) + "\n")
    else:
        try:
            plan = extract_json(ai_text)
        except Exception as exc:
            (output_dir / "raw-ai-response.txt").write_text(sanitize(ai_text), encoding="utf-8")
            raise SystemExit(f"AI response was not valid JSON: {exc}") from exc

    changed: list[tuple[str, str]] = []
    for file_spec in plan.get("files", []):
        path = validate_path(str(file_spec.get("path", "")))
        content = file_spec.get("content")
        if not isinstance(content, str):
            raise ValueError(f"File {path} has no string content")
        target = repo_root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        existing = read_text(target) if target.exists() else None
        if existing != content:
            target.write_text(content.rstrip() + "\n", encoding="utf-8")
            changed.append((path, str(file_spec.get("reason", "No reason provided"))))

    plan_md = [
        "# AI Agent Remediation Plan",
        "",
        f"Generated: {now_utc()}",
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
    if changed:
        for path, reason in changed:
            plan_md.append(f"- `{path}` — {reason}")
    else:
        plan_md.append("- No repository files were changed by the agent.")
    plan_md.extend(["", "## Validation", ""])
    for item in plan.get("validation", []):
        plan_md.append(f"- {item}")
    (output_dir / "remediation-plan.md").write_text("\n".join(plan_md).rstrip() + "\n", encoding="utf-8")
    (output_dir / "remediation-plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")

    print(f"Changed {len(changed)} files")
    for path, reason in changed:
        print(f"- {path}: {reason}")
    return 0


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
    p_remediate.set_defaults(func=remediate)

    args = parser.parse_args(list(argv) if argv is not None else None)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
