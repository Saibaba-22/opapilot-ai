# AI CI/CD Remediation Agent Runbook

This project now has a human-approved AI remediation loop for GitHub Actions, Docker, and EC2 deployment failures.

## What the agent does

1. The normal `Build and Deploy AI DevOps Assistant` workflow validates the Flask app, runs pytest, and builds/smoke-tests the Docker image.
2. If that workflow fails, `AI Agent - RCA on CI/CD Failure` runs automatically.
3. The RCA workflow collects the failed workflow metadata/logs, reviews the CI/CD and Docker files, and uploads an artifact named `ai-agent-rca-run-<run_id>`.
4. The RCA workflow also opens a GitHub issue with:
   - failure evidence,
   - likely root cause,
   - solution options,
   - recommended fix plan,
   - validation/rollback plan,
   - approval instructions.
5. A maintainer reviews the issue. If the team approves the agent to prepare a fix, comment:

   ```text
   /ai-agent approve
   ```

6. `AI Agent - Human Approved Remediation` then runs the v4 remediation loop: it applies only allow-listed CI/CD/Docker/app/test/workflow-guardrail changes, validates project health, Python compile, pytest, Docker build, and container `/health`, retries with validation feedback when needed, and opens a pull request only after validation passes.
7. A human reviews and merges the pull request.
8. After merge to `main`, Docker publish and production deploy are still gated by GitHub Environment approvals.

## What the agent never does

- It never merges directly to `main`.
- It never deploys production without GitHub Environment approval.
- It never bypasses Docker publishing approval.
- It never hard-codes secrets.
- It only edits files listed in `scripts/ai_ci_agent.py` under `ALLOWED_REMEDIATION_PATHS`.

## Required GitHub secrets

Configure these in **Settings → Secrets and variables → Actions → Secrets**:

| Secret | Purpose |
|---|---|
| `DOCKERHUB_USERNAME` | Docker Hub username used to push and pull images. |
| `DOCKERHUB_TOKEN` | Docker Hub access token. Use a token, not your Docker Hub password. |
| `EC2_HOST` | EC2 public DNS name or IP address. |
| `EC2_SSH_KEY` | Private SSH key for the `ubuntu` user on the EC2 host. |
| `GEMINI_API_KEY` | Gemini key used by the Flask app. The AI agent also falls back to this if `AI_AGENT_API_KEY` is not set. |
| `AI_AGENT_API_KEY` | Optional but recommended separate Gemini key for CI/CD RCA and remediation. |
| `AI_AGENT_GITHUB_TOKEN` | GitHub token/PAT with repo and workflow permissions, required for AI remediation PRs that update `.github/workflows/*.yml`. |

## Optional GitHub variable

Configure under **Settings → Secrets and variables → Actions → Variables**:

| Variable | Default | Purpose |
|---|---|---|
| `AI_AGENT_MODEL` | `gemini-1.5-flash` | Gemini model used by the RCA/remediation agent. |
| `AI_AGENT_MAX_ATTEMPTS` | `3` | Maximum remediation attempts before the v4 workflow stops and asks for manual review. |

## Required GitHub Environments

Create these under **Settings → Environments**.

### `docker-publish`

Recommended settings:

- Required reviewers: at least one repo maintainer.
- Deployment branches: `main` only.

This makes Docker Hub publishing wait for human approval after CI validation passes.

### `production`

Recommended settings:

- Required reviewers: at least one repo maintainer.
- Deployment branches: `main` only.

This makes the EC2 deployment wait for human approval after the Docker image is published.

## Normal operational flow

```mermaid
flowchart TD
  A[Push or merge to main] --> B[Validate Python + Docker build + /health smoke test]
  A --> T[Run pytest test suite]
  B -->|success| C[Wait for docker-publish environment approval]
  T -->|success| C
  C --> D[Push immutable SHA tag and latest to Docker Hub]
  D --> E[Wait for production environment approval]
  E --> F[Deploy SHA-tagged image to EC2]
  F --> G[Verify /health]
  B -->|failure| H[AI RCA workflow]
  T -->|failure| H
  C -->|failure| H
  D -->|failure| H
  E -->|failure| H
  F -->|failure| H
  H --> I[RCA artifact + GitHub issue]
  I --> J{Human approves?}
  J -->|comment /ai-agent approve| K[AI remediation workflow]
  K --> L[Branch + validation + PR]
  L --> M[Human code review and merge]
  M --> A
```

## Manual RCA run

If you want the agent to analyze an older failed run:

1. Open **Actions → AI Agent - RCA on CI/CD Failure**.
2. Click **Run workflow**.
3. Enter the failed run ID.
4. Review the uploaded artifact and generated issue.

## Manual remediation run

If the issue comment trigger is not desired:

1. Open **Actions → AI Agent - Human Approved Remediation**.
2. Click **Run workflow**.
3. Enter the RCA issue number and optional failed run ID.
4. Review the generated PR.

## Validations performed before Docker publish/deploy

- Python dependencies install.
- `python -m py_compile app.py`.
- Pytest dependencies install from `requirements-dev.txt`.
- `pytest -q` must pass in the separate `pytest` job.
- Docker image build with Buildx.
- Container run with a dummy `GEMINI_API_KEY`.
- `/health` endpoint smoke test.

The `docker-publish` job depends on both `validate` and `pytest`, so Docker publishing and EC2 deployment cannot start unless pytest passes.

## Enhanced AI Remediation v4 and Project Health Guardian

The human-approved remediation workflow has a validation retry loop. After `/ai-agent approve`, it can safely remediate allow-listed issues in `app.py`, `.github/workflows/deploy.yml`, workflow guardrails, Dockerfile, requirements, and tests.

The v4 workflow validates every remediation attempt with:

- Project Health Doctor checks
- `python -m py_compile app.py scripts/ai_ci_agent.py`
- `pytest -q`
- `docker build`
- a running container `/health` smoke test on the dynamically discovered app/container port

If validation fails, the validation output is fed into the next remediation attempt. The default maximum is 3 attempts and can be configured with the repository variable `AI_AGENT_MAX_ATTEMPTS`.

### Project Health Guardian

v4 adds `.github/workflows/ai-agent-guardian.yml`. This separate workflow runs on pushes to `main` and can still detect repository policy/YAML problems even when the main deploy workflow is broken or invalid.

The guardian checks:

- workflow YAML syntax;
- required project files;
- no `***MASKED***` placeholders in output files;
- no tracked `ai-agent-input/` or `ai-agent-output/` runtime artifacts;
- `app.py` has Flask and `/health`;
- Dockerfile and deploy workflow align with the discovered app/container port;
- `docker-publish` depends on both `validate` and `pytest`;
- Docker publishing uses the `docker-publish` environment;
- production deploy uses the `production` environment;
- remediation workflow uses `AI_AGENT_GITHUB_TOKEN` for workflow-file PRs.

If the guardian fails, it uploads a project health artifact and opens an issue with `/ai-agent approve` instructions.

### Safe deterministic remediations

Known deterministic safe remediations include:

- removing the exact intentional training failure file `tests/test_training_failure.py` when it contains `Training pytest failure for AI RCA demo` and `assert False`;
- dynamically discovering the app/container port from Dockerfile `EXPOSE`, Gunicorn bind values, `app.py` `app.run(... port=...)`, `PORT` defaults, and workflow evidence;
- aligning wrong deploy health check ports such as `localhost:50/health` to the discovered app port;
- aligning Docker port mappings to `DISCOVERED_PORT:DISCOVERED_PORT` when project evidence supports it;
- restoring GitHub workflow expressions if an older remediation accidentally wrote sanitized placeholders such as `***MASKED*** secrets.DOCKERHUB_TOKEN }}`.

### Masked placeholder protection

- GitHub expressions like `${{ secrets.DOCKERHUB_TOKEN }}` are preserved when repository files are sent to the AI prompt.
- The agent refuses to write allow-listed files if the AI response contains `***MASKED***` placeholders.
- The validation suite fails before PR creation if any allow-listed output file contains masked placeholders.

The agent still will not fix secrets or infrastructure directly. For expired Docker tokens, wrong EC2 SSH keys, blocked security groups, quota/rate-limit problems, or unavailable cloud resources, it creates artifacts explaining the required manual action.

## Rollback

The deployment uses immutable Docker tags based on `github.sha`. If the latest deployment is unhealthy:

1. Find the previous successful image SHA tag in Docker Hub or GitHub Actions.
2. SSH to the EC2 host.
3. Pull and run the previous tag:

   ```bash
   docker pull DOCKERHUB_USERNAME/devops-ai-assistant:<previous_sha>
   docker rm -f ai-assistant || true
   docker run -d -p 5000:5000 \
     -e GEMINI_API_KEY="$GEMINI_API_KEY" \
     --name ai-assistant \
     --restart unless-stopped \
     DOCKERHUB_USERNAME/devops-ai-assistant:<previous_sha>
   curl -fsS http://localhost:5000/health
   ```
