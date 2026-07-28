# DevOps AI Assistant

A beginner Docker + AWS + AI DevOps project. Full step-by-step instructions are in
`DevOps_AI_Assistant_Beginner_Guide.docx`. This README is just a quick command reference.

## Local run (no Docker)

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
export GEMINI_API_KEY=your_key_here   # Windows (cmd): set GEMINI_API_KEY=your_key_here
python app.py
```

Visit http://localhost:5000

## Run tests locally

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Local run (Docker)

```bash
docker build -t devops-ai-assistant .
docker run -d -p 5000:5000 -e GEMINI_API_KEY=your_key_here --name ai-assistant devops-ai-assistant
```

## Push to Docker Hub

```bash
docker login
docker tag devops-ai-assistant YOUR_DOCKERHUB_USERNAME/devops-ai-assistant:latest
docker push YOUR_DOCKERHUB_USERNAME/devops-ai-assistant:latest
```

## Files in this project

| File | Purpose |
|---|---|
| `app.py` | Flask app + Gemini AI agent |
| `requirements.txt` | Runtime Python dependencies |
| `requirements-dev.txt` | Local/CI test dependencies, including pytest |
| `tests/test_app.py` | Pytest tests for Flask routes and configuration behavior |
| `Dockerfile` | Container build instructions |
| `.dockerignore` | Files excluded from the Docker image |
| `.gitignore` | Files excluded from Git |
| `.env.example` | Template for your local `GEMINI_API_KEY` |
| `.github/workflows/deploy.yml` | CI/CD pipeline: validate + pytest → human-approved Docker publish → human-approved EC2 deploy |
| `.github/workflows/ai-agent-rca.yml` | AI agent workflow that creates an RCA artifact/issue when CI/CD fails |
| `.github/workflows/ai-agent-remediate.yml` | Human-approved AI remediation workflow that opens a PR |
| `scripts/ai_ci_agent.py` | Constrained RCA/remediation agent used by GitHub Actions |
| `docs/AI_AGENT_RUNBOOK.md` | Setup and operations guide for the AI CI/CD remediation loop |

## AI CI/CD remediation agent

When the main CI/CD workflow fails, the AI agent collects logs, reviews GitHub Actions/Docker context, creates an RCA artifact, and opens an issue. It does **not** fix code immediately.

A human must approve remediation by commenting this on the RCA issue:

```text
/ai-agent approve
```

After approval, the agent creates a branch, applies an allow-listed fix, validates Python + pytest + Docker + `/health`, and opens a pull request. A human still reviews/merges the PR. Docker publishing and production deployment are gated by GitHub Environments named `docker-publish` and `production`.

See `docs/AI_AGENT_RUNBOOK.md` for setup details.

## Required GitHub Actions secrets

Set these under **Settings → Secrets and variables → Actions**:

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`
- `EC2_HOST`
- `EC2_SSH_KEY`
- `GEMINI_API_KEY`
- `AI_AGENT_API_KEY` (optional but recommended; if omitted, the agent uses `GEMINI_API_KEY`)

## Required GitHub Environments

Create these under **Settings → Environments** and add required reviewers:

- `docker-publish`
- `production`
