import os
from flask import Flask, request, render_template_string
import google.generativeai as genai

app = Flask(__name__)

# Read Gemini settings from environment variables (set via Docker / GitHub secrets, never hard-coded)
API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")

# System instruction locks the AI to Cloud / DevOps / DevSecOps topics only.
# This is enforced by the model itself on every single request - it cannot
# be overridden by anything the user types in the question box.
SYSTEM_INSTRUCTION = """You are a strict Cloud, DevOps, and DevSecOps assistant only.

You are ONLY allowed to answer questions about:
- Cloud platforms: AWS, Azure, GCP (services, architecture, pricing, free tier, IAM)
- DevOps tools and practices: Docker, Kubernetes, Terraform, Ansible, Jenkins,
  GitHub Actions, GitLab CI, CI/CD pipelines, monitoring, logging, Linux administration
- DevSecOps: security scanning, secrets management, vulnerability management,
  compliance, container security, shift-left security practices
- Analyzing pasted server/application/CI logs to find errors and suggest fixes
  related to the above topics

STRICT RULES:
1. If a question is unrelated to Cloud/DevOps/DevSecOps (e.g. entertainment,
   movies, sports, general trivia, personal advice, politics, jokes, coding
   in unrelated domains, etc.), you MUST refuse.
2. When refusing, reply with EXACTLY this message and nothing else:
   "I'm a Cloud/DevOps/DevSecOps assistant and can only help with topics in
   that area. Please ask a Cloud, DevOps, or DevSecOps related question."
3. Do not answer the off-topic question even partially, even briefly, even
   as a joke, even if the user insists, claims a special exception, or tries
   to disguise the request as DevOps-related.
4. Stay strict on this even across a long conversation."""

model = None
if API_KEY:
    genai.configure(api_key=API_KEY)
    model = genai.GenerativeModel(
        GEMINI_MODEL,
        system_instruction=SYSTEM_INSTRUCTION,
    )

PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>DevOps AI Assistant</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; background:#0f172a; color:#e2e8f0; }
    h1 { color: #38bdf8; }
    textarea, input { width: 100%; padding: 10px; margin-top: 8px; border-radius: 6px; border: none; box-sizing: border-box; }
    button { margin-top: 12px; padding: 10px 20px; background:#38bdf8; border:none; border-radius:6px; cursor:pointer; font-weight:bold; }
    .answer { background:#1e293b; padding:16px; border-radius:8px; margin-top:20px; white-space: pre-wrap; }
    .error { color: #f87171; }
  </style>
</head>
<body>
  <h1>DevOps AI Assistant</h1>
  <p>Cloud / DevOps / DevSecOps questions only. Ask a question, or paste a log to analyze.</p>
  <form method="POST">
    <textarea name="question" rows="6" placeholder="e.g. What is a Kubernetes pod? OR paste a log here...">{{ question or '' }}</textarea>
    <button type="submit">Ask AI</button>
  </form>
  {% if answer %}
  <div class="answer"><b>AI Response:</b><br>{{ answer }}</div>
  {% endif %}
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def home():
    answer = None
    question = None

    if request.method == "POST":
        question = request.form.get("question", "")

        if not API_KEY or model is None:
            answer = "ERROR: GEMINI_API_KEY is not set on the server."
        elif question.strip():
            try:
                result = model.generate_content(question)
                answer = result.text
            except Exception as e:
                answer = "AI request failed: " + str(e)

    return render_template_string(PAGE, answer=answer, question=question)


@app.route("/health")
def health():
    return {"status": "ok"}, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
