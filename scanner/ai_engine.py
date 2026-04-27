"""
AI-QANet Scoring Engine (Mock Implementation)
----------------------------------------------
This module simulates the AI-QANet inference pipeline described in the seminar report.
In a production deployment, this would load the actual trained INT8-quantized model
and run inference on the submitted code diff.

For the dashboard demo, it uses a deterministic scoring algorithm that mirrors
the statistical behaviour of the real model (F1=92%, mean latency=235ms).
"""

import re
import random
import time
import hashlib
from dataclasses import dataclass
from typing import List, Tuple


# ── Vulnerability Pattern Library (mirrors CWE taxonomy) ─────────────────────
VULNERABILITY_PATTERNS = [
    {
        "cwe": "CWE-89", "severity": "critical", "cvss": 9.8,
        "title": "SQL Injection",
        "patterns": [r"execute\s*\(.*%.*\)", r"cursor\.execute\([^?]", r"format.*SELECT", r"f['\"].*SELECT"],
        "remediation": "Use parameterised queries or an ORM. Never interpolate user input into SQL strings.",
    },
    {
        "cwe": "CWE-79", "severity": "high", "cvss": 7.5,
        "title": "Cross-Site Scripting (XSS)",
        "patterns": [r"mark_safe\(", r"innerHTML\s*=", r"dangerouslySetInnerHTML", r"\.html\(.*request"],
        "remediation": "Escape all user-supplied input before rendering. Use Django's template auto-escaping.",
    },
    {
        "cwe": "CWE-798", "severity": "critical", "cvss": 9.1,
        "title": "Use of Hard-Coded Credentials",
        "patterns": [r"password\s*=\s*['\"][^'\"]{4,}", r"secret\s*=\s*['\"]", r"api_key\s*=\s*['\"]", r"AWS_SECRET"],
        "remediation": "Store credentials in environment variables or a secrets manager. Never hard-code.",
    },
    {
        "cwe": "CWE-327", "severity": "high", "cvss": 7.4,
        "title": "Use of Broken or Risky Cryptographic Algorithm",
        "patterns": [r"hashlib\.md5\(", r"hashlib\.sha1\(", r"DES\.", r"RC4"],
        "remediation": "Replace MD5/SHA-1/DES with SHA-256, SHA-3, or AES-256-GCM.",
    },
    {
        "cwe": "CWE-78", "severity": "critical", "cvss": 9.4,
        "title": "OS Command Injection",
        "patterns": [r"os\.system\(", r"subprocess\.call\(.*shell=True", r"eval\(.*input", r"exec\(.*request"],
        "remediation": "Use subprocess with a list of arguments and shell=False. Validate all inputs.",
    },
    {
        "cwe": "CWE-22", "severity": "high", "cvss": 8.1,
        "title": "Path Traversal",
        "patterns": [r"\.\./", r"open\(.*request", r"os\.path\.join.*request"],
        "remediation": "Validate and sanitise file paths. Use os.path.realpath() and check against allowed base dir.",
    },
    {
        "cwe": "CWE-502", "severity": "high", "cvss": 7.8,
        "title": "Deserialization of Untrusted Data",
        "patterns": [r"pickle\.loads\(", r"yaml\.load\([^L]", r"marshal\.loads"],
        "remediation": "Use safe deserializers: yaml.safe_load(), json.loads(). Avoid pickle on untrusted data.",
    },
    {
        "cwe": "CWE-918", "severity": "medium", "cvss": 5.5,
        "title": "Server-Side Request Forgery (SSRF)",
        "patterns": [r"requests\.get\(.*request\.", r"urllib.*request\.GET", r"httpx\.get\(.*input"],
        "remediation": "Validate and whitelist allowed URLs/IPs before making server-side HTTP requests.",
    },
    {
        "cwe": "CWE-400", "severity": "medium", "cvss": 5.3,
        "title": "Uncontrolled Resource Consumption",
        "patterns": [r"while True:", r"for.*range\(.*\*.*\)", r"\.read\(\)(?!\s*\[:)"],
        "remediation": "Add rate limiting, pagination, and read size limits. Use streaming for large responses.",
    },
    {
        "cwe": "CWE-209", "severity": "low", "cvss": 3.7,
        "title": "Information Exposure Through Error Messages",
        "patterns": [r"traceback\.print_exc\(\)", r"DEBUG\s*=\s*True", r"except.*pass"],
        "remediation": "Log detailed errors server-side. Return generic error messages to clients.",
    },
]

# ── Risk class mapping ────────────────────────────────────────────────────────
def _severity_to_risk(max_cvss: float) -> Tuple[str, float]:
    if max_cvss >= 9.0:
        return "critical", min(max_cvss / 10.0 + random.uniform(0, 0.05), 1.0)
    elif max_cvss >= 7.0:
        return "high", max_cvss / 10.0 + random.uniform(-0.05, 0.05)
    elif max_cvss >= 4.0:
        return "medium", max_cvss / 10.0 + random.uniform(-0.05, 0.05)
    else:
        return "low", random.uniform(0.05, 0.25)


@dataclass
class ScanResult:
    risk_level: str
    risk_score: float
    inference_ms: int
    precision: float
    recall: float
    f1_score: float
    vulnerabilities: List[dict]
    passed: bool


def scan_code(code_diff: str, filename: str = "submitted_code.py") -> ScanResult:
    """
    Main entry point for the AI-QANet scoring engine.
    Simulates distilled Transformer inference with diff-aware attention.
    """
    start = time.time()

    # Simulate model tokenization + forward pass latency
    # (matches AI-QANet's 235ms mean on 2vCPU runner)
    token_count = len(code_diff.split()) 
    base_latency = 120 + min(token_count * 0.8, 350)
    time.sleep(base_latency / 1000.0)

    found_vulns = []
    lines = code_diff.split('\n')

    for pattern_info in VULNERABILITY_PATTERNS:
        for line_no, line in enumerate(lines, 1):
            for pattern in pattern_info["patterns"]:
                if re.search(pattern, line, re.IGNORECASE):
                    found_vulns.append({
                        "cwe_id": pattern_info["cwe"],
                        "cve_id": "",
                        "title": pattern_info["title"],
                        "description": f"Detected {pattern_info['title']} pattern on line {line_no}: {line.strip()[:120]}",
                        "severity": pattern_info["severity"],
                        "file_path": filename,
                        "line_number": line_no,
                        "cvss_score": pattern_info["cvss"],
                        "remediation": pattern_info["remediation"],
                    })
                    break  # one finding per pattern per line

    # Deduplicate by CWE
    seen_cwes = set()
    unique_vulns = []
    for v in found_vulns:
        if v["cwe_id"] not in seen_cwes:
            seen_cwes.add(v["cwe_id"])
            unique_vulns.append(v)

    elapsed_ms = int((time.time() - start) * 1000)

    # Determine risk level from findings
    if unique_vulns:
        max_cvss = max(v["cvss_score"] for v in unique_vulns)
        risk_level, risk_score = _severity_to_risk(max_cvss)
    else:
        risk_level = "low"
        risk_score = random.uniform(0.02, 0.15)

    # Simulate model metrics (calibrated to match paper results: F1=92%)
    seed = int(hashlib.md5(code_diff.encode()).hexdigest(), 16) % 1000
    rng = random.Random(seed)
    precision = round(rng.uniform(0.89, 0.96), 3)
    recall = round(rng.uniform(0.88, 0.95), 3)
    f1 = round(2 * precision * recall / (precision + recall), 3)

    passed = risk_level in ("low", "medium")

    return ScanResult(
        risk_level=risk_level,
        risk_score=round(risk_score, 4),
        inference_ms=elapsed_ms,
        precision=precision,
        recall=recall,
        f1_score=f1,
        vulnerabilities=unique_vulns,
        passed=passed,
    )


# ── Sample code snippets for mock pipeline runs ───────────────────────────────
SAMPLE_DIFFS = [
    # Critical - SQL injection
    """+def get_user(username):
+    query = f"SELECT * FROM users WHERE name = '{username}'"
+    cursor.execute(query)
+    return cursor.fetchone()""",

    # High - hardcoded credential
    """+AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
+DB_PASSWORD = 'Sup3rS3cret!'
+api_key = 'sk-1234567890abcdef'""",

    # High - OS command injection
    """+def run_report(report_name):
+    os.system(f'generate_report.sh {report_name}')
+    result = subprocess.call(f'ls {report_name}', shell=True)""",

    # Medium - SSRF
    """+def fetch_url(url):
+    response = requests.get(request.GET['target_url'])
+    return response.content""",

    # Low - clean commit
    """+def calculate_total(items):
+    return sum(item.price for item in items if item.is_active)
+
+def paginate(queryset, page_size=20):
+    return queryset[:page_size]""",

    # High - XSS
    """+def render_comment(comment_text):
+    return mark_safe(f'<div class="comment">{comment_text}</div>')""",

    # High - insecure crypto
    """+import hashlib
+def hash_password(password):
+    return hashlib.md5(password.encode()).hexdigest()""",

    # Critical - deserialization
    """+import pickle
+def load_session(data):
+    return pickle.loads(data)  # loads user-supplied bytes""",

    # Low - refactor
    """+class UserSerializer:
+    def to_representation(self, user):
+        return {'id': user.id, 'email': user.email, 'role': user.role}""",

    # Medium - resource consumption
    """+def read_file(path):
+    with open(path) as f:
+        content = f.read()  # no size limit
+    return content""",
]

COMMIT_AUTHORS = ["alice@corp.com", "bob@corp.com", "carol@corp.com", "dave@corp.com", "eve@corp.com"]
COMMIT_MESSAGES = [
    "feat: add user authentication endpoint",
    "fix: resolve null pointer in payment module",
    "refactor: extract database helper functions",
    "chore: update dependency versions",
    "feat: implement report generation API",
    "fix: correct session handling logic",
    "feat: add admin dashboard endpoint",
    "refactor: improve password storage mechanism",
    "fix: patch critical security vulnerability",
    "feat: add file upload functionality",
]
