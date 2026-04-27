# AI-QANet: CI/CD Security Dashboard
Link of ZeroGPT Report: https://drive.google.com/file/d/1GpZFHKco2LTBd1zvAxURD7P-5m8CQaby/view?usp=sharing
AI-Driven Automated Quality Assurance and Vulnerability Assessment in Enterprise CI/CD Pipelines.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run migrations
python manage.py makemigrations scanner
python manage.py migrate

# 3. Create superuser (optional, for /admin)
python manage.py createsuperuser

# 4. Start server
python manage.py runserver
```

## Usage

1. Open http://127.0.0.1:8000/
2. Click **Load Demo Data** to populate 60 historical pipeline runs
3. Click **New Scan** to submit code and get an AI risk assessment
4. Click any commit hash to see the full vulnerability report

## Pages

| URL | Description |
|-----|-------------|
| `/` | Main dashboard — stats, charts, recent runs |
| `/scan/` | Submit code diff for AI scanning |
| `/run/<id>/` | Full vulnerability report for a single run |
| `/pipeline/<id>/` | All runs for a specific pipeline |
| `/seed/` | Load 60 mock historical runs |
| `/webhook/` | GitHub-compatible webhook endpoint (POST) |
| `/api/stats/` | JSON stats API |
| `/admin/` | Django admin panel |

## Webhook Integration (GitHub Actions)

Add this step to your `.github/workflows/ci.yml`:

```yaml
- name: AI-QANet Security Scan
  run: |
    curl -X POST http://your-server/webhook/ \
      -H "Content-Type: application/json" \
      -d '{
        "repository": {"full_name": "${{ github.repository }}"},
        "ref": "${{ github.ref }}",
        "commits": [{
          "id": "${{ github.sha }}",
          "message": "${{ github.event.head_commit.message }}",
          "author": {"email": "${{ github.event.head_commit.author.email }}"},
          "added": [],
          "modified": []
        }]
      }'
```

## Architecture

```
cicd_dashboard/
├── cicd_dashboard/          # Django project config
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── scanner/                 # Main app
│   ├── ai_engine.py         # AI-QANet scoring engine (core intelligence)
│   ├── models.py            # Pipeline, PipelineRun, Vulnerability
│   ├── views.py             # Dashboard, scan, webhook, API views
│   ├── urls.py              # URL routing
│   └── templates/scanner/
│       ├── dashboard.html   # Main dashboard with charts
│       ├── run_detail.html  # Per-run vulnerability report
│       ├── scan_submit.html # Code submission form
│       └── pipeline_detail.html
├── manage.py
└── requirements.txt
```

## AI Engine Notes

`scanner/ai_engine.py` implements the AI-QANet scoring pipeline:
- **Pattern detection**: Regex-based matching against 10 CWE vulnerability classes
- **Risk scoring**: CVSS-calibrated risk level assignment (Critical/High/Medium/Low)
- **Latency simulation**: Mirrors AI-QANet's 235ms mean inference on 2vCPU runners
- **Model metrics**: Precision/Recall/F1 seeded deterministically per code diff

In production, replace `scan_code()` with the actual INT8-quantized AI-QANet model inference using ONNX Runtime or HuggingFace Transformers.
