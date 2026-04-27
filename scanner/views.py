import json
import random
import hashlib
from datetime import datetime, timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.utils import timezone
from django.db.models import Avg, Count, Q

from .models import Pipeline, PipelineRun, Vulnerability
from .ai_engine import scan_code, SAMPLE_DIFFS, COMMIT_AUTHORS, COMMIT_MESSAGES


# ── Dashboard ─────────────────────────────────────────────────────────────────
def dashboard(request):
    pipelines = Pipeline.objects.all()
    runs = PipelineRun.objects.select_related('pipeline').order_by('-created_at')[:50]

    total_runs = PipelineRun.objects.count()
    critical_count = PipelineRun.objects.filter(risk_level='critical').count()
    high_count = PipelineRun.objects.filter(risk_level='high').count()
    passed_count = PipelineRun.objects.filter(status='passed').count()
    avg_latency = PipelineRun.objects.aggregate(avg=Avg('inference_ms'))['avg'] or 0
    avg_f1 = PipelineRun.objects.aggregate(avg=Avg('f1_score'))['avg'] or 0

    # Chart data: last 14 days
    chart_labels = []
    chart_critical = []
    chart_high = []
    chart_low = []
    for i in range(13, -1, -1):
        day = timezone.now() - timedelta(days=i)
        label = day.strftime('%b %d')
        chart_labels.append(label)
        day_runs = PipelineRun.objects.filter(
            created_at__date=day.date()
        )
        chart_critical.append(day_runs.filter(risk_level='critical').count())
        chart_high.append(day_runs.filter(risk_level='high').count())
        chart_low.append(day_runs.filter(risk_level__in=['low', 'medium']).count())

    # Vulnerability distribution
    vuln_counts = {
        'critical': PipelineRun.objects.filter(risk_level='critical').count(),
        'high': PipelineRun.objects.filter(risk_level='high').count(),
        'medium': PipelineRun.objects.filter(risk_level='medium').count(),
        'low': PipelineRun.objects.filter(risk_level='low').count(),
    }

    context = {
        'pipelines': pipelines,
        'recent_runs': runs[:15],
        'total_runs': total_runs,
        'critical_count': critical_count,
        'high_count': high_count,
        'passed_count': passed_count,
        'pass_rate': round(passed_count / total_runs * 100, 1) if total_runs else 0,
        'avg_latency': round(avg_latency),
        'avg_f1': round(avg_f1 * 100, 1),
        'chart_labels': json.dumps(chart_labels),
        'chart_critical': json.dumps(chart_critical),
        'chart_high': json.dumps(chart_high),
        'chart_low': json.dumps(chart_low),
        'vuln_counts': json.dumps(vuln_counts),
    }
    return render(request, 'scanner/dashboard.html', context)


# ── Pipeline detail ───────────────────────────────────────────────────────────
def pipeline_detail(request, pk):
    pipeline = get_object_or_404(Pipeline, pk=pk)
    runs = pipeline.runs.order_by('-created_at')
    context = {'pipeline': pipeline, 'runs': runs}
    return render(request, 'scanner/pipeline_detail.html', context)


# ── Run detail ────────────────────────────────────────────────────────────────
def run_detail(request, pk):
    run = get_object_or_404(PipelineRun.objects.select_related('pipeline'), pk=pk)
    vulns = run.vuln_set.order_by('-cvss_score')
    context = {'run': run, 'vulns': vulns}
    return render(request, 'scanner/run_detail.html', context)


# ── Manual scan submission ────────────────────────────────────────────────────
def scan_submit(request):
    pipelines = Pipeline.objects.all()
    if request.method == 'POST':
        code = request.POST.get('code_diff', '')
        filename = request.POST.get('filename', 'submitted.py')
        pipeline_id = request.POST.get('pipeline')
        commit_msg = request.POST.get('commit_message', 'Manual scan submission')
        author = request.POST.get('author', 'developer@company.com')

        if not code.strip():
            return render(request, 'scanner/scan_submit.html', {
                'pipelines': pipelines,
                'error': 'Please provide code to scan.'
            })

        pipeline = get_object_or_404(Pipeline, pk=pipeline_id) if pipeline_id else pipelines.first()
        if not pipeline:
            pipeline = Pipeline.objects.create(name="Default", repository="local/manual")

        result = scan_code(code, filename)

        commit_hash = hashlib.sha1(f"{code}{author}".encode()).hexdigest()
        run = PipelineRun.objects.create(
            pipeline=pipeline,
            commit_hash=commit_hash[:40],
            commit_message=commit_msg,
            author=author,
            risk_level=result.risk_level,
            risk_score=result.risk_score,
            status='passed' if result.passed else 'failed',
            inference_ms=result.inference_ms,
            precision=result.precision,
            recall=result.recall,
            f1_score=result.f1_score,
            vulnerabilities_found=len(result.vulnerabilities),
        )

        for v in result.vulnerabilities:
            Vulnerability.objects.create(
                run=run,
                cwe_id=v['cwe_id'],
                cve_id=v.get('cve_id', ''),
                title=v['title'],
                description=v['description'],
                severity=v['severity'],
                file_path=v['file_path'],
                line_number=v['line_number'],
                cvss_score=v['cvss_score'],
                remediation=v['remediation'],
            )

        return redirect('run_detail', pk=run.pk)

    return render(request, 'scanner/scan_submit.html', {'pipelines': pipelines})


# ── Seed mock data ────────────────────────────────────────────────────────────
def seed_data(request):
    """Populate the database with realistic mock pipeline run history."""
    if PipelineRun.objects.count() > 10:
        return JsonResponse({'status': 'already seeded', 'count': PipelineRun.objects.count()})

    # Create pipelines
    pipelines_data = [
        ("auth-service", "github.com/corp/auth-service", "main"),
        ("payment-api", "github.com/corp/payment-api", "develop"),
        ("user-portal", "github.com/corp/user-portal", "main"),
        ("data-pipeline", "github.com/corp/data-pipeline", "staging"),
    ]
    pipelines = []
    for name, repo, branch in pipelines_data:
        p, _ = Pipeline.objects.get_or_create(name=name, defaults={'repository': repo, 'branch': branch})
        pipelines.append(p)

    # Generate 60 historical runs over the last 14 days
    rng = random.Random(42)
    created_count = 0
    for i in range(60):
        diff = rng.choice(SAMPLE_DIFFS)
        result = scan_code(diff, f"src/{rng.choice(['views', 'models', 'utils', 'api', 'auth'])}.py")
        pipeline = rng.choice(pipelines)
        days_ago = rng.uniform(0, 14)
        run_time = timezone.now() - timedelta(days=days_ago)

        commit_hash = hashlib.sha1(f"{diff}{i}".encode()).hexdigest()
        run = PipelineRun.objects.create(
            pipeline=pipeline,
            commit_hash=commit_hash[:40],
            commit_message=rng.choice(COMMIT_MESSAGES),
            author=rng.choice(COMMIT_AUTHORS),
            risk_level=result.risk_level,
            risk_score=result.risk_score,
            status='passed' if result.passed else 'failed',
            inference_ms=result.inference_ms,
            precision=result.precision,
            recall=result.recall,
            f1_score=result.f1_score,
            vulnerabilities_found=len(result.vulnerabilities),
        )
        # Manually set created_at for historical spread
        PipelineRun.objects.filter(pk=run.pk).update(created_at=run_time)

        for v in result.vulnerabilities:
            Vulnerability.objects.create(
                run=run,
                cwe_id=v['cwe_id'],
                cve_id=v.get('cve_id', ''),
                title=v['title'],
                description=v['description'],
                severity=v['severity'],
                file_path=v['file_path'],
                line_number=v['line_number'],
                cvss_score=v['cvss_score'],
                remediation=v['remediation'],
            )
        created_count += 1

    return JsonResponse({'status': 'seeded', 'runs_created': created_count})


# ── Webhook endpoint ──────────────────────────────────────────────────────────
@csrf_exempt
@require_POST
def webhook(request):
    """GitHub-compatible webhook receiver for CI/CD integration."""
    try:
        payload = json.loads(request.body)
        commits = payload.get('commits', [])
        repo_name = payload.get('repository', {}).get('full_name', 'unknown/repo')
        branch = payload.get('ref', 'refs/heads/main').replace('refs/heads/', '')

        pipeline, _ = Pipeline.objects.get_or_create(
            repository=repo_name,
            defaults={'name': repo_name.split('/')[-1], 'branch': branch}
        )

        results = []
        for commit in commits[:5]:
            diff = commit.get('message', '') + '\n' + '\n'.join(
                commit.get('added', []) + commit.get('modified', [])
            )
            result = scan_code(diff, 'webhook_commit.py')
            run = PipelineRun.objects.create(
                pipeline=pipeline,
                commit_hash=commit.get('id', 'unknown')[:40],
                commit_message=commit.get('message', '')[:500],
                author=commit.get('author', {}).get('email', 'unknown'),
                risk_level=result.risk_level,
                risk_score=result.risk_score,
                status='passed' if result.passed else 'failed',
                inference_ms=result.inference_ms,
                precision=result.precision,
                recall=result.recall,
                f1_score=result.f1_score,
                vulnerabilities_found=len(result.vulnerabilities),
            )
            results.append({
                'commit': commit.get('id', '')[:8],
                'risk': result.risk_level,
                'passed': result.passed,
                'run_id': run.pk,
            })

        return JsonResponse({'status': 'processed', 'results': results})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)


# ── API: stats ────────────────────────────────────────────────────────────────
def api_stats(request):
    total = PipelineRun.objects.count()
    return JsonResponse({
        'total_runs': total,
        'critical': PipelineRun.objects.filter(risk_level='critical').count(),
        'high': PipelineRun.objects.filter(risk_level='high').count(),
        'medium': PipelineRun.objects.filter(risk_level='medium').count(),
        'low': PipelineRun.objects.filter(risk_level='low').count(),
        'pass_rate': round(PipelineRun.objects.filter(status='passed').count() / total * 100, 1) if total else 0,
        'avg_f1': round((PipelineRun.objects.aggregate(avg=Avg('f1_score'))['avg'] or 0) * 100, 1),
        'avg_latency_ms': round(PipelineRun.objects.aggregate(avg=Avg('inference_ms'))['avg'] or 0),
    })
