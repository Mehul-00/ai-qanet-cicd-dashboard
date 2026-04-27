from django.db import models
import json


class Pipeline(models.Model):
    name = models.CharField(max_length=200)
    repository = models.CharField(max_length=300)
    branch = models.CharField(max_length=100, default='main')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.repository})"


class PipelineRun(models.Model):
    RISK_CHOICES = [
        ('critical', 'Critical Vulnerability'),
        ('high', 'High Risk'),
        ('medium', 'Medium Risk'),
        ('low', 'Low / No Risk'),
    ]
    STATUS_CHOICES = [
        ('passed', 'Passed'),
        ('failed', 'Failed'),
        ('running', 'Running'),
    ]

    pipeline = models.ForeignKey(Pipeline, on_delete=models.CASCADE, related_name='runs')
    commit_hash = models.CharField(max_length=40)
    commit_message = models.TextField()
    author = models.CharField(max_length=100)
    risk_level = models.CharField(max_length=20, choices=RISK_CHOICES)
    risk_score = models.FloatField(help_text="0.0 to 1.0")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    inference_ms = models.IntegerField(help_text="Inference latency in ms")
    precision = models.FloatField(default=0.0)
    recall = models.FloatField(default=0.0)
    f1_score = models.FloatField(default=0.0)
    vulnerabilities_found = models.IntegerField(default=0)
    _vulnerabilities_detail = models.TextField(db_column='vulnerabilities_detail', default='[]')
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def vulnerabilities_detail(self):
        return json.loads(self._vulnerabilities_detail)

    @vulnerabilities_detail.setter
    def vulnerabilities_detail(self, value):
        self._vulnerabilities_detail = json.dumps(value)

    def risk_badge_class(self):
        mapping = {
            'critical': 'badge-critical',
            'high': 'badge-high',
            'medium': 'badge-medium',
            'low': 'badge-low',
        }
        return mapping.get(self.risk_level, 'badge-low')

    def __str__(self):
        return f"Run {self.commit_hash[:8]} - {self.risk_level}"


class Vulnerability(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]

    run = models.ForeignKey(PipelineRun, on_delete=models.CASCADE, related_name='vuln_set')
    cwe_id = models.CharField(max_length=20)
    cve_id = models.CharField(max_length=30, blank=True)
    title = models.CharField(max_length=300)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    file_path = models.CharField(max_length=500)
    line_number = models.IntegerField()
    cvss_score = models.FloatField(default=0.0)
    remediation = models.TextField(blank=True)

    def __str__(self):
        return f"{self.cwe_id}: {self.title}"
