from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('pipeline/<int:pk>/', views.pipeline_detail, name='pipeline_detail'),
    path('run/<int:pk>/', views.run_detail, name='run_detail'),
    path('scan/', views.scan_submit, name='scan_submit'),
    path('seed/', views.seed_data, name='seed_data'),
    path('webhook/', views.webhook, name='webhook'),
    path('api/stats/', views.api_stats, name='api_stats'),
]
