from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count
from .models import RequestLog, SuspiciousIP


@shared_task
def detect_anomalies():
    """
    Task 4: Hourly anomaly detection
    Flags IPs with:
    - More than 100 requests in 1 hour
    - Multiple accesses to sensitive paths
    """
    one_hour_ago = timezone.now() - timedelta(hours=1)

    # Detection 1: Excessive requests
    high_traffic_ips = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values("ip_address")
        .annotate(request_count=Count("id"))
        .filter(request_count__gt=100)
    )

    for ip_data in high_traffic_ips:
        ip_address = ip_data["ip_address"]
        request_count = ip_data["request_count"]

        SuspiciousIP.objects.get_or_create(
            ip_address=ip_address,
            detected_at__gte=one_hour_ago,
            defaults={
                "reason": f"Excessive requests: {request_count} requests in 1 hour",
                "request_count": request_count,
            },
        )

    # Detection 2: Sensitive path access
    sensitive_paths = ["/admin", "/login", "/api/admin"]

    for path in sensitive_paths:
        suspicious_accesses = (
            RequestLog.objects.filter(
                timestamp__gte=one_hour_ago, path__startswith=path
            )
            .values("ip_address")
            .annotate(access_count=Count("id"))
            .filter(access_count__gt=5)
        )

        for ip_data in suspicious_accesses:
            ip_address = ip_data["ip_address"]
            access_count = ip_data["access_count"]

            SuspiciousIP.objects.get_or_create(
                ip_address=ip_address,
                detected_at__gte=one_hour_ago,
                defaults={
                    "reason": f"Multiple {path} attempts: {access_count} times",
                    "request_count": access_count,
                },
            )

    total = SuspiciousIP.objects.filter(detected_at__gte=one_hour_ago).count()
    return f"Flagged {total} suspicious IPs"
