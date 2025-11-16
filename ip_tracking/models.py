from django.db import models

# Create your models here.


class RequestLog(models.Model):
    """Logs all incoming requests with IP, path, timestamp, and geolocation"""

    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    country = models.CharField(max_length=100, blank=True, null=True)  # Task 2
    city = models.CharField(max_length=100, blank=True, null=True)  # Task 2

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["ip_address", "timestamp"]),
            models.Index(fields=["path"]),
        ]

    def __str__(self):
        return f"{self.ip_address} - {self.path} - {self.timestamp}"


class BlockedIP(models.Model):
    """Stores blacklisted IP addresses - Task 1"""

    ip_address = models.GenericIPAddressField(unique=True)
    blocked_at = models.DateTimeField(auto_now_add=True)
    reason = models.TextField(blank=True)

    def __str__(self):
        return f"Blocked: {self.ip_address}"


class SuspiciousIP(models.Model):
    """Flags suspicious IPs detected by anomaly detection - Task 4"""

    ip_address = models.GenericIPAddressField()
    reason = models.TextField()
    detected_at = models.DateTimeField(auto_now_add=True)
    request_count = models.IntegerField(default=0)

    class Meta:
        ordering = ["-detected_at"]
        indexes = [
            models.Index(fields=["ip_address", "detected_at"]),
        ]

    def __str__(self):
        return f"Suspicious: {self.ip_address} - {self.reason}"
