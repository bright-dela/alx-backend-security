from django.contrib import admin
from .models import RequestLog, BlockedIP, SuspiciousIP


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ["ip_address", "path", "country", "city", "timestamp"]
    list_filter = ["country", "timestamp"]
    search_fields = ["ip_address", "path"]


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ["ip_address", "reason", "blocked_at"]
    search_fields = ["ip_address"]


@admin.register(SuspiciousIP)
class SuspiciousIPAdmin(admin.ModelAdmin):
    list_display = ["ip_address", "reason", "request_count", "detected_at"]
    list_filter = ["detected_at"]
    search_fields = ["ip_address"]
