from django.http import HttpResponseForbidden
from django.core.cache import cache
from .models import RequestLog, BlockedIP
import requests


class IPLoggingMiddleware:
    """
    Middleware that:
    - Logs all requests (Task 0)
    - Blocks blacklisted IPs (Task 1)
    - Adds geolocation data (Task 2)
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def get_geolocation(self, ip_address):
        """
        Fetch geolocation data for an IP address
        Uses cache to store results for 24 hours
        """
        cache_key = f"geo_{ip_address}"
        cached_data = cache.get(cache_key)

        if cached_data:
            return cached_data

        try:
            response = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=2)

            if response.status_code == 200:
                data = response.json()
                geo_data = {
                    "country": data.get("country_name", ""),
                    "city": data.get("city", ""),
                }
                # Cache for 24 hours (86400 seconds)
                cache.set(cache_key, geo_data, 86400)
                return geo_data
        except Exception as e:
            print(f"Geolocation error: {e}")

        return {"country": "", "city": ""}

    def __call__(self, request):
        # Get IP address (handles proxies)
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(",")[0].strip()
        else:
            ip_address = request.META.get("REMOTE_ADDR")

        # Task 1: Check if IP is blocked
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Your IP has been blocked.")

        # Task 2: Get geolocation data
        geo_data = self.get_geolocation(ip_address)

        # Task 0: Log the request with all data
        RequestLog.objects.create(
            ip_address=ip_address,
            path=request.path,
            country=geo_data["country"],
            city=geo_data["city"],
        )

        response = self.get_response(request)
        return response
