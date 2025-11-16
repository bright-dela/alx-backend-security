from django.core.management.base import BaseCommand
from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    """Task 1: Management command to block IPs"""

    help = "Block an IP address"

    def add_arguments(self, parser):
        parser.add_argument("ip_address", type=str)
        parser.add_argument("--reason", type=str, default="")

    def handle(self, *args, **options):
        ip_address = options["ip_address"]
        reason = options["reason"]

        blocked_ip, created = BlockedIP.objects.get_or_create(
            ip_address=ip_address, defaults={"reason": reason}
        )

        if created:
            self.stdout.write(self.style.SUCCESS(f"Blocked IP: {ip_address}"))
        else:
            self.stdout.write(self.style.WARNING(f"Already blocked: {ip_address}"))
