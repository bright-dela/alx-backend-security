from django.shortcuts import render
from django.http import JsonResponse
from django_ratelimit.decorators import ratelimit
from django.contrib.auth.decorators import login_required

# Create your views here.


@ratelimit(key="ip", rate="5/m", method="POST")
def login_view(request):
    """
    Task 3: Login view with rate limiting
    5 requests per minute for anonymous users
    """
    was_limited = getattr(request, "limited", False)

    if was_limited:
        return JsonResponse(
            {"error": "Rate limit exceeded. Please try again later."}, status=429
        )

    if request.method == "POST":
        # Your login logic here
        return JsonResponse({"message": "Login successful"})

    return JsonResponse({"message": "Login endpoint"})


@login_required
@ratelimit(key="ip", rate="10/m", method="POST")
def sensitive_action_view(request):
    """
    Task 3: Protected action with higher rate limit
    10 requests per minute for authenticated users
    """
    was_limited = getattr(request, "limited", False)

    if was_limited:
        return JsonResponse(
            {"error": "Rate limit exceeded. Please try again later."}, status=429
        )

    return JsonResponse({"message": "Action completed"})
