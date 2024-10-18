from django.urls import path
from accounts.views import GoogleAuthRedirectView, GoogleCallbackView

app_name = "accounts"

urlpatterns = [
    path(
        "google/redirect/",
        GoogleAuthRedirectView.as_view(),
        name="google_auth_redirect",
    ),
    path(
        "google/callback/",
        GoogleCallbackView.as_view(),
        name="google_auth_callback",
    ),
]
