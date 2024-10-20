from django.urls import path
from accounts.views import (
    GoogleAuthRedirectView,
    GoogleCallbackView,
    UserRegisterView,
    TokenView,
    GoogleLoginView
)

app_name = "accounts"

urlpatterns = [
    path("login/", TokenView.as_view(), name="login"),
    path("google/login/", GoogleLoginView.as_view(), name="google_login"),
    path("register/", UserRegisterView.as_view(), name="register"),
    path(
        "google/redirect/",
        GoogleAuthRedirectView.as_view(),
        name="google_auth_redirect",
    ),
    path(
        "callback/google/",
        GoogleCallbackView.as_view(),
        name="google_auth_callback",
    ),
]
13710515