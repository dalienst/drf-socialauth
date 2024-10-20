import requests
from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model, authenticate
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny

from django.conf import settings
from django.shortcuts import redirect
from urllib.parse import urlencode

from accounts.serializers import (
    UserSerializer,
    UserLoginSerializer,
    GoogleLoginSerializer,
)

User = get_user_model()


class TokenView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = UserLoginSerializer

    def post(self, request, format=None):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data["email"]
            password = serializer.validated_data["password"]

            user = authenticate(email=email, password=password)

            if user:
                if user.is_active:
                    token, created = Token.objects.get_or_create(user=user)
                    user_details = {
                        "id": user.id,
                        "email": user.email,
                        "is_superuser": user.is_superuser,
                        "is_active": user.is_active,
                        "is_staff": user.is_staff,
                        "is_verified": user.is_verified,
                        "reference": user.reference,
                        "slug": user.slug,
                        "last_login": user.last_login,
                        "token": token.key,
                    }
                    return Response(user_details, status=status.HTTP_200_OK)
                else:
                    return Response(
                        {"detail": ("User account is disabled.")},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            else:
                return Response(
                    {"detail": ("Unable to log in with provided credentials.")},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GoogleLoginView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = GoogleLoginSerializer

    def post(self, request, format=None):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data["email"]

            user = User.objects.filter(email=email).first()

            if user:
                if user.is_active:
                    token, created = Token.objects.get_or_create(user=user)
                    user_details = {
                        "id": user.id,
                        "email": user.email,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "is_superuser": user.is_superuser,
                        "is_active": user.is_active,
                        "is_staff": user.is_staff,
                        "is_verified": user.is_verified,
                        "reference": user.reference,
                        "slug": user.slug,
                        "last_login": user.last_login,
                        "token": token.key,
                    }
                    return Response(user_details, status=status.HTTP_200_OK)
                else:
                    return Response(
                        {"detail": ("User account is disabled.")},
                        status=status.HTTP_400_BAD_REQUEST,
                    )


class UserRegisterView(generics.CreateAPIView):
    serializer_class = UserSerializer

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class GoogleAuthRedirectView(APIView):
    """
    Redirects user to Google's OAuth 2.0 authorization page.
    """

    def get(self, request, *args, **kwargs):
        google_auth_url = "https://accounts.google.com/o/oauth2/auth"
        params = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile",
        }
        auth_url = f"{google_auth_url}?{urlencode(params)}"
        return redirect(auth_url)


class GoogleCallbackView(APIView):
    """
    Handles the callback from Google OAuth2 and exchanges the authorization code for tokens.
    """

    def get(self, request, *args, **kwargs):
        # Extract the authorization code from the query parameters
        code = request.query_params.get("code")
        if not code:
            return Response(
                {"error": "No Code Provided"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Exchange the authorization code for access and refresh tokens
        token_url = "https://oauth2.googleapis.com/token"
        token_data = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }

        # Send a POST request to exchange the code for tokens
        token_response = requests.post(token_url, data=token_data)
        token_response_data = token_response.json()

        # Check for errors in the token response
        if token_response.status_code != 200 or "error" in token_response_data:
            return Response(
                {"error": token_response_data.get("error", "Failed to obtain token")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        access_token = token_response_data.get("access_token")
        id_token = token_response_data.get("id_token")

        # Fetch user info from Google
        user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo"
        user_info_response = requests.get(
            user_info_url, headers={"Authorization": f"Bearer {access_token}"}
        )

        if user_info_response.status_code != 200:
            return Response(
                {"error": "Failed to retrieve user info"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user_info = user_info_response.json()

        # Create or log in user based on user_info
        user, token = create_or_get_user_from_google(user_info)

        return Response(
            {
                "token": token.key,
                "user": user.email,
                "id": user.id,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "is_active": user.is_active,
                "is_verified": user.is_verified,
                "is_staff": user.is_staff,
            },
            status=status.HTTP_200_OK,
        )


def create_or_get_user_from_google(user_info):
    """
    Create a user if not exists or get an existing user based on Google profile data.
    """
    email = user_info.get("email")
    user = User.objects.filter(email=email).first()
    if not user:
        # Create a new user
        user = User.objects.create(
            email=email,
            first_name=user_info.get("given_name"),
            last_name=user_info.get("family_name"),
            is_active=True,
            is_verified=True,  # Google OAuth ensures the user is verified
            is_social=True,
        )
        user.save()

    # Create or retrieve a token here for Token Authentication
    token, created = Token.objects.get_or_create(user=user)
    return user, token
