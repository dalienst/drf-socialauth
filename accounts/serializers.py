from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from accounts.validators import (
    validate_password_digit,
    validate_password_uppercase,
    validate_password_lowercase,
    validate_password_symbol,
)
from accounts.utils import send_activation_email
from accounts.tokens import account_activation_token


User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())],
    )
    password = serializers.CharField(
        max_length=128,
        min_length=5,
        write_only=True,
        validators=[
            validate_password_digit,
            validate_password_uppercase,
            validate_password_symbol,
            validate_password_lowercase,
        ],
        required=False,
    )
    avatar = serializers.ImageField(use_url=True, required=False)

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "password",
            "first_name",
            "last_name",
            "avatar",
            "is_staff",
            "is_active",
            "is_verified",
            "is_social",
            "created_at",
            "updated_at",
            "is_superuser",
            "last_login",
        )

    def create(self, validated_data):
        if validated_data.get("is_social", False):
            return self.create_social_user(validated_data)
        else:
            return self.create_normal_user(validated_data)

    def create_user(self, validated_data):
        # For regular signup
        user = User.objects.create_user(
            email=validated_data.get("email"),
            first_name=validated_data.get("first_name"),
            last_name=validated_data.get("last_name"),
            password=validated_data.get("password"),
        )
        user.save()

        # Send activation email for regular sign-ups
        send_activation_email(user, self.context.get("request"))
        return user

    def create_social_user(self, validated_data):
        """
        This method enables user creation for social logins
        """
        # For social signups (e.g., Google OAuth)
        user = User.objects.create_user(
            email=validated_data.get("email"),
            first_name=validated_data.get("first_name"),
            last_name=validated_data.get("last_name"),
            password=None,  # No password needed for social signups
        )
        user.is_active = True  # Social users are immediately active
        user.is_verified = True  # Social users are already verified by the provider
        user.is_social = True
        user.save()
        return user


class VerifyAccountSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()

    class Meta:
        fields = ("uidb64", "token")

    def validate(self, data):
        user = None
        try:
            user_id = force_str(urlsafe_base64_decode(data.get("uidb64")))
            user = User.objects.get(id=user_id)

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid user id", code="invalid_code")

        token = data.get("token")
        if user and not account_activation_token.check_token(user, token):
            raise serializers.ValidationError("Invalid token", code="invalid_token")

        return data

    def save(self, **kwargs):
        user_id = force_str(urlsafe_base64_decode(self.validated_data.get("uidb64")))
        user = User.objects.get(id=user_id)
        user.is_verified = True
        user.save()
        return user


class GoogleLoginSerializer(serializers.Serializer):
    token = serializers.CharField()

    class Meta:
        fields = ("token",)

    def save(self, **kwargs):
        token = self.validated_data.get("token")
        return token


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(required=True, write_only=True)


class GoogleLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
