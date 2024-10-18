import string
import secrets

from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from accounts.tokens import account_activation_token
from socialauth.settings import EMAIL_USER, DOMAIN

def generate_slug():
    characters = string.ascii_letters + string.digits
    random_string = "".join(secrets.choice(characters) for _ in range(16))
    return random_string


def generate_reference():
    characters = string.ascii_letters + string.digits
    random_string = "".join(secrets.choice(characters) for _ in range(10))
    return random_string.upper()


def send_activation_email(user, request):
    """
    A function to enable sending of activation email
    """
    current_site = get_current_site(request)  # noqa: F841
    email_body = render_to_string(
        "email_verification.html",
        {
            "user": user,
            "domain": DOMAIN,
            "uid": urlsafe_base64_encode(force_bytes(user.pk)),
            "token": account_activation_token.make_token(user),
        },
    )

    send_mail(
        "Activate your account",
        email_body,
        EMAIL_USER,
        [user.email],
        fail_silently=False,
    )
