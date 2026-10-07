"""User-facing Supabase email/password authentication helpers."""

from .client import client


def sign_up(email: str, password: str):
    return client.auth.sign_up({"email": email, "password": password})


def sign_in(email: str, password: str):
    return client.auth.sign_in_with_password({"email": email, "password": password})


def sign_out():
    return client.auth.sign_out()


def get_current_user():
    return client.auth.get_user()


__all__ = ["sign_up", "sign_in", "sign_out", "get_current_user"]