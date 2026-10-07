"""Interactive Supabase email/password authentication smoke test."""

from getpass import getpass

from supabase.auth import get_current_user, sign_in, sign_out, sign_up


def main():
    email = input("Email: ").strip()
    password = getpass("Password: ")

    sign_up(email, password)
    print("PASS: signup request completed")

    sign_in(email, password)
    print("PASS: signin completed")

    user_response = get_current_user()
    if user_response.user is None:
        raise RuntimeError("current user was not returned")
    print("PASS: current user retrieved")

    sign_out()
    print("PASS: signout completed")


if __name__ == "__main__":
    main()