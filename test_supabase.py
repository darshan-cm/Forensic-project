"""Safe local checks for Supabase configuration and client initialization."""

from supabase.client import SUPABASE_PUBLISHABLE_KEY, SUPABASE_URL, client


def main():
    assert SUPABASE_URL.startswith(("https://", "http://")), "URL is invalid"
    assert SUPABASE_PUBLISHABLE_KEY, "publishable key is missing"
    assert client.auth is not None, "authentication client is unavailable"
    print("PASS: environment variables loaded")
    print("PASS: Supabase URL is valid")
    print("PASS: Supabase client initialized")
    print("PASS: authentication client is accessible")


if __name__ == "__main__":
    main()