"""Create and expose the configured Supabase client."""

import importlib.metadata
import importlib.util
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


def _read_env(*names):
    for name in names:
        value = os.getenv(name, "")
        if value is None:
            continue
        cleaned = value.strip().strip('"\'')
        if cleaned:
            return cleaned
    return ""


SUPABASE_URL = _read_env("SUPABASE_URL").strip().strip('"\'')
SUPABASE_PUBLISHABLE_KEY = _read_env(
    "SUPABASE_PUBLISHABLE_KEY",
    "SUPABASE_KEY",
).strip().strip('"\'')

if not SUPABASE_URL:
    raise RuntimeError("SUPABASE_URL is not configured")
parsed_url = urlparse(SUPABASE_URL)
if parsed_url.scheme not in {"https", "http"} or not parsed_url.netloc:
    raise RuntimeError("SUPABASE_URL must be a valid HTTP(S) URL")
if not SUPABASE_PUBLISHABLE_KEY or SUPABASE_PUBLISHABLE_KEY.startswith("REPLACE_WITH_"):
    raise RuntimeError("SUPABASE_PUBLISHABLE_KEY is not configured")
os.environ["SUPABASE_URL"] = SUPABASE_URL
os.environ["SUPABASE_PUBLISHABLE_KEY"] = SUPABASE_PUBLISHABLE_KEY


def _load_official_client_factory():
    """Load the dependency despite this integration package sharing its name."""
    package_path = importlib.metadata.distribution("supabase").locate_file("supabase")
    module_name = "_forensicguard_supabase_dependency"
    spec = importlib.util.spec_from_file_location(
        module_name,
        package_path / "__init__.py",
        submodule_search_locations=[str(package_path)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load the Supabase Python client")
    official_package = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = official_package
    local_package = sys.modules.get("supabase")
    sys.modules["supabase"] = official_package
    try:
        spec.loader.exec_module(official_package)
    finally:
        if local_package is not None:
            sys.modules["supabase"] = local_package
        else:
            sys.modules.pop("supabase", None)
    return official_package.create_client


create_client = _load_official_client_factory()
client = create_client(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY)

__all__ = ["client"]