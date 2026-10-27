import os
import sys

aegis_cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aegis_core", "aegis_core")
if aegis_cfg_path not in sys.path:
    sys.path.insert(0, aegis_cfg_path)

try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    load_dotenv(dotenv_path=env_path, override=False)
except Exception:
    pass

# Botocore treats an explicitly empty AWS_PROFILE as a requested profile named
# "" and raises ProfileNotFound. Leave it unset unless a real profile is used.
if not (os.getenv("AWS_PROFILE") or "").strip():
    os.environ.pop("AWS_PROFILE", None)
if not (os.getenv("AWS_DEFAULT_PROFILE") or "").strip():
    os.environ.pop("AWS_DEFAULT_PROFILE", None)

if (os.getenv("LLM_PROVIDER") or "").strip().lower() in ("", "bedrock") and \
        os.getenv("USE_BEDROCK", "true").lower() == "true":
    os.environ.setdefault("MODEL_PROVIDER", "bedrock")
    os.environ.setdefault("BEDROCK_MODEL_ID", "global.anthropic.claude-sonnet-5")
os.environ.setdefault("DEMO_MODE", "0")

# Dynamically synchronize settings with aegis_core's internal config module to prevent attribute collision
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("aegis_internal_cfg", os.path.join(aegis_cfg_path, "config.py"))
    if spec and spec.loader:
        aegis_cfg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(aegis_cfg)
        for attr in dir(aegis_cfg):
            if not attr.startswith("__"):
                globals()[attr] = getattr(aegis_cfg, attr)
except Exception:
    pass

# NVD API key (optional, increases rate limit from 5 req/30s to 50 req/30s)
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# LLM provider: LLM_PROVIDER=bedrock|azure_openai is the one switch for every model call
# (enrichment, remediation agent, Internet lookup, adapter fallback). USE_BEDROCK is only a
# fallback for older .env files that set USE_BEDROCK=false without LLM_PROVIDER.
LLM_PROVIDER = (os.getenv("LLM_PROVIDER") or
                ("bedrock" if os.getenv("USE_BEDROCK", "true").lower() == "true" else "azure_openai")
                ).strip().strip('"').strip("'").lower()
if LLM_PROVIDER not in ("bedrock", "azure_openai"):
    raise ValueError(f"LLM_PROVIDER must be bedrock or azure_openai, not {LLM_PROVIDER!r}")
os.environ["LLM_PROVIDER"] = LLM_PROVIDER    # the remediation agent and Internet lookup read it
USE_BEDROCK = LLM_PROVIDER == "bedrock"
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID") or "global.anthropic.claude-sonnet-5"

# Azure OpenAI (used when LLM_PROVIDER=azure_openai)
AZURE_OPENAI_ENDPOINT = (os.getenv("AZURE_OPENAI_ENDPOINT") or "").strip().strip('"').strip("'")
AZURE_OPENAI_API_KEY = (os.getenv("AZURE_OPENAI_API_KEY") or "").strip().strip('"').strip("'")
AZURE_OPENAI_API_VERSION = (os.getenv("AZURE_OPENAI_API_VERSION") or "2024-02-01").strip()
AZURE_CHAT_DEPLOYMENT = (os.getenv("AZURE_CHAT_DEPLOYMENT") or os.getenv("AZURE_OPENAI_DEPLOYMENT") or "").strip()
# Newer reasoning deployments (o-series) take max_completion_tokens instead of max_tokens.
AZURE_TOKEN_PARAMETER = (os.getenv("AZURE_TOKEN_PARAMETER") or "max_tokens").strip()
AWS_DEFAULT_REGION = (os.getenv("AWS_DEFAULT_REGION") or "us-west-2").strip().strip('"').strip("'")

# Cleanly extract AWS credentials in case there are surrounding quotes or spaces in .env
AWS_ACCESS_KEY_ID = (os.getenv("AWS_ACCESS_KEY_ID") or "").strip().strip('"').strip("'")
AWS_SECRET_ACCESS_KEY = (os.getenv("AWS_SECRET_ACCESS_KEY") or "").strip().strip('"').strip("'")
AWS_SESSION_TOKEN = (os.getenv("AWS_SESSION_TOKEN") or "").strip().strip('"').strip("'")
AWS_PROFILE = (os.getenv("AWS_PROFILE") or "").strip().strip('"').strip("'")
