import json
import sys
import time
from datetime import date, datetime
from pathlib import Path

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

import config


def clean(value):
    if value is None:
        return ""
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return str(value).strip()


def normalize_name(value):
    return " ".join(
        clean(value).replace("_", " ").replace("-", " ").lower().split()
    )


def get_value(row, *names):
    accepted = {normalize_name(name) for name in names}
    for column, value in row.items():
        if normalize_name(column) in accepted:
            return clean(value)
    return ""


def llm_provider():
    """bedrock or azure_openai, from LLM_PROVIDER in .env (the one switch for every model call)."""
    return config.LLM_PROVIDER


def create_llm_client():
    """A client for the configured provider; pass it to invoke_llm."""
    if llm_provider() == "azure_openai":
        return create_azure_client()
    return create_bedrock_client()


def create_azure_client():
    from openai import AzureOpenAI
    missing = [name for name, value in (("AZURE_OPENAI_ENDPOINT", config.AZURE_OPENAI_ENDPOINT),
                                        ("AZURE_OPENAI_API_KEY", config.AZURE_OPENAI_API_KEY),
                                        ("AZURE_CHAT_DEPLOYMENT", config.AZURE_CHAT_DEPLOYMENT)) if not value]
    if missing:
        raise RuntimeError("LLM_PROVIDER=azure_openai needs " + ", ".join(missing) + " in .env")
    client = AzureOpenAI(azure_endpoint=config.AZURE_OPENAI_ENDPOINT, api_key=config.AZURE_OPENAI_API_KEY,
                         api_version=config.AZURE_OPENAI_API_VERSION, timeout=60, max_retries=1)
    print(f"Azure OpenAI client initialized for deployment {config.AZURE_CHAT_DEPLOYMENT}.")
    return client


def invoke_llm(client, body, purpose="model request"):
    """Send an Anthropic Messages body (as used with Bedrock) to the configured provider.

    The reply always has the Anthropic shape: content blocks (text / tool_use), stop_reason
    and usage, so callers do not depend on the provider.
    """
    if llm_provider() == "azure_openai":
        return invoke_azure(client, body, purpose)
    return invoke_bedrock(client, body, purpose)


def _azure_messages(body):
    def text_of(content):
        if isinstance(content, str):
            return content
        return "\n".join(block.get("text", "") for block in content or [] if block.get("type") == "text")
    messages = []
    system = body.get("system")
    if system:
        messages.append({"role": "system", "content": text_of(system)})
    for message in body.get("messages") or []:
        messages.append({"role": message["role"], "content": text_of(message.get("content"))})
    return messages


def invoke_azure(client, body, purpose="model request"):
    evidence_root = str(Path(__file__).parent / "aegis-cve-evidence")
    if evidence_root not in sys.path:
        sys.path.insert(0, evidence_root)
    from remediation.rate_limit import model_requests

    request = {"model": config.AZURE_CHAT_DEPLOYMENT, "messages": _azure_messages(body),
               config.AZURE_TOKEN_PARAMETER: body.get("max_tokens", 4096)}
    tools = body.get("tools") or []
    if tools:
        request["tools"] = [{"type": "function", "function": {
            "name": tool["name"], "description": tool.get("description", ""),
            "parameters": tool.get("input_schema") or {"type": "object"}}} for tool in tools]
        choice = body.get("tool_choice") or {}
        if choice.get("type") == "tool":
            request["tool_choice"] = {"type": "function", "function": {"name": choice["name"]}}
        elif choice.get("type") == "any":
            request["tool_choice"] = "required"

    print(f"Connecting to Azure OpenAI for {purpose}...")
    started = time.monotonic()
    try:
        model_requests.wait()
        response = client.chat.completions.create(**request)
    except Exception as exc:
        print(f"Azure OpenAI request failed after {time.monotonic() - started:.1f} seconds: "
              f"{type(exc).__name__}: {exc}")
        raise
    print(f"Azure OpenAI response received in {time.monotonic() - started:.1f} seconds.")

    choice = response.choices[0]
    content = []
    if choice.message.content:
        content.append({"type": "text", "text": choice.message.content})
    for call in choice.message.tool_calls or []:
        try:
            arguments = json.loads(call.function.arguments or "{}")
        except json.JSONDecodeError:
            arguments = None   # truncated or invalid JSON: callers treat it as missing output
        content.append({"type": "tool_use", "id": call.id, "name": call.function.name, "input": arguments})
    stop = {"length": "max_tokens", "tool_calls": "tool_use", "stop": "end_turn",
            "content_filter": "refusal"}.get(choice.finish_reason, choice.finish_reason)
    usage = getattr(response, "usage", None)
    return {"content": content, "stop_reason": stop,
            "usage": {"input_tokens": getattr(usage, "prompt_tokens", None),
                      "output_tokens": getattr(usage, "completion_tokens", None)}}


def create_bedrock_client():
    if config.LLM_PROVIDER != "bedrock":
        raise RuntimeError("LLM_PROVIDER is not bedrock; use create_llm_client()")

    session_options = {}
    if config.AWS_ACCESS_KEY_ID and config.AWS_SECRET_ACCESS_KEY:
        session_options.update({
            "aws_access_key_id": config.AWS_ACCESS_KEY_ID,
            "aws_secret_access_key": config.AWS_SECRET_ACCESS_KEY,
        })
        if config.AWS_SESSION_TOKEN:
            session_options["aws_session_token"] = config.AWS_SESSION_TOKEN
    elif config.AWS_PROFILE:
        session_options["profile_name"] = config.AWS_PROFILE

    session = boto3.Session(**session_options)
    options = {
        "region_name": config.AWS_DEFAULT_REGION,
        "config": BotoConfig(
            read_timeout=60,
            connect_timeout=10,
            retries={"total_max_attempts": 1, "mode": "standard"},
        ),
    }

    client = session.client("bedrock-runtime", **options)
    print(
        f"Bedrock client initialized for {config.AWS_DEFAULT_REGION}. "
        "The connection will be verified by the first model request."
    )
    return client


def invoke_bedrock(client, body, purpose="model request"):
    evidence_root = str(Path(__file__).parent / "aegis-cve-evidence")
    if evidence_root not in sys.path:
        sys.path.insert(0, evidence_root)
    from remediation.rate_limit import model_requests

    request = {
        "modelId": config.BEDROCK_MODEL_ID,
        "body": json.dumps(body),
        "contentType": "application/json",
        "accept": "application/json",
    }

    print(f"Connecting to Bedrock for {purpose}...")
    started = time.monotonic()

    try:
        try:
            model_requests.wait()
            response = client.invoke_model(
                **request,
                performanceConfigLatency="optimized",
            )
        except ClientError as exc:
            message = str(exc).lower()
            unsupported_latency = (
                exc.response.get("Error", {}).get("Code") == "ValidationException"
                and ("latency" in message or "performance" in message)
            )
            if not unsupported_latency:
                raise

            print("Optimized latency is unavailable; using standard latency.")
            model_requests.wait()
            response = client.invoke_model(**request)

        result = json.loads(response["body"].read())
    except Exception as exc:
        elapsed = time.monotonic() - started
        print(
            f"Bedrock connection failed after {elapsed:.1f} seconds: "
            f"{type(exc).__name__}: {exc}"
        )
        raise

    elapsed = time.monotonic() - started
    print(f"Bedrock connection established; response received in {elapsed:.1f} seconds.")
    return result
