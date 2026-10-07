import json
import time
from datetime import date, datetime

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


def create_bedrock_client():
    if not config.USE_BEDROCK:
        raise RuntimeError("USE_BEDROCK must be true in config.py or .env")

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
