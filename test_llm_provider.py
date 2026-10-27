"""LLM_PROVIDER switches enrichment between Bedrock and Azure OpenAI (offline, fake clients)."""
import json
from types import SimpleNamespace

import agent_utils
import config

TOOL = {"name": "return_version_probe", "description": "Probe",
        "input_schema": {"type": "object", "properties": {"executable": {"type": "string"}}}}
BODY = {"anthropic_version": "bedrock-2023-05-31", "max_tokens": 800,
        "messages": [{"role": "user", "content": [{"type": "text", "text": "Which binary?"}]}],
        "tools": [TOOL], "tool_choice": {"type": "tool", "name": "return_version_probe"}}


class FakeAzure:
    def __init__(self, arguments, finish="stop"):
        self.sent, self.arguments, self.finish = None, arguments, finish
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **request):
        self.sent = request
        call = SimpleNamespace(id="call_1", function=SimpleNamespace(name="return_version_probe",
                                                                     arguments=self.arguments))
        message = SimpleNamespace(content=None, tool_calls=[call])
        return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason=self.finish)],
                               usage=SimpleNamespace(prompt_tokens=12, completion_tokens=5))


def test_azure_reply_has_the_anthropic_shape(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "azure_openai")
    monkeypatch.setattr(config, "AZURE_CHAT_DEPLOYMENT", "gpt-4o")
    monkeypatch.setattr(agent_utils.config, "AZURE_TOKEN_PARAMETER", "max_tokens")
    client = FakeAzure(json.dumps({"executable": "openssl"}))
    reply = agent_utils.invoke_llm(client, BODY, "test")
    # Request: Anthropic tool -> Azure function, forced by name.
    assert client.sent["model"] == "gpt-4o" and client.sent["max_tokens"] == 800
    assert client.sent["messages"] == [{"role": "user", "content": "Which binary?"}]
    assert client.sent["tools"][0]["function"]["parameters"] == TOOL["input_schema"]
    assert client.sent["tool_choice"] == {"type": "function", "function": {"name": "return_version_probe"}}
    # Reply: the same blocks the Bedrock callers already read.
    assert reply["content"] == [{"type": "tool_use", "id": "call_1", "name": "return_version_probe",
                                 "input": {"executable": "openssl"}}]
    assert reply["usage"] == {"input_tokens": 12, "output_tokens": 5}


def test_truncated_azure_reply_reports_max_tokens(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "azure_openai")
    reply = agent_utils.invoke_llm(FakeAzure('{"executable": "op', finish="length"), BODY, "test")
    assert reply["stop_reason"] == "max_tokens" and reply["content"][0]["input"] is None


def test_bedrock_is_used_when_the_provider_is_bedrock(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "bedrock")
    calls = []
    monkeypatch.setattr(agent_utils, "invoke_bedrock", lambda client, body, purpose: calls.append(body) or {})
    agent_utils.invoke_llm(object(), BODY, "test")
    assert calls == [BODY]
