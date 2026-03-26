import os
from langchain_core.language_models import BaseChatModel


def get_llm() -> BaseChatModel:
    provider = os.getenv("LLM_PROVIDER", "ollama").lower()

    match provider:
        case "ollama":
            from langchain_ollama import ChatOllama
            return ChatOllama(
                model=os.getenv("OLLAMA_MODEL", "llama3.1:8b"),
                base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
                temperature=0,
            )
        case "openai":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                model=os.getenv("OPENAI_MODEL", "gpt-4o"),
                api_key=os.getenv("OPENAI_API_KEY"),
                temperature=0,
            )
        case "claude":
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(
                model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
                api_key=os.getenv("ANTHROPIC_API_KEY"),
                temperature=0,
            )
        case "featherless":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                model=os.getenv("FEATHERLESS_MODEL", "meta-llama/Meta-Llama-3.1-8B-Instruct"),
                api_key=os.getenv("FEATHERLESS_API_KEY"),
                base_url="https://api.featherless.ai/v1",
                temperature=0,
            )
        case _:
            raise ValueError(f"Unknown LLM_PROVIDER: {provider!r}. Choose: ollama | openai | claude | featherless")
