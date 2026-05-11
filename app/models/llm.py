from langchain_openai import ChatOpenAI
from app.config import (
    OPENAI_API_KEY,
    OPENAI_BASE_URL,
    MODEL_NAME,
)


def get_llm():
    return ChatOpenAI(
        api_key=OPENAI_API_KEY,
        base_url=OPENAI_BASE_URL,
        model=MODEL_NAME,
        temperature=0,
    )